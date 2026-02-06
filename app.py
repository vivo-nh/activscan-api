from flask import Flask, request, jsonify
import subprocess
import uuid
import os
import time
import json
import requests
import xml.etree.ElementTree as ET
from pathlib import Path

from profiles import PROFILES

# Auth between WP plugin -> this API
WORKER_API_KEY = os.getenv("WORKER_API_KEY", "")

# Remote ZAP
ZAP_API = os.getenv("ZAP_API", "").rstrip("/")  # e.g. https://<zap-service>/ or http://...
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")      # must match zap service key

ZAP_MAX_SECONDS = int(os.getenv("ZAP_MAX_SECONDS", "240"))
ZAP_CHILDREN = int(os.getenv("ZAP_CHILDREN", "60"))
ZAP_RECURSE = os.getenv("ZAP_RECURSE", "false").lower() in ("1", "true", "yes")

NMAP_MAX_SECONDS = int(os.getenv("NMAP_MAX_SECONDS", "60"))
NMAP_MIN_BYTES = int(os.getenv("NMAP_MIN_BYTES", "300"))
NMAP_GRACE_SECONDS = int(os.getenv("NMAP_GRACE_SECONDS", "30"))

JOBS_DIR = Path(os.getenv("JOBS_DIR", "/tmp/jobs"))
JOBS_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)


def _now():
    return int(time.time())


def _unauthorized():
    return jsonify({"error": "unauthorized"}), 401


def _job_path(job_id: str) -> Path:
    return JOBS_DIR / f"{job_id}.json"


def _load_job(job_id: str):
    p = _job_path(job_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _save_job(job: dict):
    try:
        _job_path(job["job_id"]).write_text(json.dumps(job), encoding="utf-8")
    except Exception:
        pass


def _file_info(path: str):
    try:
        st = os.stat(path)
        return {"exists": True, "bytes": st.st_size}
    except Exception:
        return {"exists": False, "bytes": 0}


def _ready(path: str, min_bytes: int) -> bool:
    try:
        return os.path.exists(path) and os.path.getsize(path) >= min_bytes
    except Exception:
        return False


def _read_head(path: str, max_bytes: int = 4096) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _read_tail(path: str, max_bytes: int = 4096) -> str:
    try:
        size = os.path.getsize(path)
        start = max(0, size - max_bytes)
        with open(path, "rb") as f:
            f.seek(start)
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _looks_like_nmap_xml(path: str) -> bool:
    head = _read_head(path, 4096).lstrip()
    return head.startswith("<") and ("<nmaprun" in head)


def _looks_complete_nmap_xml(path: str) -> bool:
    return "</nmaprun>" in _read_tail(path, 4096)


def _parse_nmap_open_ports(nmap_xml_path: str):
    if not _looks_like_nmap_xml(nmap_xml_path):
        raise ValueError("nmap_output_not_xml")
    if not _looks_complete_nmap_xml(nmap_xml_path):
        raise ValueError("nmap_output_incomplete_xml")

    tree = ET.parse(nmap_xml_path)
    root = tree.getroot()

    open_ports = []
    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            service_el = port_el.find("service")
            service_name = service_el.get("name") if service_el is not None else None

            open_ports.append({
                "port": int(port_el.get("portid")),
                "proto": port_el.get("protocol"),
                "service": service_name
            })
    return open_ports


# -------------------------
# ZAP remote helpers
# -------------------------
def _zap_enabled() -> bool:
    return bool(ZAP_API) and bool(ZAP_API_KEY)


def _zap_req(path: str, params: dict, timeout: int = 10):
    # Always include apikey
    params = dict(params or {})
    params["apikey"] = ZAP_API_KEY
    url = f"{ZAP_API}{path}"
    r = requests.get(url, params=params, timeout=timeout)
    r.raise_for_status()
    return r


def _zap_api_ok() -> bool:
    if not _zap_enabled():
        return False
    try:
        r = _zap_req("/JSON/core/view/version/", {}, timeout=5)
        return r.ok
    except Exception:
        return False


def _zap_target_url(target: str) -> str:
    return f"https://{target}"


def _zap_access_url(url: str):
    _zap_req("/JSON/core/action/accessUrl/", {"url": url}, timeout=10)


def _zap_spider(url: str) -> str:
    params = {
        "url": url,
        "maxChildren": ZAP_CHILDREN,
        "recurse": "true" if ZAP_RECURSE else "false",
    }
    r = _zap_req("/JSON/spider/action/scan/", params, timeout=15)
    return r.json().get("scan")


def _zap_is_spider_done(scan_id: str | None) -> bool:
    if not scan_id:
        return False
    r = _zap_req("/JSON/spider/view/status/", {"scanId": scan_id}, timeout=10)
    pct = int(r.json().get("status", "0"))
    return pct >= 100


def _zap_alerts(baseurl: str):
    r = _zap_req("/JSON/core/view/alerts/", {"baseurl": baseurl}, timeout=20)
    alerts = r.json().get("alerts", [])
    findings = []
    for a in alerts:
        findings.append({
            "title": a.get("alert"),
            "severity": a.get("risk") or "info",
            "evidence": a.get("url")
        })
    return findings


def _normalise(zap_findings, open_ports, notes):
    risk_score = min(100, (len(zap_findings) * 10) + (len(open_ports) * 5))
    return {
        "status": "complete",
        "stage": "complete",
        "risk_score": risk_score,
        "summary": {
            "critical": 0,
            "high": len(zap_findings),
            "medium": len(open_ports),
            "low": 0
        },
        "zap": {"findings": zap_findings},
        "nmap": {"open_ports": open_ports},
        "notes": notes
    }


@app.route("/", methods=["GET"])
def health():
    return jsonify({"ok": True})


@app.route("/scan/start", methods=["POST"])
def start_scan():
    if request.headers.get("Authorization") != f"Bearer {WORKER_API_KEY}":
        return _unauthorized()

    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip().lower()
    profile_name = (data.get("profile") or "lite").strip().lower()

    if not target:
        return jsonify({"error": "missing_target"}), 400

    profile = PROFILES.get(profile_name) or PROFILES.get("lite")
    if not profile:
        return jsonify({"error": "missing_profile_config"}), 500

    job_id = str(uuid.uuid4())
    nmap_out = f"/tmp/{job_id}_nmap.xml"

    # Start Nmap
    nmap_args = profile["nmap"]["args"]
    nmap_cmd = f'nmap {nmap_args} --host-timeout {NMAP_MAX_SECONDS}s -oX - "{target}" > "{nmap_out}"'
    subprocess.Popen(nmap_cmd, shell=True)

    job = {
        "job_id": job_id,
        "status": "running",
        "stage": "starting",
        "target": target,
        "profile": profile_name,
        "created_at": _now(),
        "nmap_out": nmap_out,
        "zap_status": "not_started",
        "zap_scan_id": None,
        "zap_findings": [],
        "notes": [],
    }

    # Kick off ZAP spider remotely
    if not _zap_enabled():
        job["zap_status"] = "error"
        job["notes"].append("zap_not_configured")
    elif not _zap_api_ok():
        job["zap_status"] = "error"
        job["notes"].append("zap_not_running")
    else:
        try:
            url = _zap_target_url(target)
            _zap_access_url(url)
            scan_id = _zap_spider(url)
            job["zap_status"] = "spidering"
            job["zap_scan_id"] = scan_id
        except Exception:
            job["zap_status"] = "error"
            job["notes"].append("zap_api_error")

    _save_job(job)
    return jsonify({"job_id": job_id})


@app.route("/scan/status/<job_id>", methods=["GET"])
def status(job_id):
    if request.headers.get("Authorization") != f"Bearer {WORKER_API_KEY}":
        return _unauthorized()

    job = _load_job(job_id)
    if not job:
        return jsonify({"error": "unknown_job"}), 404

    elapsed = _now() - int(job["created_at"])
    notes = job.get("notes", [])

    # Progress ZAP
    zap_status = job.get("zap_status", "not_started")
    if zap_status in ("spidering", "not_started"):
        if not _zap_api_ok():
            job["zap_status"] = "error"
            if "zap_not_running" not in notes:
                notes.append("zap_not_running")
        else:
            if elapsed <= ZAP_MAX_SECONDS:
                try:
                    done = _zap_is_spider_done(job.get("zap_scan_id"))
                    if done:
                        job["zap_findings"] = _zap_alerts(_zap_target_url(job["target"]))
                        job["zap_status"] = "complete"
                    else:
                        job["zap_status"] = "spidering"
                except Exception:
                    job["zap_status"] = "error"
                    if "zap_api_error" not in notes:
                        notes.append("zap_api_error")
            else:
                job["zap_status"] = "timed_out"
                if "zap_timed_out" not in notes:
                    notes.append("zap_timed_out")

    # Nmap readiness
    nmap_info = _file_info(job["nmap_out"])
    nmap_ready = _ready(job["nmap_out"], NMAP_MIN_BYTES)

    if nmap_ready and not _looks_complete_nmap_xml(job["nmap_out"]) and elapsed < (NMAP_MAX_SECONDS + NMAP_GRACE_SECONDS):
        job["notes"] = notes
        _save_job(job)
        return jsonify({
            "status": "running",
            "stage": "nmap",
            "elapsed_seconds": elapsed,
            "notes": notes,
            "debug": {"nmap_file": nmap_info, "nmap_complete": False, "zap_status": job.get("zap_status")}
        })

    if not nmap_ready and elapsed < (NMAP_MAX_SECONDS + NMAP_GRACE_SECONDS):
        job["notes"] = notes
        _save_job(job)
        return jsonify({
            "status": "running",
            "stage": "nmap",
            "elapsed_seconds": elapsed,
            "notes": notes,
            "debug": {"nmap_file": nmap_info, "zap_status": job.get("zap_status")}
        })

    # Parse Nmap
    open_ports = []
    if nmap_ready:
        try:
            open_ports = _parse_nmap_open_ports(job["nmap_out"])
        except ValueError as ve:
            if str(ve) == "nmap_output_not_xml" and "nmap_no_xml" not in notes:
                notes.append("nmap_no_xml")
            elif str(ve) == "nmap_output_incomplete_xml" and "nmap_incomplete_xml" not in notes:
                notes.append("nmap_incomplete_xml")
            else:
                if "nmap_parse_error" not in notes:
                    notes.append("nmap_parse_error")
        except Exception:
            if "nmap_parse_error" not in notes:
                notes.append("nmap_parse_error")
    else:
        if "nmap_no_output" not in notes:
            notes.append("nmap_no_output")

    result = _normalise(job.get("zap_findings", []), open_ports, notes)
    result["debug"] = {
        "elapsed_seconds": elapsed,
        "nmap_file": nmap_info,
        "zap_status": job.get("zap_status"),
        "zap_findings_count": len(job.get("zap_findings", [])),
        "target": job["target"],
        "profile": job["profile"]
    }

    job["status"] = "complete"
    job["stage"] = "complete"
    job["notes"] = notes
    _save_job(job)

    return jsonify(result)
