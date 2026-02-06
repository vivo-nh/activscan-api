from flask import Flask, request, jsonify
import subprocess
import uuid
import os
import time
import json
import requests
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List

from profiles import PROFILES

# Auth between WP plugin -> this API
WORKER_API_KEY = os.getenv("WORKER_API_KEY", "")

# Remote ZAP
ZAP_API = os.getenv("ZAP_API", "").rstrip("/")          # e.g. https://<zap-service>  (NO trailing slash preferred)
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")              # must match zap service key

# ZAP "lite" controls
ZAP_MAX_SECONDS = int(os.getenv("ZAP_MAX_SECONDS", "240"))
ZAP_CHILDREN = int(os.getenv("ZAP_CHILDREN", "60"))
ZAP_RECURSE = os.getenv("ZAP_RECURSE", "false").lower() in ("1", "true", "yes")
ZAP_PASSIVE_SETTLE_SECONDS = int(os.getenv("ZAP_PASSIVE_SETTLE_SECONDS", "8"))  # lite: short wait for passive rules
ZAP_ALERTS_MAX = int(os.getenv("ZAP_ALERTS_MAX", "20"))                          # cap findings returned

# Nmap controls
NMAP_MAX_SECONDS = int(os.getenv("NMAP_MAX_SECONDS", "60"))
NMAP_MIN_BYTES = int(os.getenv("NMAP_MIN_BYTES", "300"))
NMAP_GRACE_SECONDS = int(os.getenv("NMAP_GRACE_SECONDS", "30"))

JOBS_DIR = Path(os.getenv("JOBS_DIR", "/tmp/jobs"))
JOBS_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

# Reuse HTTP connections (faster + more reliable under load)
HTTP = requests.Session()
HTTP.headers.update({"User-Agent": "ACTIVSCAN-Lite/1.0"})


def _now() -> int:
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


def _zap_url(path: str) -> str:
    # path should start with "/JSON/..."
    if not path.startswith("/"):
        path = "/" + path
    return f"{ZAP_API}{path}"


def _zap_req(path: str, params: dict, timeout: int = 10) -> requests.Response:
    params = dict(params or {})
    params["apikey"] = ZAP_API_KEY
    url = _zap_url(path)
    r = HTTP.get(url, params=params, timeout=timeout, allow_redirects=True)
    r.raise_for_status()
    return r


def _zap_diag() -> Dict[str, Any]:
    """
    Returns a diagnostic object you can surface in job/debug.
    Helps distinguish:
      - unreachable
      - auth failed
      - redirect loops
      - non-json responses
    """
    if not _zap_enabled():
        return {"ok": False, "reason": "not_configured"}

    try:
        url = _zap_url("/JSON/core/view/version/")
        r = HTTP.get(url, params={"apikey": ZAP_API_KEY}, timeout=6, allow_redirects=True)

        # Auth failures from ZAP typically come as 401/403 (or 200 with an error payload depending on config)
        diag = {
            "ok": r.ok,
            "http_status": r.status_code,
            "final_url": r.url,
            "redirects": len(r.history) if r.history else 0,
        }

        # Try parse JSON
        try:
            js = r.json()
            diag["json"] = True
            diag["version"] = js.get("version") or js.get("core", {}).get("version")
            # If ZAP returns an API error envelope, capture that
            if isinstance(js, dict) and ("code" in js or "message" in js):
                diag["zap_error"] = js
        except Exception:
            diag["json"] = False
            diag["body_head"] = (r.text or "")[:200]

        # A redirect loop usually manifests as many redirects, or a final_url that differs and returns HTML
        if diag.get("redirects", 0) >= 5:
            diag["ok"] = False
            diag["reason"] = "too_many_redirects"
        elif r.status_code in (401, 403):
            diag["ok"] = False
            diag["reason"] = "auth_failed"
        elif not r.ok:
            diag["ok"] = False
            diag["reason"] = "bad_status"
        elif not diag.get("json", False):
            diag["ok"] = False
            diag["reason"] = "non_json_response"
        else:
            diag["reason"] = "ok"

        return diag

    except requests.exceptions.TooManyRedirects:
        return {"ok": False, "reason": "too_many_redirects"}
    except requests.exceptions.ConnectTimeout:
        return {"ok": False, "reason": "connect_timeout"}
    except requests.exceptions.ReadTimeout:
        return {"ok": False, "reason": "read_timeout"}
    except requests.exceptions.ConnectionError as ce:
        return {"ok": False, "reason": "connection_error", "detail": str(ce)[:200]}
    except Exception as e:
        return {"ok": False, "reason": "unknown_error", "detail": str(e)[:200]}


def _zap_target_candidates(target: str) -> List[str]:
    """
    Try https first, then http. Some sites behave better when first accessed over http
    (or have unusual redirect behaviour).
    """
    t = target.strip()
    if t.startswith("http://") or t.startswith("https://"):
        return [t]
    return [f"https://{t}", f"http://{t}"]


def _zap_access_url(url: str):
    _zap_req("/JSON/core/action/accessUrl/", {"url": url}, timeout=12)


def _zap_spider(url: str) -> Optional[str]:
    params = {
        "url": url,
        "maxChildren": ZAP_CHILDREN,
        "recurse": "true" if ZAP_RECURSE else "false",
    }
    r = _zap_req("/JSON/spider/action/scan/", params, timeout=20)
    return (r.json() or {}).get("scan")


def _zap_is_spider_done(scan_id: Optional[str]) -> Tuple[bool, int]:
    if not scan_id:
        return (False, 0)
    r = _zap_req("/JSON/spider/view/status/", {"scanId": scan_id}, timeout=12)
    pct = int((r.json() or {}).get("status", "0"))
    return (pct >= 100, pct)


def _zap_alerts_summary(baseurl: str) -> Dict[str, Any]:
    """
    Returns counts by risk. Useful even when alert list is empty.
    """
    r = _zap_req("/JSON/core/view/alertsSummary/", {"baseurl": baseurl}, timeout=20)
    js = r.json() or {}
    # ZAP returns something like {"alertsSummary": {"High": "1", "Medium":"2", ...}}
    summary = js.get("alertsSummary", {}) if isinstance(js, dict) else {}
    # Normalise
    out = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for k, v in (summary or {}).items():
        key = str(k).strip().lower()
        try:
            out[key] = int(v)
        except Exception:
            pass
    return out


def _zap_alerts(baseurl: str, limit: int = 20) -> List[Dict[str, Any]]:
    """
    Pull a capped list of alerts and convert into your existing 'findings' format.
    """
    params = {"baseurl": baseurl, "start": 0, "count": int(limit)}
    r = _zap_req("/JSON/core/view/alerts/", params, timeout=25)
    alerts = (r.json() or {}).get("alerts", []) or []

    findings = []
    for a in alerts:
        # risk: "High"/"Medium"/"Low"/"Informational"
        risk = (a.get("risk") or "info").strip().lower()
        conf = (a.get("confidence") or "").strip().lower()
        url = a.get("url")
        alert_name = a.get("alert")
        param = a.get("param") or ""
        evidence = a.get("evidence") or ""

        # Keep backwards compatibility with your UI: title/severity/evidence
        findings.append({
            "title": alert_name or "ZAP finding",
            "severity": risk,               # high/medium/low/info
            "evidence": url or "",
            "confidence": conf,
            "param": param,
            "zap_plugin_id": a.get("pluginId"),
            "description": a.get("description") or "",
            "solution": a.get("solution") or "",
            "reference": a.get("reference") or "",
            "wascid": a.get("wascid"),
            "cweid": a.get("cweid"),
            "other": a.get("other") or "",
            "attack": a.get("attack") or "",
            "evidence_detail": evidence
        })

    return findings


def _calc_risk_score(zap_summary: Dict[str, int], open_ports: List[Dict[str, Any]]) -> int:
    # Conservative scoring; keep stable
    high = int(zap_summary.get("high", 0))
    med = int(zap_summary.get("medium", 0))
    low = int(zap_summary.get("low", 0))
    info = int(zap_summary.get("info", 0))

    # Ports weighting: common web ports are lower weight; uncommon higher
    port_points = 0
    for p in open_ports:
        port = int(p.get("port", 0))
        if port in (80, 443):
            port_points += 2
        elif port in (8080, 8443):
            port_points += 4
        else:
            port_points += 6

    score = (high * 18) + (med * 10) + (low * 4) + min(10, info) + port_points
    return max(0, min(100, score))


def _normalise(zap_findings, zap_summary, open_ports, notes, zap_meta=None):
    zap_summary = zap_summary or {"high": 0, "medium": 0, "low": 0, "info": 0}
    risk_score = _calc_risk_score(zap_summary, open_ports)

    return {
        "status": "complete",
        "stage": "complete",
        "risk_score": risk_score,
        "summary": {
            "critical": 0,  # lite mode doesn't attempt exploit confirmation
            "high": int(zap_summary.get("high", 0)),
            "medium": int(zap_summary.get("medium", 0)),
            "low": int(zap_summary.get("low", 0)),
            "info": int(zap_summary.get("info", 0)),
        },
        "zap": {
            "findings": zap_findings,
            "summary": zap_summary,
            "meta": zap_meta or {}
        },
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

    # Start Nmap (async)
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
        "zap_summary": {"high": 0, "medium": 0, "low": 0, "info": 0},
        "zap_baseurl": None,
        "zap_diag": None,
        "zap_meta": {},

        "notes": [],
    }

    # Kick off ZAP spider remotely
    if not _zap_enabled():
        job["zap_status"] = "error"
        job["notes"].append("zap_not_configured")
        job["zap_diag"] = {"ok": False, "reason": "not_configured"}
    else:
        diag = _zap_diag()
        job["zap_diag"] = diag

        if not diag.get("ok"):
            job["zap_status"] = "error"
            # Keep old note for UI compatibility, but add more specific notes too
            job["notes"].append("zap_not_running")
            job["notes"].append(f"zap_{diag.get('reason','unknown')}")
        else:
            # Try https then http (or use provided full URL)
            candidates = _zap_target_candidates(target)
            started = False
            last_err = None

            for url in candidates:
                try:
                    _zap_access_url(url)
                    scan_id = _zap_spider(url)
                    if scan_id:
                        job["zap_status"] = "spidering"
                        job["zap_scan_id"] = scan_id
                        job["zap_baseurl"] = url
                        job["zap_meta"] = {"started_url": url, "candidates": candidates}
                        started = True
                        break
                    else:
                        last_err = "no_scan_id"
                except Exception as e:
                    last_err = str(e)[:180]

            if not started:
                job["zap_status"] = "error"
                job["notes"].append("zap_api_error")
                if last_err:
                    job["zap_diag"] = {**job.get("zap_diag", {}), "start_error": last_err}

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
        diag = _zap_diag()
        job["zap_diag"] = diag

        if not diag.get("ok"):
            job["zap_status"] = "error"
            if "zap_not_running" not in notes:
                notes.append("zap_not_running")
            reason = diag.get("reason", "unknown")
            tag = f"zap_{reason}"
            if tag not in notes:
                notes.append(tag)
        else:
            if elapsed <= ZAP_MAX_SECONDS:
                try:
                    done, pct = _zap_is_spider_done(job.get("zap_scan_id"))
                    job["zap_meta"] = {**(job.get("zap_meta") or {}), "spider_pct": pct}

                    if done:
                        baseurl = job.get("zap_baseurl") or _zap_target_candidates(job["target"])[0]
                        # Short passive settle window (lite)
                        time.sleep(max(0, min(20, ZAP_PASSIVE_SETTLE_SECONDS)))

                        # Fetch summary + capped list of alerts
                        summary = _zap_alerts_summary(baseurl)
                        findings = _zap_alerts(baseurl, limit=ZAP_ALERTS_MAX)

                        job["zap_summary"] = summary
                        job["zap_findings"] = findings
                        job["zap_status"] = "complete"
                    else:
                        job["zap_status"] = "spidering"
                except Exception as e:
                    job["zap_status"] = "error"
                    if "zap_api_error" not in notes:
                        notes.append("zap_api_error")
                    job["zap_diag"] = {**(job.get("zap_diag") or {}), "status_error": str(e)[:180]}
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
            "debug": {
                "nmap_file": nmap_info,
                "nmap_complete": False,
                "zap_status": job.get("zap_status"),
                "zap_diag": job.get("zap_diag"),
            }
        })

    if not nmap_ready and elapsed < (NMAP_MAX_SECONDS + NMAP_GRACE_SECONDS):
        job["notes"] = notes
        _save_job(job)
        return jsonify({
            "status": "running",
            "stage": "nmap",
            "elapsed_seconds": elapsed,
            "notes": notes,
            "debug": {
                "nmap_file": nmap_info,
                "zap_status": job.get("zap_status"),
                "zap_diag": job.get("zap_diag"),
            }
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

    # Build final response
    zap_findings = job.get("zap_findings", []) or []
    zap_summary = job.get("zap_summary", {"high": 0, "medium": 0, "low": 0, "info": 0}) or {"high": 0, "medium": 0, "low": 0, "info": 0}
    zap_meta = job.get("zap_meta", {}) or {}
    zap_diag = job.get("zap_diag", None)

    if zap_diag:
        zap_meta["diag"] = zap_diag
    if job.get("zap_baseurl"):
        zap_meta["baseurl"] = job.get("zap_baseurl")

    result = _normalise(zap_findings, zap_summary, open_ports, notes, zap_meta=zap_meta)

    result["debug"] = {
        "elapsed_seconds": elapsed,
        "nmap_file": nmap_info,
        "zap_status": job.get("zap_status"),
        "zap_findings_count": len(zap_findings),
        "zap_summary": zap_summary,
        "zap_baseurl": job.get("zap_baseurl"),
        "zap_diag": zap_diag,
        "target": job["target"],
        "profile": job["profile"]
    }

    job["status"] = "complete"
    job["stage"] = "complete"
    job["notes"] = notes
    _save_job(job)

    return jsonify(result)
