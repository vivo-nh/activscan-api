PROFILES = {
    "lite": {
        "nmap": {
            # -Pn: skip host discovery (often blocked)
            # -sT: TCP connect scan (works without raw socket privileges)
            # --top-ports 50: reasonable speed
            # --open: only open ports in output
            "args": "-Pn -sT --top-ports 50 --open"
        }
    }
}
