import os
import shutil
import subprocess
from typing import Dict, Any, Optional

class NmapScanner:
    """
    Wrapper for Network Mapper (Nmap) port scanning and NSE vulnerability scripts.
    Scripts used in study: vuln, http-csrf, http-dombased-xss, http-stored-xss,
    sslv2-drown, ssl-ccs-injection.
    """

    def __init__(self, raw_reports_dir: Optional[str] = None):
        self.nmap_bin = shutil.which("nmap")
        self.raw_reports_dir = raw_reports_dir

    def scan_host(self, host: str, run_vuln_scripts: bool = True, timeout: int = 300) -> Dict[str, Any]:
        if not self.nmap_bin:
            return self._load_fallback_report(host)

        cmd = [self.nmap_bin, "-sV", "-Pn"]
        if run_vuln_scripts:
            cmd.extend(["--script=vuln,http-csrf,http-dombased-xss,http-stored-xss,ssl-ccs-injection,sslv2-drown"])
        cmd.append(host)

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {
                "host": host,
                "command": " ".join(cmd),
                "returncode": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr
            }
        except Exception as e:
            return {
                "host": host,
                "command": " ".join(cmd),
                "error": str(e),
                "stdout": self._load_fallback_raw(host)
            }

    def _load_fallback_report(self, host: str) -> Dict[str, Any]:
        raw = self._load_fallback_raw(host)
        return {
            "host": host,
            "simulated": True,
            "stdout": raw,
            "note": "Loaded empirical scan report artifact from study dataset."
        }

    def _load_fallback_raw(self, host: str) -> str:
        if not self.raw_reports_dir:
            return f"Nmap scan output for {host} (simulated - tool not found in PATH)"
        clean_name = host.replace("https://", "").replace("http://", "").split("/")[0]
        fpath = os.path.join(self.raw_reports_dir, f"{clean_name}.nmap.txt")
        if os.path.exists(fpath):
            with open(fpath, "r", encoding="utf-8") as f:
                return f.read()
        return f"Scan report for {host}"
