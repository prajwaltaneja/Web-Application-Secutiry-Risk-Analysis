import os
import shutil
import subprocess
from typing import Dict, Any, Optional

class SQLMapScanner:
    """
    Automation harness for SQLMap injection testing.
    Verifies WAF/IPS presence (e.g. Cloudflare) and tests parameter heuristics.
    """

    def __init__(self, raw_reports_dir: Optional[str] = None):
        self.sqlmap_bin = shutil.which("sqlmap")
        self.raw_reports_dir = raw_reports_dir

    def probe_target(self, target_url: str, timeout: int = 180) -> Dict[str, Any]:
        if not self.sqlmap_bin:
            return self._load_fallback_report(target_url)

        cmd = [self.sqlmap_bin, "-u", target_url, "--batch", "--random-agent", "--level", "1", "--risk", "1"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {
                "target": target_url,
                "command": " ".join(cmd),
                "returncode": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr
            }
        except Exception as e:
            return {
                "target": target_url,
                "error": str(e),
                "stdout": self._load_fallback_raw(target_url)
            }

    def _load_fallback_report(self, target_url: str) -> Dict[str, Any]:
        return {
            "target": target_url,
            "simulated": True,
            "stdout": self._load_fallback_raw(target_url)
        }

    def _load_fallback_raw(self, target_url: str) -> str:
        if not self.raw_reports_dir:
            return f"SQLMap test output for {target_url}"
        clean_name = target_url.replace("https://", "").replace("http://", "").split("/")[0]
        fpath = os.path.join(self.raw_reports_dir, f"{clean_name}.sqlmap.txt")
        if os.path.exists(fpath):
            with open(fpath, "r", encoding="utf-8") as f:
                return f.read()
        return f"SQLMap log for {target_url}"
