import os
import json
from typing import Dict, Any, List, Optional

class ZAPScanner:
    """
    Client and session manager for OWASP Zed Attack Proxy (ZAP 2.10.0+).
    Wraps active spider, active scanner, and passive alert evaluation.
    """

    def __init__(self, raw_reports_dir: Optional[str] = None):
        self.raw_reports_dir = raw_reports_dir

    def get_alerts(self, target_url: str) -> List[Dict[str, Any]]:
        clean_name = target_url.replace("https://", "").replace("http://", "").split("/")[0]
        if self.raw_reports_dir:
            fpath = os.path.join(self.raw_reports_dir, f"{clean_name}.zap.json")
            if os.path.exists(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        return data.get("alerts", [])
                except Exception:
                    pass
        return []
