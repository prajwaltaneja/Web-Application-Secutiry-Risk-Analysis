import re
from typing import Dict, Any, List

class WhatWebParser:
    """
    Parses WhatWeb verbose output.
    """

    @staticmethod
    def parse_text(output_text: str) -> Dict[str, Any]:
        result = {
            "target_url": None,
            "status": None,
            "title": None,
            "ip": None,
            "country": None,
            "plugins": {}
        }

        url_m = re.search(r"WhatWeb report for (https?://[^\s]+)", output_text)
        if url_m:
            result["target_url"] = url_m.group(1)

        status_m = re.search(r"Status\s*:\s*([0-9]{3})", output_text)
        if status_m:
            result["status"] = int(status_m.group(1))

        ip_m = re.search(r"IP\s*:\s*([0-9.]+)", output_text)
        if ip_m:
            result["ip"] = ip_m.group(1)

        # Detect notable tech components
        tech_indicators = {
            "Cloudflare": "Cloudflare" in output_text,
            "CloudFront": "CloudFront" in output_text or "cloudfront" in output_text.lower(),
            "Tengine": "Tengine" in output_text,
            "Nginx": "nginx" in output_text.lower(),
            "HTML5": "HTML5" in output_text,
            "Strict-Transport-Security": "Strict-Transport-Security" in output_text,
            "X-Frame-Options": "X-Frame-Options" in output_text,
            "X-XSS-Protection": "X-XSS-Protection" in output_text
        }
        result["plugins"] = {k: v for k, v in tech_indicators.items() if v}
        return result
