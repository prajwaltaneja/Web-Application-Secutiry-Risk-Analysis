import re
from typing import Dict, Any, List

class NmapParser:
    """
    Parses Nmap output (both raw text and script scan output).
    """

    @staticmethod
    def parse_text(output_text: str) -> Dict[str, Any]:
        result = {
            "target_ip": None,
            "host_status": "unknown",
            "ports": [],
            "os_detection": None,
            "script_results": {}
        }

        # IP extraction
        ip_match = re.search(r"Nmap scan report for (?:[^\s]+ \()?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\)?", output_text)
        if ip_match:
            result["target_ip"] = ip_match.group(1)

        # Host status
        if "Host is up" in output_text:
            result["host_status"] = "up"

        # Ports extraction
        port_lines = re.findall(r"^([0-9]+/(?:tcp|udp))\s+([a-zA-Z]+)\s+([^\s]+)\s*(.*)$", output_text, re.MULTILINE)
        for port, state, service, version in port_lines:
            result["ports"].append({
                "port": port,
                "state": state,
                "service": service,
                "version": version.strip()
            })

        # Script results
        scripts = ["http-csrf", "http-dombased-xss", "http-stored-xss", "ssl-ccs-injection", "sslv2-drown"]
        for s in scripts:
            match = re.search(r"\|_?\s*" + re.escape(s) + r":\s*([^\r\n]+)", output_text)
            if match:
                result["script_results"][s] = match.group(1).strip()

        # OS detection
        os_match = re.search(r"Running (?:\(JUST GUESSING\))?:\s*([^\r\n]+)", output_text)
        if os_match:
            result["os_detection"] = os_match.group(1).strip()

        return result
