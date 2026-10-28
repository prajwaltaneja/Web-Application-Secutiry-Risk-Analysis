import re
from typing import Dict, Any, List

class NiktoParser:
    """
    Parses Nikto console text outputs.
    """

    IGNORABLE_PREFIXES = (
        "target ip:",
        "target hostname:",
        "target port:",
        "server:",
        "ssl info:",
        "start time:",
        "end time:",
        "message:",
        "scan terminated:"
    )

    @staticmethod
    def parse_text(output_text: str) -> Dict[str, Any]:
        result = {
            "target_ip": None,
            "target_hostname": None,
            "target_port": None,
            "server_banner": None,
            "ssl_info": None,
            "vulnerabilities": []
        }

        ip_m = re.search(r"Target IP:\s+([0-9.]+)", output_text)
        if ip_m:
            result["target_ip"] = ip_m.group(1)

        host_m = re.search(r"Target Hostname:\s+([^\r\n]+)", output_text)
        if host_m:
            result["target_hostname"] = host_m.group(1).strip()

        port_m = re.search(r"Target Port:\s+([0-9]+)", output_text)
        if port_m:
            result["target_port"] = int(port_m.group(1))

        server_m = re.search(r"Server:\s+([^\r\n]+)", output_text)
        if server_m:
            result["server_banner"] = server_m.group(1).strip()

        ssl_m = re.search(r"SSL Info:\s+Subject:\s+([^\r\n]+)", output_text)
        if ssl_m:
            result["ssl_info"] = ssl_m.group(1).strip()

        # Extract items starting with "+ " that are actual findings
        items = re.findall(r"\+\s+([^\r\n]+)", output_text)
        for item in items:
            cleaned = item.strip()
            if not any(cleaned.lower().startswith(prefix) for prefix in NiktoParser.IGNORABLE_PREFIXES):
                result["vulnerabilities"].append(cleaned)

        return result
