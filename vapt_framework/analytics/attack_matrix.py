import json
import csv
import io
import sys
from typing import Dict, List, Any

# Column headers matching Figure 31 of thesis
ATTACK_VULN_COLUMNS = [
    "CSP Wildcard Directive",
    "CSP: style-src unsafe inline",
    "CSP: script-src unsafe inline",
    "X-frame option header not set",
    "Absence of Anti-CSRF Tokens",
    "Cross-domain JavaScript source file inclusion",
    "Secure pages include mixed content",
    "Cookie without same site attribute",
    "Incomplete or no cache control",
    "X-content type option header missing"
]

# Attack categories matching Figure 31 of thesis
EMPIRICAL_ATTACK_MAPPINGS: Dict[str, List[str]] = {
    "XSS attack": [
        "CSP Wildcard Directive",
        "CSP: style-src unsafe inline",
        "CSP: script-src unsafe inline",
        "X-content type option header missing"
    ],
    "XSSI attack": [
        "Cross-domain JavaScript source file inclusion",
        "Cookie without same site attribute"
    ],
    "Data Injection Attack": [
        "CSP Wildcard Directive"
    ],
    "Clickjacking Attack": [
        "X-frame option header not set"
    ],
    "CSRF Attack": [
        "Absence of Anti-CSRF Tokens",
        "Cookie without same site attribute"
    ],
    "Man-In-The-Middle Attack": [
        "Secure pages include mixed content"
    ],
    "Timing Attack": [
        "Cookie without same site attribute"
    ],
    "Cache Poisoning Software Attack": [
        "Incomplete or no cache control"
    ],
    "File Inclusion Attack": [
        "Cross-domain JavaScript source file inclusion"
    ],
    "MIME Sniffing Attack": [
        "X-content type option header missing"
    ]
}


class AttackMatrixEngine:
    """
    Generates and exports the Vulnerability vs. Attack Matrix (Figure 31 of thesis).
    Maps attack vectors to enabling vulnerabilities.
    """

    def __init__(self, mappings: Dict[str, List[str]] = None):
        self.mappings = mappings or EMPIRICAL_ATTACK_MAPPINGS
        self.columns = ATTACK_VULN_COLUMNS

    def to_markdown(self) -> str:
        lines = []
        headers = ["Attack Vector"] + self.columns
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("| " + " | ".join(["---"] * len(headers)) + " |")

        for attack, enabled_vulns in self.mappings.items():
            row = [f"**{attack}**"]
            for col in self.columns:
                if col in enabled_vulns:
                    row.append("[X]")
                else:
                    row.append("-")
            lines.append("| " + " | ".join(row) + " |")
        return "\n".join(lines)

    def to_csv(self) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Attack Vector"] + self.columns)
        for attack, enabled_vulns in self.mappings.items():
            row = [attack] + ["1" if col in enabled_vulns else "0" for col in self.columns]
            writer.writerow(row)
        return output.getvalue()

    def to_json(self) -> str:
        data = {}
        for attack, enabled_vulns in self.mappings.items():
            data[attack] = {col: (col in enabled_vulns) for col in self.columns}
        return json.dumps(data, indent=2)
