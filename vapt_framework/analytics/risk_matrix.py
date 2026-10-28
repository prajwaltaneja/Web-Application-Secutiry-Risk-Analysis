import json
import csv
import io
from typing import Dict, List, Any

# Column headers matching Figure 30 of thesis
RISK_VULN_COLUMNS = [
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

# Baseline empirical findings from B.Tech major project thesis (Figure 30)
EMPIRICAL_RISK_DATA: Dict[str, Dict[str, str]] = {
    "blockchain.com": {
        "CSP Wildcard Directive": "M",
        "CSP: style-src unsafe inline": "M",
        "CSP: script-src unsafe inline": "",
        "X-frame option header not set": "M",
        "Absence of Anti-CSRF Tokens": "L",
        "Cross-domain JavaScript source file inclusion": "",
        "Secure pages include mixed content": "",
        "Cookie without same site attribute": "",
        "Incomplete or no cache control": "L",
        "X-content type option header missing": ""
    },
    "binance.com": {
        "CSP Wildcard Directive": "M",
        "CSP: style-src unsafe inline": "M",
        "CSP: script-src unsafe inline": "M",
        "X-frame option header not set": "",
        "Absence of Anti-CSRF Tokens": "",
        "Cross-domain JavaScript source file inclusion": "L",
        "Secure pages include mixed content": "",
        "Cookie without same site attribute": "L",
        "Incomplete or no cache control": "L",
        "X-content type option header missing": "L"
    },
    "crypto.com": {
        "CSP Wildcard Directive": "M",
        "CSP: style-src unsafe inline": "M",
        "CSP: script-src unsafe inline": "M",
        "X-frame option header not set": "",
        "Absence of Anti-CSRF Tokens": "",
        "Cross-domain JavaScript source file inclusion": "",
        "Secure pages include mixed content": "",
        "Cookie without same site attribute": "L",
        "Incomplete or no cache control": "L",
        "X-content type option header missing": "L"
    },
    "m.kucoin.com": {
        "CSP Wildcard Directive": "M",
        "CSP: style-src unsafe inline": "M",
        "CSP: script-src unsafe inline": "M",
        "X-frame option header not set": "",
        "Absence of Anti-CSRF Tokens": "",
        "Cross-domain JavaScript source file inclusion": "L",
        "Secure pages include mixed content": "",
        "Cookie without same site attribute": "L",
        "Incomplete or no cache control": "L",
        "X-content type option header missing": ""
    },
    "coincheck.com": {
        "CSP Wildcard Directive": "",
        "CSP: style-src unsafe inline": "",
        "CSP: script-src unsafe inline": "",
        "X-frame option header not set": "",
        "Absence of Anti-CSRF Tokens": "L",
        "Cross-domain JavaScript source file inclusion": "L",
        "Secure pages include mixed content": "M",
        "Cookie without same site attribute": "L",
        "Incomplete or no cache control": "L",
        "X-content type option header missing": "L"
    },
    "wazirx.com": {
        "CSP Wildcard Directive": "",
        "CSP: style-src unsafe inline": "",
        "CSP: script-src unsafe inline": "",
        "X-frame option header not set": "",
        "Absence of Anti-CSRF Tokens": "",
        "Cross-domain JavaScript source file inclusion": "",
        "Secure pages include mixed content": "",
        "Cookie without same site attribute": "",
        "Incomplete or no cache control": "L",
        "X-content type option header missing": "L"
    },
    "bitcoin.com": {
        "CSP Wildcard Directive": "",
        "CSP: style-src unsafe inline": "",
        "CSP: script-src unsafe inline": "",
        "X-frame option header not set": "M",
        "Absence of Anti-CSRF Tokens": "L",
        "Cross-domain JavaScript source file inclusion": "L",
        "Secure pages include mixed content": "",
        "Cookie without same site attribute": "",
        "Incomplete or no cache control": "L",
        "X-content type option header missing": "L"
    },
    "poly.network": {
        "CSP Wildcard Directive": "M",
        "CSP: style-src unsafe inline": "",
        "CSP: script-src unsafe inline": "",
        "X-frame option header not set": "",
        "Absence of Anti-CSRF Tokens": "",
        "Cross-domain JavaScript source file inclusion": "L",
        "Secure pages include mixed content": "",
        "Cookie without same site attribute": "",
        "Incomplete or no cache control": "L",
        "X-content type option header missing": "L"
    },
    "etherium.com": {
        "CSP Wildcard Directive": "",
        "CSP: style-src unsafe inline": "",
        "CSP: script-src unsafe inline": "",
        "X-frame option header not set": "",
        "Absence of Anti-CSRF Tokens": "L",
        "Cross-domain JavaScript source file inclusion": "",
        "Secure pages include mixed content": "",
        "Cookie without same site attribute": "",
        "Incomplete or no cache control": "L",
        "X-content type option header missing": "L"
    },
    "blockchain.com(wallet)": {
        "CSP Wildcard Directive": "M",
        "CSP: style-src unsafe inline": "M",
        "CSP: script-src unsafe inline": "",
        "X-frame option header not set": "",
        "Absence of Anti-CSRF Tokens": "L",
        "Cross-domain JavaScript source file inclusion": "",
        "Secure pages include mixed content": "",
        "Cookie without same site attribute": "",
        "Incomplete or no cache control": "L",
        "X-content type option header missing": ""
    },
    "bitcoin.com(wallet)": {
        "CSP Wildcard Directive": "",
        "CSP: style-src unsafe inline": "",
        "CSP: script-src unsafe inline": "",
        "X-frame option header not set": "M",
        "Absence of Anti-CSRF Tokens": "L",
        "Cross-domain JavaScript source file inclusion": "L",
        "Secure pages include mixed content": "",
        "Cookie without same site attribute": "",
        "Incomplete or no cache control": "L",
        "X-content type option header missing": ""
    },
    "atomic.io": {
        "CSP Wildcard Directive": "M",
        "CSP: style-src unsafe inline": "",
        "CSP: script-src unsafe inline": "",
        "X-frame option header not set": "",
        "Absence of Anti-CSRF Tokens": "L",
        "Cross-domain JavaScript source file inclusion": "",
        "Secure pages include mixed content": "",
        "Cookie without same site attribute": "",
        "Incomplete or no cache control": "L",
        "X-content type option header missing": "L"
    }
}


class RiskMatrixEngine:
    """
    Generates and exports the empirical Risk Matrix (Figure 30 of thesis).
    Maps 12 target systems to severity ratings (M: Medium, L: Low, -: Not Present).
    """

    def __init__(self, data: Dict[str, Dict[str, str]] = None):
        self.data = data or EMPIRICAL_RISK_DATA
        self.columns = RISK_VULN_COLUMNS

    def to_markdown(self) -> str:
        lines = []
        headers = ["Target Website"] + self.columns
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("| " + " | ".join(["---"] * len(headers)) + " |")

        for site, vulns in self.data.items():
            row = [f"**{site}**"]
            for col in self.columns:
                val = vulns.get(col, "")
                if val == "M":
                    row.append("<span style='color:orange;font-weight:bold'>M</span>")
                elif val == "L":
                    row.append("<span style='color:blue;font-weight:bold'>L</span>")
                else:
                    row.append("-")
            lines.append("| " + " | ".join(row) + " |")
        return "\n".join(lines)

    def to_csv(self) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Target Website"] + self.columns)
        for site, vulns in self.data.items():
            row = [site] + [vulns.get(col, "") for col in self.columns]
            writer.writerow(row)
        return output.getvalue()

    def to_json(self) -> str:
        return json.dumps(self.data, indent=2)
