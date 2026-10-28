import json
from typing import Dict, Any, List
from vapt_framework.core.models import (
    Severity,
    VulnerabilityCategory,
    VulnerabilityFinding
)

class ZAPParser:
    """
    Parses OWASP ZAP alerts exported in JSON or dictionaries.
    """

    ALERT_TO_CATEGORY = {
        "CSP: Wildcard Directive": VulnerabilityCategory.CSP_WILDCARD,
        "CSP: style-src unsafe-inline": VulnerabilityCategory.CSP_STYLE_INLINE,
        "CSP: script-src unsafe-inline": VulnerabilityCategory.CSP_SCRIPT_INLINE,
        "X-Frame-Options Header Not Set": VulnerabilityCategory.X_FRAME_OPTIONS,
        "Absence of Anti-CSRF Tokens": VulnerabilityCategory.ABSENCE_CSRF,
        "Cross-Domain JavaScript Source File Inclusion": VulnerabilityCategory.CROSS_DOMAIN_JS,
        "Secure Pages Include Mixed Content": VulnerabilityCategory.MIXED_CONTENT,
        "Cookie Without SameSite Attribute": VulnerabilityCategory.COOKIE_SAMESITE,
        "Incomplete or No Cache-control and Pragma HTTP Header Set": VulnerabilityCategory.CACHE_CONTROL,
        "X-Content-Type-Options Header Missing": VulnerabilityCategory.X_CONTENT_TYPE,
    }

    @staticmethod
    def parse_alerts(alerts_data: List[Dict[str, Any]], target_id: str, target_url: str) -> List[VulnerabilityFinding]:
        findings = []
        for alert in alerts_data:
            name = alert.get("alert") or alert.get("name", "")
            cat = None
            for key, val in ZAPParser.ALERT_TO_CATEGORY.items():
                if key.lower() in name.lower():
                    cat = val
                    break

            if not cat:
                continue

            risk_str = alert.get("risk", "Low")
            try:
                severity = Severity(risk_str.capitalize())
            except Exception:
                severity = Severity.LOW

            f = VulnerabilityFinding(
                category=cat,
                title=name,
                severity=severity,
                target_id=target_id,
                target_url=target_url,
                cwe_id=int(alert.get("cweid", 0)) if alert.get("cweid") else None,
                wasc_id=int(alert.get("wascid", 0)) if alert.get("wascid") else None,
                description=alert.get("desc", ""),
                evidence=alert.get("evidence", ""),
                remediation=alert.get("solution", ""),
                parameter=alert.get("param", "")
            )
            findings.append(f)
        return findings
