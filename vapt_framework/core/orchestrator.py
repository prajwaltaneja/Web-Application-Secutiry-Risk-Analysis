import os
from datetime import datetime
from typing import List, Dict, Any, Optional

from vapt_framework.core.models import Target, ScanReport, VulnerabilityFinding
from vapt_framework.core.config import load_targets
from vapt_framework.modules.header_auditor import HeaderAuditor
from vapt_framework.modules.nmap_scanner import NmapScanner
from vapt_framework.modules.nikto_scanner import NiktoScanner
from vapt_framework.modules.whatweb_scanner import WhatWebScanner
from vapt_framework.modules.zap_scanner import ZAPScanner
from vapt_framework.modules.sqlmap_scanner import SQLMapScanner
from vapt_framework.parsers.nmap_parser import NmapParser
from vapt_framework.parsers.nikto_parser import NiktoParser
from vapt_framework.parsers.whatweb_parser import WhatWebParser
from vapt_framework.parsers.zap_parser import ZAPParser


class VAPTOrchestrator:
    """
    Coordinates the 9-Step VAPT Object Cycle across target cryptocurrency web applications.
    Integrates network reconnaissance, web server auditing, client-side policy evaluation,
    and WAF/injection resistance testing.
    """

    def __init__(self, raw_reports_base: Optional[str] = None):
        self.raw_reports_base = raw_reports_base or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "reports", "raw")
        )
        self.header_auditor = HeaderAuditor()
        self.nmap_scanner = NmapScanner(os.path.join(self.raw_reports_base, "nmap"))
        self.nikto_scanner = NiktoScanner(os.path.join(self.raw_reports_base, "nikto"))
        self.whatweb_scanner = WhatWebScanner(os.path.join(self.raw_reports_base, "whatweb"))
        self.zap_scanner = ZAPScanner(os.path.join(self.raw_reports_base, "zap"))
        self.sqlmap_scanner = SQLMapScanner(os.path.join(self.raw_reports_base, "sqlmap"))

    def audit_target(self, target: Target, run_live: bool = False) -> ScanReport:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        findings: List[VulnerabilityFinding] = []

        # 1. Header & Client-Side Policy Audit
        if run_live:
            header_findings = self.header_auditor.audit_target(target.url, target_id=target.id)
            findings.extend(header_findings)

        # 2. OWASP ZAP Alerts
        zap_alerts = self.zap_scanner.get_alerts(target.url)
        if zap_alerts:
            zap_findings = ZAPParser.parse_alerts(zap_alerts, target_id=target.id, target_url=target.url)
            findings.extend(zap_findings)

        # 3. Nmap Reconnaissance
        nmap_out = {}
        target_ip = target.ip_addresses[0] if target.ip_addresses else target.url
        nmap_res = self.nmap_scanner.scan_host(target_ip)
        if "stdout" in nmap_res:
            nmap_out = NmapParser.parse_text(nmap_res["stdout"])

        # 4. Nikto Web Server Inspection
        nikto_res = self.nikto_scanner.scan_target(target.url)
        nikto_out = {}
        if "stdout" in nikto_res:
            nikto_out = NiktoParser.parse_text(nikto_res["stdout"])

        # 5. WhatWeb Fingerprint
        whatweb_res = self.whatweb_scanner.fingerprint_target(target.url)
        whatweb_out = {}
        if "stdout" in whatweb_res:
            whatweb_out = WhatWebParser.parse_text(whatweb_res["stdout"])

        # 6. SQLMap Injection & WAF Analysis
        sqlmap_res = self.sqlmap_scanner.probe_target(target.url)

        report = ScanReport(
            target=target,
            timestamp=timestamp,
            findings=findings,
            open_ports=nmap_out.get("ports", []),
            server_banner=nikto_out.get("server_banner") or target.cdn_waf,
            waf_detected=target.cdn_waf,
            technologies=list(whatweb_out.get("plugins", {}).keys()),
            raw_artifacts={
                "nmap": nmap_res.get("stdout", ""),
                "nikto": nikto_res.get("stdout", ""),
                "whatweb": whatweb_res.get("stdout", ""),
                "sqlmap": sqlmap_res.get("stdout", "")
            }
        )
        return report

    def run_all(self, run_live: bool = False) -> List[ScanReport]:
        targets = load_targets()
        reports = []
        for t in targets:
            report = self.audit_target(t, run_live=run_live)
            reports.append(report)
        return reports
