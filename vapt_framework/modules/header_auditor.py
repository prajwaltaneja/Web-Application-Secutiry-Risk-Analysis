import re
import urllib.request
import urllib.parse
from html.parser import HTMLParser
from typing import List, Dict, Tuple, Optional, Any
from urllib.error import URLError, HTTPError

from vapt_framework.core.models import (
    Severity,
    VulnerabilityCategory,
    VulnerabilityFinding
)


class SimpleHTMLInspector(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.parsed_base = urllib.parse.urlparse(base_url)
        self.forms: List[Dict[str, Any]] = []
        self.external_scripts: List[str] = []
        self.mixed_content_resources: List[str] = []
        self.current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag.lower() == "form":
            self.current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "GET").upper(),
                "inputs": [],
                "has_csrf": False
            }
            self.forms.append(self.current_form)

        elif tag.lower() == "input" and self.current_form:
            input_name = attr_dict.get("name", "").lower()
            input_type = attr_dict.get("type", "text").lower()
            self.current_form["inputs"].append({"name": input_name, "type": input_type})
            csrf_markers = ["csrf", "xsrf", "token", "authenticity_token", "_token", "nonce"]
            if any(marker in input_name for marker in csrf_markers):
                self.current_form["has_csrf"] = True

        elif tag.lower() == "script":
            src = attr_dict.get("src", "")
            if src:
                parsed_src = urllib.parse.urlparse(src)
                if parsed_src.netloc and parsed_src.netloc != self.parsed_base.netloc:
                    self.external_scripts.append(src)
                if self.parsed_base.scheme == "https" and parsed_src.scheme == "http":
                    self.mixed_content_resources.append(src)

        elif tag.lower() in ["img", "iframe", "link", "audio", "video", "source"]:
            src = attr_dict.get("src") or attr_dict.get("href") or ""
            if self.parsed_base.scheme == "https" and src.startswith("http://"):
                self.mixed_content_resources.append(src)

    def handle_endtag(self, tag: str):
        if tag.lower() == "form":
            self.current_form = None


class HeaderAuditor:
    """
    Auditor for security headers, cookies, and client-side web protections.
    Directly evaluates the 10 core vulnerability classes investigated in the study.
    """

    def __init__(self, user_agent: str = "VAPT-Audit-Bot/1.0 (Academic Security Research; MSIT)"):
        self.user_agent = user_agent

    def audit_target(self, target_url: str, target_id: str = "target", timeout: int = 10) -> List[VulnerabilityFinding]:
        headers: Dict[str, str] = {}
        cookies: List[str] = []
        body: str = ""

        try:
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": self.user_agent}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                # In standard urllib, multiple Set-Cookie headers may be combined or in get_all
                if hasattr(resp.headers, "get_all"):
                    cookies = resp.headers.get_all("Set-Cookie") or []
                elif "set-cookie" in headers:
                    cookies = [headers["set-cookie"]]
                try:
                    body = resp.read().decode("utf-8", errors="ignore")
                except Exception:
                    body = ""
        except (URLError, HTTPError) as e:
            # Handle error gracefully or extract headers if available
            if hasattr(e, "headers") and e.headers:
                headers = {k.lower(): v for k, v in e.headers.items()}
                if hasattr(e.headers, "get_all"):
                    cookies = e.headers.get_all("Set-Cookie") or []
                elif "set-cookie" in headers:
                    cookies = [headers["set-cookie"]]

        return self.audit_response(
            target_url=target_url,
            target_id=target_id,
            headers=headers,
            raw_cookies=cookies,
            html_body=body
        )

    def audit_response(
        self,
        target_url: str,
        target_id: str,
        headers: Dict[str, str],
        raw_cookies: List[str],
        html_body: str = ""
    ) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        h = {k.lower(): v for k, v in headers.items()}
        csp = h.get("content-security-policy", "")

        # 1. CSP: wildcard directive
        if csp:
            if re.search(r"(default-src|script-src|connect-src|object-src)[^;]*\*", csp, re.IGNORECASE):
                evidence = self._extract_matching_csp_directive(csp, r"(default-src|script-src|connect-src|object-src)[^;]*\*")
                findings.append(VulnerabilityFinding(
                    category=VulnerabilityCategory.CSP_WILDCARD,
                    title="Content Security Policy (CSP): Wildcard Directive In Use",
                    severity=Severity.MEDIUM,
                    target_id=target_id,
                    target_url=target_url,
                    cwe_id=16,
                    wasc_id=15,
                    description="The Content-Security-Policy header contains wildcard '*' directives, allowing data injection or loading scripts/resources from arbitrary origins.",
                    evidence=evidence or csp[:200],
                    remediation="Replace wildcard '*' with explicitly whitelisted trusted domains or nonces/hashes in Content-Security-Policy directives."
                ))

        # 2. CSP: style-src unsafe inline
        if csp:
            if re.search(r"(style-src)[^;]*'unsafe-inline'", csp, re.IGNORECASE):
                evidence = self._extract_matching_csp_directive(csp, r"style-src[^;]*'unsafe-inline'")
                findings.append(VulnerabilityFinding(
                    category=VulnerabilityCategory.CSP_STYLE_INLINE,
                    title="Content Security Policy (CSP): style-src 'unsafe-inline' Detected",
                    severity=Severity.MEDIUM,
                    target_id=target_id,
                    target_url=target_url,
                    cwe_id=16,
                    wasc_id=15,
                    description="'unsafe-inline' inside style-src allows injection of arbitrary inline CSS, enabling DOM manipulation, CSS-based keylogging, and sensitive data exfiltration.",
                    evidence=evidence or "style-src ... 'unsafe-inline'",
                    remediation="Eliminate 'unsafe-inline' from style-src. Utilize cryptographic nonces (nonce-...) or SHA-256 hashes for legitimate inline styles."
                ))

        # 3. CSP: script-src unsafe inline
        if csp:
            if re.search(r"(script-src|default-src)[^;]*'unsafe-inline'", csp, re.IGNORECASE):
                evidence = self._extract_matching_csp_directive(csp, r"(script-src|default-src)[^;]*'unsafe-inline'")
                findings.append(VulnerabilityFinding(
                    category=VulnerabilityCategory.CSP_SCRIPT_INLINE,
                    title="Content Security Policy (CSP): script-src 'unsafe-inline' Detected",
                    severity=Severity.MEDIUM,
                    target_id=target_id,
                    target_url=target_url,
                    cwe_id=16,
                    wasc_id=15,
                    description="'unsafe-inline' within script-src severely diminishes XSS defense, allowing attacker-supplied inline JavaScript payloads to execute within the victim's session.",
                    evidence=evidence or "script-src ... 'unsafe-inline'",
                    remediation="Remove 'unsafe-inline' from script-src. Refactor inline JavaScript into external files and adopt CSP3 strict nonce-based or hash-based policies."
                ))

        # 4. X-frame options header not set
        xfo = h.get("x-frame-options", "").strip().upper()
        csp_frame_ancestors = "frame-ancestors" in csp.lower()
        if not xfo and not csp_frame_ancestors:
            findings.append(VulnerabilityFinding(
                category=VulnerabilityCategory.X_FRAME_OPTIONS,
                title="Missing X-Frame-Options Header (Clickjacking Vulnerability)",
                severity=Severity.MEDIUM,
                target_id=target_id,
                target_url=target_url,
                cwe_id=16,
                wasc_id=15,
                description="The HTTP response does not specify X-Frame-Options or CSP frame-ancestors, permitting malicious sites to embed this page in transparent frames and conduct clickjacking attacks.",
                evidence="X-Frame-Options header not present in HTTP response.",
                remediation="Configure the web server to send 'X-Frame-Options: SAMEORIGIN' or 'X-Frame-Options: DENY', and define 'frame-ancestors 'self'' in CSP."
            ))

        # Inspect HTML body if available
        html_inspector = SimpleHTMLInspector(target_url)
        if html_body:
            try:
                html_inspector.feed(html_body)
            except Exception:
                pass

        # 5. Absence of anti CSRF tokens
        unprotected_forms = [f for f in html_inspector.forms if f.get("method") == "POST" and not f.get("has_csrf")]
        if unprotected_forms:
            evidence_form = str(unprotected_forms[0]["action"])
            findings.append(VulnerabilityFinding(
                category=VulnerabilityCategory.ABSENCE_CSRF,
                title="Absence of Anti-CSRF Tokens in Form Submissions",
                severity=Severity.LOW,
                target_id=target_id,
                target_url=target_url,
                cwe_id=352,
                wasc_id=9,
                description="State-changing HTML forms lack unique, unpredictable anti-CSRF challenge tokens, leaving users susceptible to Cross-Site Request Forgery.",
                evidence=f"Unprotected POST form targeting '{evidence_form}'",
                remediation="Embed cryptographic anti-CSRF synchronizer tokens in all state-changing HTML forms and enforce server-side validation."
            ))

        # 6. Cross domain JavaScript source file inclusion
        if html_inspector.external_scripts:
            findings.append(VulnerabilityFinding(
                category=VulnerabilityCategory.CROSS_DOMAIN_JS,
                title="Cross-Domain JavaScript Source File Inclusion",
                severity=Severity.LOW,
                target_id=target_id,
                target_url=target_url,
                cwe_id=829,
                wasc_id=15,
                description="The web page imports executable JavaScript from third-party domains. If an external host is compromised or modified, malicious payloads execute in this application's security context.",
                evidence=f"External script sources: {', '.join(html_inspector.external_scripts[:3])}",
                remediation="Host JavaScript libraries locally or enforce Subresource Integrity (SRI) attributes (e.g., integrity='sha384-...') on external script tags."
            ))

        # 7. Secure pages include mixed content
        if html_inspector.mixed_content_resources:
            findings.append(VulnerabilityFinding(
                category=VulnerabilityCategory.MIXED_CONTENT,
                title="Secure Page Includes Mixed Active/Passive HTTP Content",
                severity=Severity.MEDIUM,
                target_id=target_id,
                target_url=target_url,
                cwe_id=311,
                wasc_id=15,
                description="An HTTPS page fetches subordinate resources via unencrypted HTTP. Active network adversaries can tamper with or sniff unencrypted resources.",
                evidence=f"Insecure resources: {', '.join(html_inspector.mixed_content_resources[:3])}",
                remediation="Upgrade all resource URLs to HTTPS or deploy Content-Security-Policy: upgrade-insecure-requests."
            ))

        # 8. Cookie without same site attribute
        cookies_without_samesite = []
        for cookie_str in raw_cookies:
            if "samesite" not in cookie_str.lower():
                cookies_without_samesite.append(cookie_str.split(";")[0])

        if cookies_without_samesite:
            findings.append(VulnerabilityFinding(
                category=VulnerabilityCategory.COOKIE_SAMESITE,
                title="Cookie Without SameSite Attribute",
                severity=Severity.LOW,
                target_id=target_id,
                target_url=target_url,
                cwe_id=16,
                wasc_id=13,
                description="Sensitive session cookies lack the SameSite attribute, causing them to be sent along with cross-site requests and increasing CSRF and timing attack susceptibility.",
                evidence=f"Cookies missing SameSite: {', '.join(cookies_without_samesite[:3])}",
                remediation="Configure application cookies with 'SameSite=Lax' or 'SameSite=Strict' alongside 'Secure' and 'HttpOnly' flags."
            ))

        # 9. Incomplete or no cache control
        cache_control = h.get("cache-control", "").lower()
        pragma = h.get("pragma", "").lower()
        has_secure_cache = ("no-store" in cache_control or "no-cache" in cache_control) and ("no-cache" in pragma or "no-store" in cache_control)
        if not has_secure_cache:
            findings.append(VulnerabilityFinding(
                category=VulnerabilityCategory.CACHE_CONTROL,
                title="Incomplete or No Cache-Control and Pragma HTTP Headers",
                severity=Severity.LOW,
                target_id=target_id,
                target_url=target_url,
                cwe_id=525,
                wasc_id=13,
                description="The response lacks comprehensive caching restrictions, allowing shared proxies or local browsers to cache sensitive financial/session data.",
                evidence=f"Cache-Control: '{cache_control or 'NONE'}', Pragma: '{pragma or 'NONE'}'",
                remediation="Ensure sensitive HTTP responses include 'Cache-Control: no-cache, no-store, must-revalidate' and 'Pragma: no-cache'."
            ))

        # 10. X-content type option header missing
        x_content_type = h.get("x-content-type-options", "").strip().lower()
        if x_content_type != "nosniff":
            findings.append(VulnerabilityFinding(
                category=VulnerabilityCategory.X_CONTENT_TYPE,
                title="Anti-MIME-Sniffing Header Missing (X-Content-Type-Options)",
                severity=Severity.LOW,
                target_id=target_id,
                target_url=target_url,
                cwe_id=16,
                wasc_id=15,
                description="The X-Content-Type-Options: nosniff header is absent. Browsers may MIME-sniff response bodies into executable formats (e.g., treating text/plain as text/html).",
                evidence=f"X-Content-Type-Options: '{x_content_type or 'MISSING'}'",
                remediation="Add 'X-Content-Type-Options: nosniff' header to all HTTP responses."
            ))

        return findings

    def _extract_matching_csp_directive(self, csp: str, pattern: str) -> str:
        for directive in csp.split(";"):
            if re.search(pattern, directive.strip(), re.IGNORECASE):
                return directive.strip()
        return ""
