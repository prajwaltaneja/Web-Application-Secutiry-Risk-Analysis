from vapt_framework.modules.header_auditor import HeaderAuditor
from vapt_framework.core.models import VulnerabilityCategory, Severity

def test_vulnerable_headers_and_html(vulnerable_headers, vulnerable_html):
    auditor = HeaderAuditor()
    cookies = ["session_id=abc12345; Path=/; Secure; HttpOnly"]
    findings = auditor.audit_response(
        target_url="https://test.crypto-exchange.org",
        target_id="test-exchange",
        headers=vulnerable_headers,
        raw_cookies=cookies,
        html_body=vulnerable_html
    )

    categories = {f.category for f in findings}

    assert VulnerabilityCategory.CSP_WILDCARD in categories
    assert VulnerabilityCategory.CSP_STYLE_INLINE in categories
    assert VulnerabilityCategory.CSP_SCRIPT_INLINE in categories
    assert VulnerabilityCategory.X_FRAME_OPTIONS in categories
    assert VulnerabilityCategory.ABSENCE_CSRF in categories
    assert VulnerabilityCategory.CROSS_DOMAIN_JS in categories
    assert VulnerabilityCategory.MIXED_CONTENT in categories
    assert VulnerabilityCategory.COOKIE_SAMESITE in categories
    assert VulnerabilityCategory.CACHE_CONTROL in categories
    assert VulnerabilityCategory.X_CONTENT_TYPE in categories

def test_secure_headers_clean():
    auditor = HeaderAuditor()
    headers = {
        "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-12345'; style-src 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "cache-control": "no-cache, no-store, must-revalidate",
        "pragma": "no-cache"
    }
    cookies = ["session=secret; SameSite=Strict; Secure; HttpOnly"]
    html = """<html><body>
    <form action="/login" method="POST">
        <input type="hidden" name="csrf_token" value="xyz987">
        <input type="text" name="user">
    </form>
    </body></html>"""

    findings = auditor.audit_response(
        target_url="https://secure.crypto.com",
        target_id="secure-crypto",
        headers=headers,
        raw_cookies=cookies,
        html_body=html
    )
    assert len(findings) == 0
