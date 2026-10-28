import pytest
from vapt_framework.core.models import Target, PlatformType, ArchitectureType

@pytest.fixture
def sample_target():
    return Target(
        id="test-exchange",
        name="Test Exchange",
        url="https://test.crypto-exchange.org",
        type=PlatformType.EXCHANGE,
        architecture=ArchitectureType.WEB3,
        ip_addresses=["104.18.93.71"],
        cdn_waf="Cloudflare"
    )

@pytest.fixture
def vulnerable_headers():
    return {
        "server": "cloudflare",
        "content-security-policy": "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' *; style-src 'self' 'unsafe-inline'",
        "cache-control": "public, max-age=3600",
        "pragma": ""
    }

@pytest.fixture
def secure_headers():
    return {
        "server": "cloudflare",
        "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-rAnd0m'; style-src 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "cache-control": "no-cache, no-store, must-revalidate",
        "pragma": "no-cache",
        "strict-transport-security": "max-age=31536000; includeSubDomains"
    }

@pytest.fixture
def vulnerable_html():
    return """<!DOCTYPE html>
<html>
<head>
    <title>Crypto Exchange Portal</title>
    <script src="https://cdn.thirdparty-analytics.com/tracker.js"></script>
    <script src="http://insecure-cdn.com/legacy.js"></script>
</head>
<body>
    <form action="/api/v1/transfer" method="POST">
        <input type="text" name="recipient" value="0x123">
        <input type="number" name="amount" value="10">
        <button type="submit">Transfer Funds</button>
    </form>
</body>
</html>
"""
