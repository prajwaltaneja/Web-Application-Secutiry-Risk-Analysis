from vapt_framework.parsers.nmap_parser import NmapParser
from vapt_framework.parsers.nikto_parser import NiktoParser
from vapt_framework.parsers.whatweb_parser import WhatWebParser
from vapt_framework.parsers.zap_parser import ZAPParser
from vapt_framework.core.models import VulnerabilityCategory

def test_nmap_parser():
    raw_nmap = """Nmap scan report for 104.18.93.71
Host is up (0.021s latency).
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Cloudflare http proxy
|_http-csrf: Couldn't find any CSRF vulnerabilities.
443/tcp  open  ssl/http Cloudflare http proxy
Running (JUST GUESSING): Oracle VirtualBox (96%)
"""
    parsed = NmapParser.parse_text(raw_nmap)
    assert parsed["target_ip"] == "104.18.93.71"
    assert parsed["host_status"] == "up"
    assert len(parsed["ports"]) == 2
    assert parsed["ports"][0]["port"] == "80/tcp"
    assert "Oracle VirtualBox" in parsed["os_detection"]

def test_nikto_parser():
    raw_nikto = """+ Target IP:          104.26.12.129
+ Target Hostname:    atomicwallet.io
+ Target Port:        443
+ Server: cloudflare
+ The X-Content-Type-Options header is not set.
"""
    parsed = NiktoParser.parse_text(raw_nikto)
    assert parsed["target_ip"] == "104.26.12.129"
    assert parsed["target_hostname"] == "atomicwallet.io"
    assert parsed["target_port"] == 443
    assert parsed["server_banner"] == "cloudflare"
    assert len(parsed["vulnerabilities"]) == 1

def test_whatweb_parser():
    raw_whatweb = """WhatWeb report for https://exchange.blockchain.com
Status    : 200 OK
IP        : 104.18.93.71
Summary   : Script[application/json], HTML5, HTTPServer[Tengine], X-Frame-Options[SAMEORIGIN]
"""
    parsed = WhatWebParser.parse_text(raw_whatweb)
    assert parsed["target_url"] == "https://exchange.blockchain.com"
    assert parsed["ip"] == "104.18.93.71"
    assert parsed["plugins"]["Tengine"] is True
    assert parsed["plugins"]["HTML5"] is True

def test_zap_parser():
    alerts = [
        {
            "alert": "CSP: Wildcard Directive",
            "risk": "Medium",
            "cweid": 16,
            "wascid": 15,
            "evidence": "default-src *"
        },
        {
            "alert": "X-Frame-Options Header Not Set",
            "risk": "Medium",
            "cweid": 16,
            "wascid": 15
        }
    ]
    findings = ZAPParser.parse_alerts(alerts, "target-id", "https://target.com")
    assert len(findings) == 2
    assert findings[0].category == VulnerabilityCategory.CSP_WILDCARD
    assert findings[1].category == VulnerabilityCategory.X_FRAME_OPTIONS
