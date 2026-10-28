from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class PlatformType(str, Enum):
    EXCHANGE = "exchange"
    WALLET = "wallet"


class ArchitectureType(str, Enum):
    WEB2 = "Web 2.0"
    WEB3 = "Web 3.0"


class VulnerabilityCategory(str, Enum):
    CSP_WILDCARD = "CSP: wildcard directive"
    CSP_STYLE_INLINE = "CSP: style-src unsafe inline"
    CSP_SCRIPT_INLINE = "CSP: script-src unsafe inline"
    X_FRAME_OPTIONS = "X-frame options header not set"
    ABSENCE_CSRF = "Absence of anti CSRF tokens"
    CROSS_DOMAIN_JS = "Cross domain JavaScript source file inclusion"
    MIXED_CONTENT = "Secure pages include mixed content"
    COOKIE_SAMESITE = "Cookie without same site attribute"
    CACHE_CONTROL = "Incomplete or no cache control"
    X_CONTENT_TYPE = "X-content type option header missing"


class AttackType(str, Enum):
    XSS = "XSS attack"
    XSSI = "XSSI attack"
    DATA_INJECTION = "Data Injection Attack"
    CLICKJACKING = "Clickjacking Attack"
    CSRF = "CSRF Attack"
    MITM = "Man-In-The-Middle Attack"
    TIMING = "Timing Attack"
    CACHE_POISONING = "Cache Poisoning Software Attack"
    FILE_INCLUSION = "File Inclusion Attack"
    MIME_SNIFFING = "MIME Sniffing Attack"


@dataclass
class Target:
    id: str
    name: str
    url: str
    type: PlatformType
    architecture: ArchitectureType
    ip_addresses: List[str] = field(default_factory=list)
    cdn_waf: str = ""
    web_server: str = ""
    notes: str = ""
    in_scope: bool = True
    tested_modules: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityFinding:
    category: VulnerabilityCategory
    title: str
    severity: Severity
    target_id: str
    target_url: str
    cwe_id: Optional[int] = None
    wasc_id: Optional[int] = None
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    parameter: Optional[str] = None


@dataclass
class ScanReport:
    target: Target
    timestamp: str
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    server_banner: str = ""
    waf_detected: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    raw_artifacts: Dict[str, str] = field(default_factory=dict)
