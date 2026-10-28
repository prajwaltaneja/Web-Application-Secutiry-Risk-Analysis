| Attack Vector | CSP Wildcard Directive | CSP: style-src unsafe inline | CSP: script-src unsafe inline | X-frame option header not set | Absence of Anti-CSRF Tokens | Cross-domain JavaScript source file inclusion | Secure pages include mixed content | Cookie without same site attribute | Incomplete or no cache control | X-content type option header missing |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **XSS attack** | [X] | [X] | [X] | - | - | - | - | - | - | [X] |
| **XSSI attack** | - | - | - | - | - | [X] | - | [X] | - | - |
| **Data Injection Attack** | [X] | - | - | - | - | - | - | - | - | - |
| **Clickjacking Attack** | - | - | - | [X] | - | - | - | - | - | - |
| **CSRF Attack** | - | - | - | - | [X] | - | - | [X] | - | - |
| **Man-In-The-Middle Attack** | - | - | - | - | - | - | [X] | - | - | - |
| **Timing Attack** | - | - | - | - | - | - | - | [X] | - | - |
| **Cache Poisoning Software Attack** | - | - | - | - | - | - | - | - | [X] | - |
| **File Inclusion Attack** | - | - | - | - | - | [X] | - | - | - | - |
| **MIME Sniffing Attack** | - | - | - | - | - | - | - | - | - | [X] |