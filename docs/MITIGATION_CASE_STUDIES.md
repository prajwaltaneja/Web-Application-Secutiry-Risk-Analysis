# Mitigation Case Studies: Post-Breach Defenses in Exchanges

## Abstract

A core empirical contribution of our B.Tech study was examining how major cryptocurrency platforms updated their defensive architecture following historic cyber attacks. Specifically, we analyzed post-incident architectural changes implemented by **KuCoin** (`m.kucoin.com`) and **Coincheck** (`coincheck.com`).

---

## 1. KuCoin (`m.kucoin.com`) - September 2020 Breach Analysis

### Background
In September 2020, hackers infiltrated KuCoin's hot wallets, draining over \$281 million in Bitcoin, Ethereum, and ERC-20 tokens. The root cause was an internal system compromise where attackers obtained private keys to hot wallet servers.

### Post-Breach Architectural Adaptations
During our vulnerability assessment:
- **Server Banner Obscuration**: Inspection of HTTP response headers revealed that the server banner was deliberately modified from default `nginx` to:
  ```http
  Server: IAS/1.4.2.3-1.17.3
  ```
- **Layer 7 Web Application Firewall (WAF)**: Deployment of proprietary/enterprise WAF layers that intercept and filter malicious HTTP traffic before reaching upstream application servers.
- **Reverse Proxying & Address Hiding**: Upstream IP addresses are entirely concealed behind distributed proxy edges, preventing direct network scanning or DDoS exploitation.

---

## 2. Coincheck (`coincheck.com`) - January 2018 Breach Analysis

### Background
In January 2018, Japanese exchange Coincheck suffered a \$534 million NEM token theft. The attack originated from phishing malware targeting employee workstations, which allowed external lateral movement into internal wallet infrastructure.

### Post-Breach Architectural Adaptations
During our assessment:
- **AWS CloudFront Edge Protection**: Migration of all public exchange routing behind Amazon CloudFront and specialized WAF rulesets.
- **Strict Transport Security Enforcement**: HSTS headers configured with long maximum ages and subresource isolation.
- **Segregation of Wallets and Web Tiers**: Total operational separation between client-facing web application endpoints and backend signing infrastructure.

---

## Architectural Synthesis: Defense-in-Depth

The empirical findings from both platforms demonstrate that modern cryptocurrency security relies on a multi-tiered defense-in-depth model:

1. **Protocol Layer**: Multi-signature cold storage and threshold cryptography.
2. **Network Layer**: CDN edge scrubbing, private VPC peering, and IP concealing.
3. **Application Layer**: Strict CSP rules, SameSite cookie protection, Anti-CSRF challenge validation, and Anti-MIME sniffing.
