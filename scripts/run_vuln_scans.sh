#!/bin/bash
# ==============================================================================
# Phase 2: Vulnerability Detection Pipeline
# Nikto, Nmap NSE Scripts, Uniscan, and OWASP ZAP Automation
# ==============================================================================

set -euo pipefail

TARGETS=(
    "https://exchange.blockchain.com:104.18.93.71"
    "https://www.binance.com/en:18.66.78.94"
    "https://crypto.com:104.18.112.50"
    "https://m.kucoin.com:13.225.103.45"
    "https://coincheck.com:13.249.98.23"
    "https://wazirx.com:104.18.14.88"
    "https://exchange.bitcoin.com:104.18.22.44"
    "https://poly.network:172.67.142.10"
    "https://etherium.com:104.21.32.14"
    "https://www.blockchain.com/wallet:104.16.40.77"
    "https://wallet.bitcoin.com:104.18.22.44"
    "https://atomicwallet.io:104.26.12.129"
)

OUT_DIR="$(dirname "$0")/../reports/raw"
mkdir -p "$OUT_DIR/nikto" "$OUT_DIR/uniscan" "$OUT_DIR/nmap"

echo "================================================================================"
echo "[*] Launching Vulnerability Detection Pipeline..."
echo "================================================================================"

for entry in "${TARGETS[@]}"; do
    URL="${entry%%:*}"
    IP="${entry##*:}"
    HOST=$(echo "$URL" | awk -F[/:] '{print $4}')
    echo "[+] Running Vulnerability Audits on: $HOST..."

    # Nikto Web Server Vulnerability Scan
    if command -v nikto &>/dev/null; then
        echo "  [>] Executing Nikto Scan..."
        nikto -h "$URL" > "$OUT_DIR/nikto/${HOST}.nikto.txt" 2>&1 || true
    fi

    # Nmap NSE Script Scanning (CSRF, XSS, SSL/TLS Ciphers)
    if command -v nmap &>/dev/null; then
        echo "  [>] Executing Nmap NSE Vulnerability Scripts..."
        nmap -sV -Pn --script=vuln,http-csrf,http-dombased-xss,http-stored-xss,ssl-ccs-injection,sslv2-drown "$IP" \
            > "$OUT_DIR/nmap/${IP}.vuln.nmap.txt" 2>&1 || true
    fi

    # Uniscan Scanner
    if command -v uniscan &>/dev/null; then
        echo "  [>] Executing Uniscan Web Scanner..."
        uniscan -u "$URL" > "$OUT_DIR/uniscan/${HOST}.uniscan.txt" 2>&1 || true
    fi
done

echo "[*] Vulnerability scans complete. Raw reports saved to $OUT_DIR."
