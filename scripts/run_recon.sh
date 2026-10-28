#!/bin/bash
# ==============================================================================
# Phase 1: Information Gathering & Reconnaissance Script
# Cyber Security Risk Analysis in Web Applications - MSIT B.Tech Major Project
# Authors: Prajwal Taneja, Priyam Gautam, Ambar Hajela
# Mentor: Dr. Priyanka Nandal (MSIT CSE)
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
mkdir -p "$OUT_DIR/nmap" "$OUT_DIR/whatweb"

echo "================================================================================"
echo "[*] Launching Automated Reconnaissance Pipeline..."
echo "================================================================================"

for entry in "${TARGETS[@]}"; do
    URL="${entry%%:*}"
    IP="${entry##*:}"
    HOST=$(echo "$URL" | awk -F[/:] '{print $4}')
    echo "[+] Scanning Target: $HOST ($IP)..."

    # WhatWeb Fingerprint
    if command -v whatweb &>/dev/null; then
        echo "  [>] Running WhatWeb..."
        whatweb -v "$URL" > "$OUT_DIR/whatweb/${HOST}.whatweb.txt" 2>&1 || true
    fi

    # Nmap Service & Port Discovery
    if command -v nmap &>/dev/null; then
        echo "  [>] Running Nmap Service Discovery..."
        nmap -sV -Pn -p 80,443,8080,8443 "$IP" > "$OUT_DIR/nmap/${IP}.nmap.txt" 2>&1 || true
    fi
done

echo "[*] Reconnaissance complete. Results archived in $OUT_DIR."
