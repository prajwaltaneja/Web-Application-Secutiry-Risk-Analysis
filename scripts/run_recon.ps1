# ==============================================================================
# Phase 1: Information Gathering & Reconnaissance Script (PowerShell / Windows)
# Cyber Security Risk Analysis in Web Applications - MSIT B.Tech Major Project
# ==============================================================================

$ErrorActionPreference = "Continue"

$targets = @(
    @{ Url = "https://exchange.blockchain.com"; Ip = "104.18.93.71" },
    @{ Url = "https://www.binance.com/en";       Ip = "18.66.78.94" },
    @{ Url = "https://crypto.com";               Ip = "104.18.112.50" },
    @{ Url = "https://m.kucoin.com";             Ip = "13.225.103.45" },
    @{ Url = "https://coincheck.com";            Ip = "13.249.98.23" },
    @{ Url = "https://wazirx.com";               Ip = "104.18.14.88" },
    @{ Url = "https://exchange.bitcoin.com";     Ip = "104.18.22.44" },
    @{ Url = "https://poly.network";             Ip = "172.67.142.10" },
    @{ Url = "https://etherium.com";             Ip = "104.21.32.14" },
    @{ Url = "https://www.blockchain.com/wallet"; Ip = "104.16.40.77" },
    @{ Url = "https://wallet.bitcoin.com";       Ip = "104.18.22.44" },
    @{ Url = "https://atomicwallet.io";          Ip = "104.26.12.129" }
)

$outDir = Join-Path $PSScriptRoot "..\reports\raw"
New-Item -ItemType Directory -Path (Join-Path $outDir "nmap") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $outDir "whatweb") -Force | Out-Null

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "[*] Launching Automated Reconnaissance Pipeline (Windows Terminal)..." -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

foreach ($t in $targets) {
    $uri = [System.Uri]$t.Url
    $hostName = $uri.Host
    Write-Host "[+] Scanning Target: $hostName ($($t.Ip))..." -ForegroundColor Yellow

    # Nmap Service & Port Discovery
    if (Get-Command nmap -ErrorAction SilentlyContinue) {
        Write-Host "  [>] Running Nmap Service Discovery..." -ForegroundColor Gray
        $nmapOut = Join-Path $outDir "nmap\$($t.Ip).nmap.txt"
        & nmap -sV -Pn -p 80,443,8080,8443 $t.Ip | Out-File -FilePath $nmapOut -Encoding utf8
    }

    # WhatWeb Fingerprint
    if (Get-Command whatweb -ErrorAction SilentlyContinue) {
        Write-Host "  [>] Running WhatWeb..." -ForegroundColor Gray
        $whatwebOut = Join-Path $outDir "whatweb\$hostName.whatweb.txt"
        & whatweb -v $t.Url | Out-File -FilePath $whatwebOut -Encoding utf8
    }
}

Write-Host "[*] Reconnaissance complete. Output saved to $outDir." -ForegroundColor Green
