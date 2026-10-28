# ==============================================================================
# Phase 2: Vulnerability Detection Pipeline (PowerShell / Windows)
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
New-Item -ItemType Directory -Path (Join-Path $outDir "nikto") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $outDir "uniscan") -Force | Out-Null

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "[*] Launching Vulnerability Detection Pipeline (Windows Terminal)..." -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

foreach ($t in $targets) {
    $uri = [System.Uri]$t.Url
    $hostName = $uri.Host
    Write-Host "[+] Running Vulnerability Audits on: $hostName..." -ForegroundColor Yellow

    if (Get-Command nikto -ErrorAction SilentlyContinue) {
        Write-Host "  [>] Executing Nikto..." -ForegroundColor Gray
        $niktoOut = Join-Path $outDir "nikto\$hostName.nikto.txt"
        & nikto -h $t.Url | Out-File -FilePath $niktoOut -Encoding utf8
    }

    if (Get-Command uniscan -ErrorAction SilentlyContinue) {
        Write-Host "  [>] Executing Uniscan..." -ForegroundColor Gray
        $uniscanOut = Join-Path $outDir "uniscan\$hostName.uniscan.txt"
        & uniscan -u $t.Url | Out-File -FilePath $uniscanOut -Encoding utf8
    }
}

Write-Host "[*] Vulnerability scans complete. Saved to $outDir." -ForegroundColor Green
