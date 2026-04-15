param(
    [string]$Tests = "123",
    [string[]]$Domains = @(),
    [int]$Concurrency = 100,
    [string]$OutputFile = "",
    [string]$Proxy = ""
)

$ErrorActionPreference = "Stop"

$repoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$resultsDir = Join-Path $repoDir "results"

if (-not (Test-Path -LiteralPath $resultsDir)) {
    New-Item -ItemType Directory -Path $resultsDir | Out-Null
}

if ([string]::IsNullOrWhiteSpace($OutputFile)) {
    $stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $OutputFile = "dpi_report_$stamp.txt"
}

$dockerArgs = @(
    "run"
    "--rm"
    "-it"
    "--pull=always"
    "-v"; "${repoDir}/domains.txt:/app/domains.txt"
    "-v"; "${repoDir}/tcp16.json:/app/tcp16.json"
    "-v"; "${repoDir}/config.yml:/app/config.yml"
    "-v"; "${repoDir}/whitelist_sni.txt:/app/whitelist_sni.txt"
    "-v"; "${resultsDir}:/out"
    "ghcr.io/runnin4ik/dpi-detector:latest"
    "--batch"
    "-t"; $Tests
    "-c"; "$Concurrency"
    "-o"; "/out/$OutputFile"
)

foreach ($domain in $Domains) {
    $dockerArgs += @("-d", $domain)
}

if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
    $dockerArgs += @("-p", $Proxy)
}

Write-Host ""
Write-Host "Repo:    $repoDir"
Write-Host "Results: $resultsDir"
Write-Host "Report:  $(Join-Path $resultsDir $OutputFile)"
Write-Host ""

& docker @dockerArgs
