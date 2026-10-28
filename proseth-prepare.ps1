<#
  Proseth - one installer for every Proseth service on a Windows server.

  It asks which product the customer uses NOW and switches that one on; every other
  product is installed READY - sending nothing, enrolled nowhere - so an engineer can
  switch it on later with one command and the collector's address, no internet needed.

  PowerShell as Administrator:
    iwr -UseBasicParsing <this file's raw URL> -OutFile $env:TEMP\proseth-prepare.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\proseth-prepare.ps1

  Without questions (all optional; anything missing is asked for):
    -Now aiops|agentic|both|none   -AgenticCollector IP -Group GROUP   -SkipWinRM
  Remove everything later:  -Uninstall

  What "ready" means:
    Proseth AIOps        nothing to install - its collector reads events over WinRM, so WinRM
                         is switched on (skip with -SkipWinRM if a policy manages it). It is
                         "on" once the server is added as an asset in AIOps.
    PSCyber Agentic SOC  the Wazuh agent installed STOPPED and DISABLED, pointed at nothing,
                         and its script kept in C:\Program Files\PSCyber.
  Switch Agentic on later:
    powershell -ExecutionPolicy Bypass -File "C:\Program Files\PSCyber\pscyber-agent.ps1" -Collector IP -Group GROUP

  This file is identical in the proseth-aiops-agent and pscyber-site-onboarding repositories.
#>
param(
    [ValidateSet('', 'aiops', 'agentic', 'both', 'none')][string]$Now = '',
    [string]$AgenticCollector,
    [string]$Group,
    [switch]$SkipWinRM,
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$AgenticUrl = 'https://raw.githubusercontent.com/prosethsolutionsAI/pscyber-site-onboarding/main/agents/install-agent-windows.ps1'
$Kept = Join-Path $env:ProgramFiles 'PSCyber\pscyber-agent.ps1'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host 'ERR run PowerShell as Administrator' -ForegroundColor Red; exit 1 }

if (-not $Now) {
    Write-Host 'Which Proseth product does this customer use NOW? (the others are installed ready, switched off)'
    Write-Host '  1) Proseth AIOps'; Write-Host '  2) PSCyber Agentic SOC'; Write-Host '  3) both'; Write-Host '  4) none yet - just get the server ready'
    $Now = @{ '1' = 'aiops'; '2' = 'agentic'; '3' = 'both'; '4' = 'none' }[(Read-Host '  Choose 1-4')]
    if (-not $Now) { Write-Host 'ERR choose 1, 2, 3 or 4' -ForegroundColor Red; exit 1 }
}
$agenticNow = $Now -in 'agentic', 'both'
if ($agenticNow) {
    if (-not $AgenticCollector) { $AgenticCollector = Read-Host '  PSCyber Agentic site collector IP' }
    if (-not $Group) { $Group = Read-Host '  PSCyber agent group (the customer''s Onboarding tab shows it)' }
}
$failed = @()

Write-Host "`n=== Proseth AIOps: getting ready"
if ($SkipWinRM) { Write-Host '  WinRM left as it is (-SkipWinRM) - the AIOps collector needs it on to read events' }
else {
    try { Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null; Write-Host ' ok WinRM is on' -ForegroundColor Green }
    catch { Write-Host "  could not switch WinRM on: $($_.Exception.Message)"; $failed += 'aiops' }
}

Write-Host "`n=== PSCyber Agentic SOC: getting ready"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $f = Join-Path $env:TEMP 'pscyber-agent.ps1'
    (New-Object Net.WebClient).DownloadFile($AgenticUrl, $f)
    & powershell -NoProfile -ExecutionPolicy Bypass -File $f -Prepare
    if ($LASTEXITCODE -ne 0) { $failed += 'agentic' }
    Remove-Item $f -ErrorAction SilentlyContinue
} catch { Write-Host "  $($_.Exception.Message)"; $failed += 'agentic' }

if ($agenticNow -and ($failed -notcontains 'agentic')) {
    Write-Host "`n=== PSCyber Agentic SOC: switching on"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $Kept -Collector $AgenticCollector -Group $Group
    if ($LASTEXITCODE -ne 0) { $failed += 'agentic-on' }
}
if ($Now -in 'aiops', 'both') {
    Write-Host "`n=== Proseth AIOps: switching on"
    Write-Host '  Nothing more on this server: add it as an asset in AIOps (Windows, behind the site''s AIOps collector).'
}

Write-Host "`n=== Switch on later (no internet needed)"
Write-Host '  Proseth AIOps     add this server as an asset in AIOps'
Write-Host "  PSCyber Agentic   powershell -ExecutionPolicy Bypass -File `"$Kept`" -Collector <PSCYBER_COLLECTOR_IP> -Group <GROUP>"
if ($failed.Count) { Write-Host "ERR something did not finish: $($failed -join ', ') - see the messages above, fix, and run this again" -ForegroundColor Red; exit 1 }
