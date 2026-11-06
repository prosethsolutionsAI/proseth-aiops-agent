<#
  Proseth AIOps - prepare a Windows server for monitoring. No agent: the AIOps
  collector reads CPU, memory, disks, services and the Event Log over WinRM.

  PowerShell as Administrator, ON the server to monitor (the AIOps asset's Edit
  dialog gives this line with the values filled in):

    [Net.ServicePointManager]::SecurityProtocol='Tls12'; & ([scriptblock]::Create((iwr -UseBasicParsing <this file's raw URL>).Content)) -Collector 192.0.2.10 -User administrator -AssetIP 192.0.2.20

  -Collector IP   the AIOps collector's LAN IP (WinRM is opened to it only)
  -User NAME      the login set on the asset in AIOps
  -AssetIP IP     this server's address in AIOps - the script refuses to run on any
                  machine that does not own it (pasting it on the wrong server, e.g.
                  your own, would otherwise lock that server's WinRM down)
  -Port N         WinRM port (default 5985)
  -NoLimit        leave who may connect to WinRM as it is (no collector-only rule)

  Safe to run again: a second run changes nothing. Nothing is downloaded or installed.
#>
param(
    [string]$Collector,
    [string]$User = 'administrator',
    [string]$AssetIP,
    [int]$Port = 5985,
    [switch]$NoLimit
)
& {
$ErrorActionPreference = 'Stop'
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host 'ERR open PowerShell as Administrator and run it again' -ForegroundColor Red; return }
if (-not $NoLimit -and -not $Collector) { Write-Host 'ERR give -Collector <collector LAN IP> (or -NoLimit)' -ForegroundColor Red; return }
$mine = @(Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress })
if ($AssetIP -and ($mine -notcontains $AssetIP)) {
    Write-Host "ERR this is $env:COMPUTERNAME ($($mine -join ', ')), not the asset at $AssetIP - nothing changed. Run it ON that server." -ForegroundColor Red; return }

try {
    Write-Host "`n=== 1. WinRM on ($env:COMPUTERNAME)"
    # Enable-PSRemoting RESTARTS WinRM even when it is already on - which kills the
    # session this runs in when it was started over WinRM (or by a deployment tool).
    # So it is called only when WinRM is not already answering with a listener.
    $svc = Get-Service WinRM
    $listening = $false
    if ($svc.Status -eq 'Running') {
        try { $listening = [bool](Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop |
                Where-Object { $_.Keys -contains 'Transport=HTTP' -or $_.Keys -contains 'Transport=HTTPS' }) } catch {} }
    if ($listening) { Write-Host '  WinRM already on - left running (not restarted)' }
    else { Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null }
    if ($svc.StartType -ne 'Automatic') { Set-Service WinRM -StartupType Automatic }
    if ((Get-Service WinRM).Status -ne 'Running') { Start-Service WinRM }
    Write-Host ' ok WinRM running, starts at boot' -ForegroundColor Green

    Write-Host "`n=== 2. Firewall"
    $rules = Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -ErrorAction SilentlyContinue
    if (-not $rules) {
        New-NetFirewallRule -Name 'WINRM-HTTP-In-TCP' -DisplayName 'Windows Remote Management (HTTP-In)' -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Any | Out-Null
        $rules = Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*'
    }
    if ($NoLimit) { $rules | Set-NetFirewallRule -Enabled True; Write-Host ' ok WinRM rule enabled (who may connect left as it was)' -ForegroundColor Green }
    else { $rules | Set-NetFirewallRule -RemoteAddress $Collector -Enabled True; Write-Host " ok WinRM ($Port) allowed from $Collector only" -ForegroundColor Green }

    Write-Host "`n=== 3. Rights for $User"
    $short = ($User -split '\\')[-1]
    $isAdmin = $false
    try { $isAdmin = [bool](Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Where-Object { $_.Name -match "(^|\\)$([regex]::Escape($short))$" }) } catch {}
    if ($isAdmin) {
        Write-Host " ok $User is an administrator" -ForegroundColor Green
        # A LOCAL admin other than the built-in Administrator is filtered by UAC over the network.
        if ($User -notmatch '\\|@' -and $User -ne 'administrator') {
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord
            Write-Host ' ok local admin may act as admin over WinRM' -ForegroundColor Green }
    } else {
        foreach ($g in 'Remote Management Users', 'Event Log Readers', 'Performance Monitor Users') {
            try { Add-LocalGroupMember -Group $g -Member $User -ErrorAction Stop; Write-Host " ok added to $g" -ForegroundColor Green }
            catch { if ($_.Exception.Message -match 'already a member') { Write-Host "  already in $g" } else { throw } } }
    }

    Write-Host "`n=== 4. Check"
    Test-WSMan -ComputerName localhost | Out-Null
    if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) { Write-Host " ok WinRM answers on $Port" -ForegroundColor Green }
    else { Write-Host "ERR nothing listening on $Port" -ForegroundColor Red; return }
    Write-Host "`nDONE. In AIOps press 'now' on this server's Windows health check." -ForegroundColor Cyan
}
catch { Write-Host "ERR $($_.Exception.Message)" -ForegroundColor Red }
}
