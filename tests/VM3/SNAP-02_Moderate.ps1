#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ComplianceAI – VM3 (Windows 10) SNAP-02 Setup
    Target Risk Level : MODERATE
    Failing controls  : BKP-W10-01 (VSS / no shadow copies)
                        EP-W10-01  (Defender real-time OFF)

.DESCRIPTION
    Starts from the SNAP-01 baseline and deliberately weakens two
    low-to-medium-weight controls so the scoring engine lands in the
    Moderate band (compliance ~72–85 %, risk score ~20–38).

    Controls expected:
      FW-W10-01     PASS
      LOG-W10-01    PASS
      AC-W10-01     PASS
      AC-W10-02     PASS
      UPD-W10-01    PASS
      BKP-W10-01    FAIL  <-- VSS stopped, shadow copies deleted
      CRYPTO-W10-01 PASS
      EP-W10-01     FAIL  <-- Real-time protection disabled
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "=== ComplianceAI  VM3  SNAP-02 (Moderate Risk) ===" -ForegroundColor Cyan
Write-Host "    Starting from SNAP-01 baseline – applying deliberate weaknesses..."

# ── Keep all SNAP-01 hardening first ─────────────────────────────────────────

# Firewall ON
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

# EventLog ON
Set-Service -Name EventLog -StartupType Automatic
Start-Service -Name EventLog -ErrorAction SilentlyContinue

# Password complexity ON
$tmpCfg = "$env:TEMP\secpol_snap02.cfg"
secedit /export /cfg $tmpCfg /quiet
(Get-Content $tmpCfg) -replace 'PasswordComplexity\s*=\s*\d', 'PasswordComplexity = 1' |
    Set-Content $tmpCfg
secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $tmpCfg /quiet
Remove-Item $tmpCfg -Force -ErrorAction SilentlyContinue

# Guest disabled
Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

# Windows Update ON
Set-Service -Name wuauserv -StartupType Manual
Start-Service -Name wuauserv -ErrorAction SilentlyContinue

Write-Host "`n[WEAKEN-1] Stopping VSS and deleting shadow copies (BKP-W10-01 -> FAIL)..."
# Delete existing shadow copies
Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }
# Stop and disable VSS
Stop-Service -Name VSS -Force -ErrorAction SilentlyContinue
Set-Service -Name VSS -StartupType Disabled
Write-Host "           VSS stopped, shadow copies removed."

Write-Host "`n[WEAKEN-2] Disabling Defender real-time protection (EP-W10-01 -> FAIL)..."
Set-MpPreference -DisableRealtimeMonitoring $true
Write-Host "           Real-time monitoring disabled."

Write-Host "`n=== SNAP-02 setup complete. ==="
Write-Host "    Expected: Moderate risk | ~72-85% compliance | risk score ~20-38"
Write-Host "    Take a VirtualBox snapshot named 'SNAP-02' now." -ForegroundColor Yellow
