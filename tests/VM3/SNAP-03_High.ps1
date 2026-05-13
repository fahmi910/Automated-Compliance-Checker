#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ComplianceAI – VM3 (Windows 10) SNAP-03 Setup
    Target Risk Level : HIGH
    Failing controls  : AC-W10-01  (password complexity OFF)
                        BKP-W10-01 (VSS stopped)
                        EP-W10-01  (Defender real-time OFF)
                        CRYPTO-W10-01 (BitLocker off / suspended)

.DESCRIPTION
    Three HIGH-severity controls + one MEDIUM fail.
    Scoring should land in the High band (~55–70% compliance, risk ~40–58).

    Controls expected:
      FW-W10-01     PASS
      LOG-W10-01    PASS
      AC-W10-01     FAIL  <-- password complexity disabled
      AC-W10-02     PASS
      UPD-W10-01    PASS
      BKP-W10-01    FAIL  <-- VSS stopped
      CRYPTO-W10-01 FAIL  <-- BitLocker suspended/off
      EP-W10-01     FAIL  <-- Real-time protection disabled
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "=== ComplianceAI  VM3  SNAP-03 (High Risk) ===" -ForegroundColor Cyan

# ── Passing controls ──────────────────────────────────────────────────────────
Write-Host "`n[KEEP-1] Firewall ON..."
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

Write-Host "[KEEP-2] EventLog ON..."
Set-Service -Name EventLog -StartupType Automatic
Start-Service -Name EventLog -ErrorAction SilentlyContinue

Write-Host "[KEEP-3] Guest account disabled..."
Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

Write-Host "[KEEP-4] Windows Update ON..."
Set-Service -Name wuauserv -StartupType Manual
Start-Service -Name wuauserv -ErrorAction SilentlyContinue

# ── Deliberate weaknesses ─────────────────────────────────────────────────────
Write-Host "`n[WEAKEN-1] Disabling password complexity (AC-W10-01 -> FAIL)..."
$tmpCfg = "$env:TEMP\secpol_snap03.cfg"
secedit /export /cfg $tmpCfg /quiet
(Get-Content $tmpCfg) -replace 'PasswordComplexity\s*=\s*\d', 'PasswordComplexity = 0' |
    Set-Content $tmpCfg
secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $tmpCfg /quiet
Remove-Item $tmpCfg -Force -ErrorAction SilentlyContinue
Write-Host "           PasswordComplexity = 0."

Write-Host "`n[WEAKEN-2] Stopping VSS and deleting shadow copies (BKP-W10-01 -> FAIL)..."
Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }
Stop-Service -Name VSS -Force -ErrorAction SilentlyContinue
Set-Service -Name VSS -StartupType Disabled
Write-Host "           VSS disabled."

Write-Host "`n[WEAKEN-3] Suspending/disabling BitLocker on C: (CRYPTO-W10-01 -> FAIL)..."
try {
    $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
    if ($blv.ProtectionStatus -eq "On") {
        Suspend-BitLocker -MountPoint "C:" -RebootCount 0
        Write-Host "           BitLocker suspended (protection OFF)."
    } else {
        Write-Host "           BitLocker already off – no action needed."
    }
} catch {
    Write-Host "           BitLocker cmdlet not available – using manage-bde..."
    manage-bde -protectors -disable C: 2>&1 | Out-Null
    Write-Host "           manage-bde protectors disabled on C:."
}

Write-Host "`n[WEAKEN-4] Disabling Defender real-time protection (EP-W10-01 -> FAIL)..."
Set-MpPreference -DisableRealtimeMonitoring $true
Write-Host "           Real-time monitoring disabled."

Write-Host "`n=== SNAP-03 setup complete. ==="
Write-Host "    Expected: High risk | ~55-70% compliance | risk score ~40-58"
Write-Host "    Take a VirtualBox snapshot named 'SNAP-03' now." -ForegroundColor Yellow
