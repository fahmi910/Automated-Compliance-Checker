#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ComplianceAI – VM3 (Windows 10) SNAP-04 Setup
    Target Risk Level : CRITICAL
    Failing controls  : AC-W10-01  (password complexity OFF)
                        AC-W10-02  (Guest account ENABLED)
                        FW-W10-01  (Firewall DISABLED)
                        BKP-W10-01 (VSS stopped)
                        CRYPTO-W10-01 (BitLocker suspended/off)

.DESCRIPTION
    Five controls fail, four of which are HIGH severity.
    Two high-severity fails in the same domain (Access Control) also
    trigger domain escalation.
    Scoring should land in the Critical band (~30–45% compliance, risk ~60–75).

    Controls expected:
      FW-W10-01     FAIL  <-- all firewall profiles off
      LOG-W10-01    PASS
      AC-W10-01     FAIL  <-- password complexity off
      AC-W10-02     FAIL  <-- Guest account enabled
      UPD-W10-01    PASS
      BKP-W10-01    FAIL  <-- VSS stopped
      CRYPTO-W10-01 FAIL  <-- BitLocker suspended/off
      EP-W10-01     PASS
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "=== ComplianceAI  VM3  SNAP-04 (Critical Risk) ===" -ForegroundColor Cyan

# ── Passing controls ──────────────────────────────────────────────────────────
Write-Host "`n[KEEP-1] EventLog ON..."
Set-Service -Name EventLog -StartupType Automatic
Start-Service -Name EventLog -ErrorAction SilentlyContinue

Write-Host "[KEEP-2] Windows Update ON..."
Set-Service -Name wuauserv -StartupType Manual
Start-Service -Name wuauserv -ErrorAction SilentlyContinue

Write-Host "[KEEP-3] Enabling Defender real-time protection (EP-W10-01 PASS)..."
Set-MpPreference -DisableRealtimeMonitoring $false
Start-Service -Name WinDefend -ErrorAction SilentlyContinue

# ── Deliberate weaknesses ─────────────────────────────────────────────────────
Write-Host "`n[WEAKEN-1] Disabling Windows Firewall – all profiles (FW-W10-01 -> FAIL)..."
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False
Write-Host "           All firewall profiles disabled."

Write-Host "`n[WEAKEN-2] Disabling password complexity (AC-W10-01 -> FAIL)..."
$tmpCfg = "$env:TEMP\secpol_snap04.cfg"
secedit /export /cfg $tmpCfg /quiet
(Get-Content $tmpCfg) -replace 'PasswordComplexity\s*=\s*\d', 'PasswordComplexity = 0' |
    Set-Content $tmpCfg
secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $tmpCfg /quiet
Remove-Item $tmpCfg -Force -ErrorAction SilentlyContinue
Write-Host "           PasswordComplexity = 0."

Write-Host "`n[WEAKEN-3] Enabling Guest account (AC-W10-02 -> FAIL)..."
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest) {
    Enable-LocalUser -Name "Guest"
    Write-Host "           Guest account enabled."
} else {
    # Create a Guest-like account if the built-in doesn't exist
    New-LocalUser -Name "Guest" -NoPassword -FullName "Guest" -Description "Built-in Guest" -ErrorAction SilentlyContinue
    Enable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    Write-Host "           Guest account created and enabled."
}

Write-Host "`n[WEAKEN-4] Stopping VSS and deleting shadow copies (BKP-W10-01 -> FAIL)..."
Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }
Stop-Service -Name VSS -Force -ErrorAction SilentlyContinue
Set-Service -Name VSS -StartupType Disabled
Write-Host "           VSS disabled."

Write-Host "`n[WEAKEN-5] Suspending BitLocker on C: (CRYPTO-W10-01 -> FAIL)..."
try {
    $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
    if ($blv.ProtectionStatus -eq "On") {
        Suspend-BitLocker -MountPoint "C:" -RebootCount 0
        Write-Host "           BitLocker suspended."
    } else {
        Write-Host "           BitLocker already off."
    }
} catch {
    manage-bde -protectors -disable C: 2>&1 | Out-Null
    Write-Host "           manage-bde protectors disabled."
}

Write-Host "`n=== SNAP-04 setup complete. ==="
Write-Host "    Expected: Critical risk | ~30-45% compliance | risk score ~60-75"
Write-Host "    Domain escalation expected: Yes (AC domain has 2 high FAIL controls)"
Write-Host "    Take a VirtualBox snapshot named 'SNAP-04' now." -ForegroundColor Yellow
