#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ComplianceAI – VM3 (Windows 10) SNAP-05 Setup
    Target Risk Level : SEVERE
    Failing controls  : ALL 8 controls

.DESCRIPTION
    Every control is deliberately broken.  This is the worst-case
    snapshot representing a completely unmanaged endpoint.
    Scoring should land in the Severe band (~10–30% compliance, risk ~75–95).
    Multiple domain escalations are expected (FW, AC, EP all have
    high-severity fails).

    Controls expected:
      FW-W10-01     FAIL  <-- all firewall profiles off
      LOG-W10-01    FAIL  <-- EventLog service stopped
      AC-W10-01     FAIL  <-- password complexity off
      AC-W10-02     FAIL  <-- Guest account enabled
      UPD-W10-01    FAIL  <-- Windows Update service stopped/disabled
      BKP-W10-01    FAIL  <-- VSS stopped, no shadow copies
      CRYPTO-W10-01 FAIL  <-- BitLocker suspended/off
      EP-W10-01     FAIL  <-- Defender real-time protection off
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "=== ComplianceAI  VM3  SNAP-05 (Severe Risk) ===" -ForegroundColor Cyan
Write-Host "    WARNING: This snapshot deliberately disables all security controls." -ForegroundColor Red
Write-Host "    Restore SNAP-01 immediately after testing is complete.`n" -ForegroundColor Red

# ── 1. Disable Windows Firewall (all profiles) ────────────────────────────────
Write-Host "[1/8] Disabling Windows Firewall – all profiles (FW-W10-01 -> FAIL)..."
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False
Write-Host "      All firewall profiles disabled."

# ── 2. Stop Windows Event Log ────────────────────────────────────────────────
Write-Host "`n[2/8] Stopping Windows Event Log service (LOG-W10-01 -> FAIL)..."
# Note: EventLog is a protected service. We disable it for the scan
# then the VM will need a reboot to register the stopped state in Get-Service.
# Alternative: set StartupType to Disabled and reboot before scanning.
Set-Service -Name EventLog -StartupType Disabled
Stop-Service -Name EventLog -Force -ErrorAction SilentlyContinue
Write-Host "      EventLog set to Disabled. Reboot the VM before running the agent"
Write-Host "      so Get-Service reflects StartType=Disabled."

# ── 3. Disable password complexity ───────────────────────────────────────────
Write-Host "`n[3/8] Disabling password complexity (AC-W10-01 -> FAIL)..."
$tmpCfg = "$env:TEMP\secpol_snap05.cfg"
secedit /export /cfg $tmpCfg /quiet
(Get-Content $tmpCfg) -replace 'PasswordComplexity\s*=\s*\d', 'PasswordComplexity = 0' |
    Set-Content $tmpCfg
secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $tmpCfg /quiet
Remove-Item $tmpCfg -Force -ErrorAction SilentlyContinue
Write-Host "      PasswordComplexity = 0."

# ── 4. Enable Guest account ──────────────────────────────────────────────────
Write-Host "`n[4/8] Enabling Guest account (AC-W10-02 -> FAIL)..."
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest) {
    Enable-LocalUser -Name "Guest"
} else {
    New-LocalUser -Name "Guest" -NoPassword -FullName "Guest" -Description "Built-in Guest" -ErrorAction SilentlyContinue
    Enable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
}
Write-Host "      Guest account enabled."

# ── 5. Stop Windows Update service ───────────────────────────────────────────
Write-Host "`n[5/8] Stopping Windows Update service (UPD-W10-01 -> FAIL)..."
Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
Set-Service -Name wuauserv -StartupType Disabled
Write-Host "      wuauserv stopped and disabled."

# ── 6. Stop VSS and delete shadow copies ─────────────────────────────────────
Write-Host "`n[6/8] Stopping VSS and deleting shadow copies (BKP-W10-01 -> FAIL)..."
Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }
Stop-Service -Name VSS -Force -ErrorAction SilentlyContinue
Set-Service -Name VSS -StartupType Disabled
Write-Host "      VSS disabled, all shadow copies deleted."

# ── 7. Suspend / disable BitLocker ───────────────────────────────────────────
Write-Host "`n[7/8] Suspending BitLocker on C: (CRYPTO-W10-01 -> FAIL)..."
try {
    $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
    if ($blv.ProtectionStatus -eq "On") {
        Suspend-BitLocker -MountPoint "C:" -RebootCount 0
        Write-Host "      BitLocker suspended."
    } else {
        Write-Host "      BitLocker already off."
    }
} catch {
    manage-bde -protectors -disable C: 2>&1 | Out-Null
    Write-Host "      manage-bde protectors disabled."
}

# ── 8. Disable Defender real-time protection ─────────────────────────────────
Write-Host "`n[8/8] Disabling Defender real-time protection (EP-W10-01 -> FAIL)..."
Set-MpPreference -DisableRealtimeMonitoring $true
Write-Host "      Real-time monitoring disabled."

Write-Host "`n=== SNAP-05 setup complete. ==="
Write-Host "    REBOOT the VM now, then log in and run the compliance agent."
Write-Host "    Expected: Severe risk | ~10-30% compliance | risk score ~75-95"
Write-Host "    Domain escalation expected: Yes (multiple domains)"
Write-Host "    Take a VirtualBox snapshot named 'SNAP-05' AFTER the reboot." -ForegroundColor Yellow
Write-Host "`n    IMPORTANT: Restore SNAP-01 after testing to recover a healthy baseline." -ForegroundColor Red
