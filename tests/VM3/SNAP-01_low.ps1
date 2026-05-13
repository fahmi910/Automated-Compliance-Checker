#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ComplianceAI – VM3 (Windows 10) SNAP-01 Setup
    Target Risk Level : LOW
    Expected Controls : ALL 8 controls PASS

.DESCRIPTION
    Hardens the Windows 10 VM so that every control evaluated by the
    compliance agent should return PASS.  Run this script ONCE, then
    take a VirtualBox snapshot named "SNAP-01".

    Controls addressed:
      FW-W10-01   Windows Firewall enabled (all profiles)
      LOG-W10-01  Windows Event Log service running
      AC-W10-01   Password complexity enabled
      AC-W10-02   Guest account disabled
      UPD-W10-01  Windows Update service running
      BKP-W10-01  VSS enabled (Volume Shadow Copy)
      CRYPTO-W10-01 BitLocker enabled on C: (skipped if TPM absent – see note)
      EP-W10-01   Windows Defender real-time protection enabled
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "=== ComplianceAI  VM3  SNAP-01 (Low Risk) ===" -ForegroundColor Cyan

# ── 1. Windows Firewall – enable all three profiles ───────────────────────────
Write-Host "`n[1/8] Enabling Windows Firewall (Domain / Private / Public)..."
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
Write-Host "      OK: All firewall profiles enabled."

# ── 2. Windows Event Log service ─────────────────────────────────────────────
Write-Host "`n[2/8] Ensuring Windows Event Log service is running..."
Set-Service -Name EventLog -StartupType Automatic
Start-Service -Name EventLog -ErrorAction SilentlyContinue
Write-Host "      OK: EventLog service running."

# ── 3. Password complexity (secedit) ─────────────────────────────────────────
Write-Host "`n[3/8] Enabling password complexity policy..."
$tmpCfg = "$env:TEMP\secpol_snap01.cfg"
secedit /export /cfg $tmpCfg /quiet
(Get-Content $tmpCfg) -replace 'PasswordComplexity\s*=\s*\d', 'PasswordComplexity = 1' |
    Set-Content $tmpCfg
secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $tmpCfg /quiet
Remove-Item $tmpCfg -Force -ErrorAction SilentlyContinue
Write-Host "      OK: Password complexity = 1 (enabled)."

# ── 4. Guest account – disable ───────────────────────────────────────────────
Write-Host "`n[4/8] Disabling Guest account..."
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest) {
    Disable-LocalUser -Name "Guest"
    Write-Host "      OK: Guest account disabled."
} else {
    Write-Host "      INFO: Guest account not found – nothing to disable."
}

# ── 5. Windows Update service (wuauserv) ─────────────────────────────────────
Write-Host "`n[5/8] Ensuring Windows Update service is running..."
Set-Service -Name wuauserv -StartupType Manual
Start-Service -Name wuauserv -ErrorAction SilentlyContinue
Write-Host "      OK: wuauserv running."

# ── 6. Volume Shadow Copy (VSS) ──────────────────────────────────────────────
Write-Host "`n[6/8] Ensuring VSS service is running and creating a shadow copy..."
Set-Service -Name VSS -StartupType Manual
Start-Service -Name VSS -ErrorAction SilentlyContinue

# Create a shadow copy so the agent sees evidence
$class  = [WMICLASS]"root\cimv2:win32_shadowcopy"
$result = $class.Create("C:\", "ClientAccessible")
if ($result.ReturnValue -eq 0) {
    Write-Host "      OK: Shadow copy created successfully."
} else {
    Write-Host "      WARN: Shadow copy creation returned code $($result.ReturnValue). VSS service is still running."
}

# ── 7. BitLocker on C: ───────────────────────────────────────────────────────
Write-Host "`n[7/8] Checking / enabling BitLocker on C:..."
try {
    $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
    if ($blv.ProtectionStatus -ne "On") {
        Write-Host "      INFO: BitLocker not active. Attempting to enable..."
        # Requires TPM or startup key. If TPM is absent in VirtualBox, this will warn.
        Enable-BitLocker -MountPoint "C:" -TpmProtector -EncryptionMethod Aes256 -ErrorAction Stop
        Write-Host "      OK: BitLocker enabled on C:."
    } else {
        Write-Host "      OK: BitLocker already active on C:."
    }
} catch {
    Write-Host "      WARN: BitLocker could not be enabled – $($_.Exception.Message)"
    Write-Host "            If running in VirtualBox without a virtual TPM, enable TPM 2.0 in VM settings"
    Write-Host "            or use a recovery-password protector and mark as PARTIAL in the test form."
}

# ── 8. Windows Defender – enable real-time protection ────────────────────────
Write-Host "`n[8/8] Enabling Windows Defender real-time protection..."
Set-MpPreference -DisableRealtimeMonitoring $false
Start-Service -Name WinDefend -ErrorAction SilentlyContinue
Write-Host "      OK: Real-time protection enabled."

Write-Host "`n=== SNAP-01 setup complete. ==="
Write-Host "    Take a VirtualBox snapshot named 'SNAP-01' now." -ForegroundColor Yellow