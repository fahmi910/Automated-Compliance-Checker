#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ComplianceAI — VM2 (Windows Server 2022) Scenario Testing
    SNAP-01 : LOW RISK  —  All 7 controls PASS

.DESCRIPTION
    Prepares VM2 so that every Windows Server control evaluated by the
    ComplianceAI rules engine will return PASS, producing the lowest
    possible risk score for Category B Scenario Testing.

    Controls targeted
    ─────────────────────────────────────────────────────────────────
    AC-WINSVR-01  Password complexity enabled          (High)
    AC-WINSVR-02  Guest account disabled               (High)
    FW-WINSVR-01  Windows Firewall enabled             (High)
    LOG-WINSVR-01 Windows Event Log running            (High)
    UPD-WINSVR-01 Windows Update service running       (High)
    BKP-WINSVR-01 VSS enabled + shadow copies present  (High)
    CRYPTO-WINSVR-01 TLS 1.0/1.1 disabled, TLS 1.2+   (High)

    Expected outcome after snapshot
    ─────────────────────────────────────────────────────────────────
    All statuses : PASS
    Risk level   : Low
    Compliance   : ~100 %

.NOTES
    Run as Administrator inside VM2 BEFORE taking the VirtualBox snapshot.
    After the script completes successfully, take the snapshot via:
        VBoxManage snapshot "VM2-WinSvr2022" take "SNAP-01-LowRisk" --description "All controls PASS"
    Then trigger the compliance agent and verify the dashboard.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─── Helpers ──────────────────────────────────────────────────────────────────

function Write-Step  { param([string]$Msg) Write-Host "`n[STEP] $Msg" -ForegroundColor Cyan }
function Write-Ok    { param([string]$Msg) Write-Host "  [OK]  $Msg" -ForegroundColor Green }
function Write-Warn  { param([string]$Msg) Write-Host "  [WARN] $Msg" -ForegroundColor Yellow }
function Write-Fail  { param([string]$Msg) Write-Host "  [FAIL] $Msg" -ForegroundColor Red }

$script:Errors = 0

function Invoke-Step {
    param([string]$Label, [scriptblock]$Action)
    Write-Step $Label
    try {
        & $Action
        Write-Ok "$Label — done"
    } catch {
        Write-Fail "$Label — $_"
        $script:Errors++
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# CONTROL 1 — AC-WINSVR-01 : Password complexity enabled
#   Evaluator : evaluate_ac_windows_01
#   Evidence  : results.access_control.password_complexity_policy
#   PASS when : policy dict contains "PasswordComplexity = 1"
# ══════════════════════════════════════════════════════════════════════════════
Invoke-Step "AC-WINSVR-01 — Enable password complexity (secedit)" {
    # Export current security policy, flip the flag, re-import
    $inf = "$env:TEMP\secpol_snap01.inf"

    secedit /export /cfg $inf /quiet

    $content = Get-Content $inf -Raw

    # Ensure PasswordComplexity = 1 is set under [System Access]
    if ($content -match "PasswordComplexity\s*=\s*\d") {
        $content = $content -replace "PasswordComplexity\s*=\s*\d", "PasswordComplexity = 1"
    } else {
        $content = $content -replace "(\[System Access\])", "`$1`r`nPasswordComplexity = 1"
    }

    Set-Content $inf $content -Encoding Unicode

    secedit /configure /db "$env:TEMP\secedit_snap01.sdb" /cfg $inf /quiet /areas SECURITYPOLICY

    Remove-Item $inf -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\secedit_snap01.sdb" -Force -ErrorAction SilentlyContinue

    # Verify
    $verify = & secedit /export /cfg "$env:TEMP\verify_snap01.inf" /quiet
    $verContent = Get-Content "$env:TEMP\verify_snap01.inf" -Raw
    Remove-Item "$env:TEMP\verify_snap01.inf" -Force -ErrorAction SilentlyContinue

    if ($verContent -notmatch "PasswordComplexity\s*=\s*1") {
        throw "Verification failed: PasswordComplexity is not 1 after applying policy."
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# CONTROL 2 — AC-WINSVR-02 : Guest account disabled
#   Evaluator : evaluate_ac_guest_windows
#   Evidence  : results.access_control.guest_account  { Enabled: false }
#   PASS when : Enabled == False
# ══════════════════════════════════════════════════════════════════════════════
Invoke-Step "AC-WINSVR-02 — Disable Guest account" {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($null -eq $guest) {
        Write-Warn "Guest account not found — evaluator will return PASS (account absent = not a risk)."
        return
    }
    if ($guest.Enabled) {
        Disable-LocalUser -Name "Guest"
    }
    $after = Get-LocalUser -Name "Guest"
    if ($after.Enabled) {
        throw "Guest account is still enabled after attempting to disable it."
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# CONTROL 3 — FW-WINSVR-01 : Windows Firewall enabled
#   Evaluator : evaluate_fw_windows_01
#   Evidence  : results.firewall.windows_firewall_profiles  (list of profile dicts)
#   PASS when : all profiles have Enabled=True AND DefaultInboundAction=Block
# ══════════════════════════════════════════════════════════════════════════════
Invoke-Step "FW-WINSVR-01 — Enable Windows Firewall on all profiles (inbound block)" {
    $profiles = @("Domain", "Private", "Public")
    foreach ($p in $profiles) {
        Set-NetFirewallProfile -Profile $p -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
    }

    # Verify
    $results = Get-NetFirewallProfile -Name $profiles
    foreach ($r in $results) {
        if (-not $r.Enabled) {
            throw "Firewall profile '$($r.Name)' is still disabled."
        }
        if ($r.DefaultInboundAction -ne "Block") {
            throw "Firewall profile '$($r.Name)' DefaultInboundAction is '$($r.DefaultInboundAction)', expected Block."
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# CONTROL 4 — LOG-WINSVR-01 : Windows Event Log running
#   Evaluator : evaluate_log_windows_01
#   Evidence  : results.logging.eventlog_service  { Status: "Running" }
#               results.logging.last_security_event  (dict with an event)
#   PASS when : service Running AND a Security log event is readable
# ══════════════════════════════════════════════════════════════════════════════
Invoke-Step "LOG-WINSVR-01 — Ensure Windows Event Log service is Running" {
    $svc = Get-Service -Name "EventLog"
    if ($svc.Status -ne "Running") {
        Start-Service -Name "EventLog"
        Start-Sleep -Seconds 3
    }
    Set-Service -Name "EventLog" -StartupType Automatic

    $svc = Get-Service -Name "EventLog"
    if ($svc.Status -ne "Running") {
        throw "EventLog service is not Running after attempting to start it."
    }

    # Generate at least one Security log event so last_security_event evidence exists
    # Event 4648 (explicit credential logon) is harmless to generate via audit policy
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    Write-Ok "  Audit policy for Logon events enabled — Security log will be populated."
}

# ══════════════════════════════════════════════════════════════════════════════
# CONTROL 5 — UPD-WINSVR-01 : Windows Update service running
#   Evaluator : evaluate_upd_windows_01
#   Evidence  : results.updates.wuauserv_status  { Status: "Running" }
#               results.updates.latest_hotfix     (dict with HotFixID + InstalledOn)
#   PASS when : wuauserv Running AND latest hotfix is recent (< 90 days)
#
#   NOTE: The hotfix age check uses the most recent KB from Get-HotFix.
#         On a freshly patched Server 2022 this will pass naturally.
#         We start the service and verify a recent KB exists; if the VM
#         is very out of date you should run Windows Update before snapshotting.
# ══════════════════════════════════════════════════════════════════════════════
Invoke-Step "UPD-WINSVR-01 — Start and enable wuauserv (Windows Update)" {
    $svc = Get-Service -Name "wuauserv"
    if ($svc.Status -ne "Running") {
        Start-Service -Name "wuauserv"
        Start-Sleep -Seconds 3
    }
    Set-Service -Name "wuauserv" -StartupType Manual   # Server default is Manual

    $svc = Get-Service -Name "wuauserv"
    if ($svc.Status -ne "Running") {
        throw "wuauserv is not Running after attempting to start it."
    }

    # Advisory: check most recent hotfix age
    $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue
    if ($hotfixes) {
        $latest   = $hotfixes[0]
        $agedays  = ((Get-Date) - $latest.InstalledOn).Days
        if ($agedays -gt 90) {
            Write-Warn "Most recent hotfix ($($latest.HotFixID)) is $agedays days old (>90)."
            Write-Warn "The agent may report UPD-WINSVR-01 as PARTIAL/FAIL. Run Windows Update before snapshotting."
        } else {
            Write-Ok "  Most recent hotfix: $($latest.HotFixID) — $agedays day(s) old (within 90-day threshold)."
        }
    } else {
        Write-Warn "No hotfixes found via Get-HotFix. Run Windows Update before taking this snapshot."
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# CONTROL 6 — BKP-WINSVR-01 : VSS enabled + shadow copies present
#   Evaluator : evaluate_bkp_windows_01
#   Evidence  : results.backup.vss_service    { Status: "Running" }
#               results.backup.shadow_copies  (list or dict with count > 0)
#               results.backup.wbadmin_status { wbadmin_available: true }
#   PASS when : VSS Running AND (shadow copies exist OR wbadmin available)
# ══════════════════════════════════════════════════════════════════════════════
Invoke-Step "BKP-WINSVR-01 — Start VSS service and create a shadow copy" {
    # 1. Start the Volume Shadow Copy service
    $svc = Get-Service -Name "VSS"
    if ($svc.Status -ne "Running") {
        Start-Service -Name "VSS"
        Start-Sleep -Seconds 3
    }
    Set-Service -Name "VSS" -StartupType Manual

    $svc = Get-Service -Name "VSS"
    if ($svc.Status -ne "Running") {
        throw "VSS service is not Running after attempting to start it."
    }

    # 2. Ensure wbadmin is present (it ships with Windows Server; install if missing)
    $wbFeature = Get-WindowsFeature -Name "Windows-Server-Backup" -ErrorAction SilentlyContinue
    if ($null -ne $wbFeature -and $wbFeature.InstallState -ne "Installed") {
        Write-Step "  Installing Windows Server Backup feature (needed for wbadmin)…"
        Install-WindowsFeature -Name "Windows-Server-Backup" -IncludeManagementTools | Out-Null
    }

    # 3. Create a shadow copy of C: so shadow_copies evidence is non-empty
    $existing = Get-WmiObject -Class Win32_ShadowCopy -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Step "  No shadow copies found — creating one for C:\…"
        $result = (Get-WmiObject -List Win32_ShadowCopy).Create("C:\", "ClientAccessible")
        if ($result.ReturnValue -ne 0) {
            Write-Warn "Shadow copy creation returned code $($result.ReturnValue). Checking wbadmin as fallback."
        } else {
            Write-Ok "  Shadow copy created successfully."
        }
    } else {
        Write-Ok "  $(@($existing).Count) shadow copy/copies already exist — no action needed."
    }

    # Verify at least one of: shadow copies OR wbadmin
    $shadows  = Get-WmiObject -Class Win32_ShadowCopy -ErrorAction SilentlyContinue
    $wbadmin  = Get-Command wbadmin -ErrorAction SilentlyContinue
    if (-not $shadows -and -not $wbadmin) {
        throw "Neither shadow copies nor wbadmin are available. BKP-WINSVR-01 will FAIL."
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# CONTROL 7 — CRYPTO-WINSVR-01 : TLS 1.0/1.1 disabled, TLS 1.2+ enforced
#   Evaluator : evaluate_crypto_winsvr_01
#   Evidence  : results.crypto.tls_registry  (dict keyed by TLS version)
#   PASS when : TLS_1.0.server_enabled == 0  AND
#               TLS_1.1.server_enabled == 0  AND
#               TLS_1.2 NOT explicitly disabled (server_enabled != 0)
# ══════════════════════════════════════════════════════════════════════════════
Invoke-Step "CRYPTO-WINSVR-01 — Disable TLS 1.0 & 1.1, ensure TLS 1.2 is enabled" {
    $schannelBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

    # Helper: set SCHANNEL registry values for a TLS version
    function Set-TLSVersion {
        param(
            [string]$Version,
            [int]$ServerEnabled,    # 0 = disabled, 1 = enabled
            [int]$ClientEnabled
        )
        $serverPath = "$schannelBase\$Version\Server"
        $clientPath = "$schannelBase\$Version\Client"

        foreach ($path in @($serverPath, $clientPath)) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
        }
        Set-ItemProperty -Path $serverPath -Name "Enabled"              -Value $ServerEnabled -Type DWord
        Set-ItemProperty -Path $serverPath -Name "DisabledByDefault"    -Value $(if ($ServerEnabled -eq 0) {1} else {0}) -Type DWord
        Set-ItemProperty -Path $clientPath -Name "Enabled"              -Value $ClientEnabled -Type DWord
        Set-ItemProperty -Path $clientPath -Name "DisabledByDefault"    -Value $(if ($ClientEnabled -eq 0) {1} else {0}) -Type DWord
    }

    # Disable TLS 1.0
    Set-TLSVersion -Version "TLS 1.0" -ServerEnabled 0 -ClientEnabled 0
    Write-Ok "  TLS 1.0 disabled."

    # Disable TLS 1.1
    Set-TLSVersion -Version "TLS 1.1" -ServerEnabled 0 -ClientEnabled 0
    Write-Ok "  TLS 1.1 disabled."

    # Ensure TLS 1.2 is explicitly ENABLED (Enabled=1)
    Set-TLSVersion -Version "TLS 1.2" -ServerEnabled 1 -ClientEnabled 1
    Write-Ok "  TLS 1.2 explicitly enabled."

    # Verify
    foreach ($ver in @("TLS 1.0", "TLS 1.1")) {
        $val = (Get-ItemProperty -Path "$schannelBase\$ver\Server" -Name "Enabled" -ErrorAction Stop).Enabled
        if ($val -ne 0) {
            throw "$ver Server\Enabled is $val (expected 0)."
        }
    }
    $tls12val = (Get-ItemProperty -Path "$schannelBase\TLS 1.2\Server" -Name "Enabled" -ErrorAction Stop).Enabled
    if ($tls12val -eq 0) {
        throw "TLS 1.2 Server\Enabled is 0 — TLS 1.2 must NOT be disabled."
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor White
Write-Host "  SNAP-01 Preparation Summary" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor White

if ($script:Errors -eq 0) {
    Write-Host ""
    Write-Host "  All steps completed successfully." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Expected compliance agent results:" -ForegroundColor White
    Write-Host "    AC-WINSVR-01  (Password complexity)  → PASS" -ForegroundColor Green
    Write-Host "    AC-WINSVR-02  (Guest account)        → PASS" -ForegroundColor Green
    Write-Host "    FW-WINSVR-01  (Windows Firewall)     → PASS" -ForegroundColor Green
    Write-Host "    LOG-WINSVR-01 (Event Log service)    → PASS" -ForegroundColor Green
    Write-Host "    UPD-WINSVR-01 (Windows Update)       → PASS  *" -ForegroundColor Green
    Write-Host "    BKP-WINSVR-01 (VSS + shadow copies)  → PASS" -ForegroundColor Green
    Write-Host "    CRYPTO-WINSVR-01 (TLS hardening)     → PASS" -ForegroundColor Green
    Write-Host ""
    Write-Host "  * If the newest hotfix is older than 90 days a PARTIAL may occur." -ForegroundColor Yellow
    Write-Host "    Run Windows Update first if the advisory warning appeared above." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Cyan
    Write-Host "    1. Reboot the VM (TLS registry changes take effect after restart)."
    Write-Host "    2. After reboot, from VirtualBox host run:"
    Write-Host '       VBoxManage snapshot "VM2-WinSvr2022" take "SNAP-01-LowRisk" --description "All 7 controls PASS"'
    Write-Host "    3. Trigger the compliance agent on VM2."
    Write-Host "    4. Verify dashboard shows Risk Level: Low and ~100% compliance."
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "  $($script:Errors) step(s) FAILED. Review errors above before snapshotting." -ForegroundColor Red
    Write-Host ""
    exit 1
}