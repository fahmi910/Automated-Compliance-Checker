#Requires -RunAsAdministrator
# ComplianceAI - VM2 (Windows Server 2022) Scenario Testing
# SNAP-01 : LOW RISK - All 7 controls PASS
# Run as Administrator inside VM2, then reboot, then take the VirtualBox snapshot.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step { param([string]$Msg) Write-Host "`n[STEP] $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "  [OK]  $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "  [WARN] $Msg" -ForegroundColor Yellow }

$script:Errors = 0

function Invoke-Step {
    param([string]$Label, [scriptblock]$Action)
    Write-Step $Label
    try {
        & $Action
        Write-Ok "$Label done"
    }
    catch {
        Write-Host "  [FAIL] $Label : $_" -ForegroundColor Red
        $script:Errors++
    }
}

# ==============================================================================
# CONTROL 1 - AC-WINSVR-01 : Password complexity enabled
# PASS when: policy contains "PasswordComplexity = 1"
# ==============================================================================
Invoke-Step "AC-WINSVR-01 Enable password complexity" {
    $inf = "$env:TEMP\secpol_snap01.inf"
    $sdb = "$env:TEMP\secedit_snap01.sdb"

    secedit /export /cfg $inf /quiet

    $content = Get-Content $inf -Raw
    if ($content -match "PasswordComplexity\s*=\s*\d") {
        $content = $content -replace "PasswordComplexity\s*=\s*\d", "PasswordComplexity = 1"
    }
    else {
        $content = $content -replace "(\[System Access\])", "`$1`r`nPasswordComplexity = 1"
    }
    Set-Content $inf $content -Encoding Unicode

    secedit /configure /db $sdb /cfg $inf /quiet /areas SECURITYPOLICY

    Remove-Item $inf -Force -ErrorAction SilentlyContinue
    Remove-Item $sdb -Force -ErrorAction SilentlyContinue

    $verInf = "$env:TEMP\verify_snap01.inf"
    secedit /export /cfg $verInf /quiet
    $verContent = Get-Content $verInf -Raw
    Remove-Item $verInf -Force -ErrorAction SilentlyContinue

    if ($verContent -notmatch "PasswordComplexity\s*=\s*1") {
        throw "Verification failed: PasswordComplexity is not 1 after applying policy."
    }
}

# ==============================================================================
# CONTROL 2 - AC-WINSVR-02 : Guest account disabled
# PASS when: Enabled == False  (or account does not exist)
# ==============================================================================
Invoke-Step "AC-WINSVR-02 Disable Guest account" {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($null -eq $guest) {
        Write-Warn "Guest account not found - evaluator will return PASS automatically."
        return
    }
    if ($guest.Enabled) {
        Disable-LocalUser -Name "Guest"
    }
    $after = Get-LocalUser -Name "Guest"
    if ($after.Enabled) {
        throw "Guest account is still enabled after disabling."
    }
}

# ==============================================================================
# CONTROL 3 - FW-WINSVR-01 : Windows Firewall enabled
# PASS when: all profiles Enabled=True AND DefaultInboundAction=Block
# ==============================================================================
Invoke-Step "FW-WINSVR-01 Enable Windows Firewall on all profiles" {
    $profiles = @("Domain", "Private", "Public")
    foreach ($p in $profiles) {
        Set-NetFirewallProfile -Profile $p -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
    }
    $fwResults = Get-NetFirewallProfile -Name $profiles
    foreach ($r in $fwResults) {
        if (-not $r.Enabled) {
            throw "Firewall profile '$($r.Name)' is still disabled."
        }
        if ($r.DefaultInboundAction -ne "Block") {
            throw "Firewall profile '$($r.Name)' DefaultInboundAction is '$($r.DefaultInboundAction)', expected Block."
        }
    }
}

# ==============================================================================
# CONTROL 4 - LOG-WINSVR-01 : Windows Event Log running
# PASS when: EventLog service Running AND Security log has at least one event
# ==============================================================================
Invoke-Step "LOG-WINSVR-01 Ensure EventLog service is running" {
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

    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    Write-Ok "Audit policy for Logon events enabled so Security log will be populated."
}

# ==============================================================================
# CONTROL 5 - UPD-WINSVR-01 : Windows Update service running
# PASS when: wuauserv Running AND latest hotfix installed within 90 days
# ==============================================================================
Invoke-Step "UPD-WINSVR-01 Start Windows Update service" {
    $svc = Get-Service -Name "wuauserv"
    if ($svc.Status -ne "Running") {
        Start-Service -Name "wuauserv"
        Start-Sleep -Seconds 3
    }
    Set-Service -Name "wuauserv" -StartupType Manual

    $svc = Get-Service -Name "wuauserv"
    if ($svc.Status -ne "Running") {
        throw "wuauserv is not Running after attempting to start it."
    }

    $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue
    if ($hotfixes) {
        $latest  = $hotfixes[0]
        $agedays = ((Get-Date) - $latest.InstalledOn).Days
        if ($agedays -gt 90) {
            Write-Warn "Most recent hotfix ($($latest.HotFixID)) is $agedays days old (>90). Run Windows Update before snapshotting."
        }
        else {
            Write-Ok "Most recent hotfix: $($latest.HotFixID) - $agedays day(s) old (within threshold)."
        }
    }
    else {
        Write-Warn "No hotfixes found via Get-HotFix. Run Windows Update before snapshotting."
    }
}

# ==============================================================================
# CONTROL 6 - BKP-WINSVR-01 : VSS enabled and shadow copies present
# PASS when: VSS Running AND (shadow copies exist OR wbadmin available)
# ==============================================================================
Invoke-Step "BKP-WINSVR-01 Start VSS and create a shadow copy" {
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

    $wbFeature = Get-WindowsFeature -Name "Windows-Server-Backup" -ErrorAction SilentlyContinue
    if ($null -ne $wbFeature -and $wbFeature.InstallState -ne "Installed") {
        Write-Step "Installing Windows Server Backup feature..."
        Install-WindowsFeature -Name "Windows-Server-Backup" -IncludeManagementTools | Out-Null
    }

    $existing = Get-WmiObject -Class Win32_ShadowCopy -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Step "No shadow copies found - creating one for C:..."
        $wmi    = Get-WmiObject -List Win32_ShadowCopy
        $result = $wmi.Create("C:\", "ClientAccessible")
        if ($result.ReturnValue -ne 0) {
            Write-Warn "Shadow copy creation returned code $($result.ReturnValue). Checking wbadmin as fallback."
        }
        else {
            Write-Ok "Shadow copy created successfully."
        }
    }
    else {
        Write-Ok "$(@($existing).Count) shadow copy/copies already exist."
    }

    $shadows = Get-WmiObject -Class Win32_ShadowCopy -ErrorAction SilentlyContinue
    $wbadmin = Get-Command wbadmin -ErrorAction SilentlyContinue
    if ((-not $shadows) -and (-not $wbadmin)) {
        throw "Neither shadow copies nor wbadmin are available. BKP-WINSVR-01 will FAIL."
    }
}

# ==============================================================================
# CONTROL 7 - CRYPTO-WINSVR-01 : TLS 1.0/1.1 disabled, TLS 1.2 enforced
# PASS when: TLS 1.0 Enabled=0, TLS 1.1 Enabled=0, TLS 1.2 Enabled != 0
# ==============================================================================
Invoke-Step "CRYPTO-WINSVR-01 Disable TLS 1.0 and 1.1, enable TLS 1.2" {
    $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

    function Set-TLSVersion {
        param([string]$Version, [int]$ServerEnabled, [int]$ClientEnabled)
        $serverPath = "$base\$Version\Server"
        $clientPath = "$base\$Version\Client"
        foreach ($path in @($serverPath, $clientPath)) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
        }
        $serverDisabled = if ($ServerEnabled -eq 0) { 1 } else { 0 }
        $clientDisabled = if ($ClientEnabled -eq 0) { 1 } else { 0 }
        Set-ItemProperty -Path $serverPath -Name "Enabled"           -Value $ServerEnabled -Type DWord
        Set-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value $serverDisabled -Type DWord
        Set-ItemProperty -Path $clientPath -Name "Enabled"           -Value $ClientEnabled -Type DWord
        Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value $clientDisabled -Type DWord
    }

    Set-TLSVersion -Version "TLS 1.0" -ServerEnabled 0 -ClientEnabled 0
    Write-Ok "TLS 1.0 disabled."

    Set-TLSVersion -Version "TLS 1.1" -ServerEnabled 0 -ClientEnabled 0
    Write-Ok "TLS 1.1 disabled."

    Set-TLSVersion -Version "TLS 1.2" -ServerEnabled 1 -ClientEnabled 1
    Write-Ok "TLS 1.2 enabled."

    foreach ($ver in @("TLS 1.0", "TLS 1.1")) {
        $val = (Get-ItemProperty -Path "$base\$ver\Server" -Name "Enabled" -ErrorAction Stop).Enabled
        if ($val -ne 0) {
            throw "$ver Server\Enabled is $val (expected 0)."
        }
    }
    $tls12 = (Get-ItemProperty -Path "$base\TLS 1.2\Server" -Name "Enabled" -ErrorAction Stop).Enabled
    if ($tls12 -eq 0) {
        throw "TLS 1.2 Server\Enabled is 0 - TLS 1.2 must not be disabled."
    }
}

# ==============================================================================
# SUMMARY
# ==============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  SNAP-01 Preparation Summary" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

if ($script:Errors -eq 0) {
    Write-Host ""
    Write-Host "  All steps completed successfully." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Expected results after agent runs:" -ForegroundColor White
    Write-Host "    AC-WINSVR-01  (Password complexity)  -> PASS" -ForegroundColor Green
    Write-Host "    AC-WINSVR-02  (Guest account)        -> PASS" -ForegroundColor Green
    Write-Host "    FW-WINSVR-01  (Windows Firewall)     -> PASS" -ForegroundColor Green
    Write-Host "    LOG-WINSVR-01 (Event Log service)    -> PASS" -ForegroundColor Green
    Write-Host "    UPD-WINSVR-01 (Windows Update)       -> PASS" -ForegroundColor Green
    Write-Host "    BKP-WINSVR-01 (VSS + shadow copies)  -> PASS" -ForegroundColor Green
    Write-Host "    CRYPTO-WINSVR-01 (TLS hardening)     -> PASS" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Cyan
    Write-Host "    1. Reboot the VM (TLS changes need a restart)."
    Write-Host "    2. From your VirtualBox host run:"
    Write-Host '       VBoxManage snapshot "VM2-WinSvr2022" take "SNAP-01-LowRisk"'
    Write-Host "    3. Trigger the compliance agent on VM2."
    Write-Host "    4. Check the dashboard - expect Risk Level: Low."
    Write-Host ""
}
else {
    Write-Host ""
    Write-Host "  $($script:Errors) step(s) FAILED. Fix errors above before snapshotting." -ForegroundColor Red
    Write-Host ""
    exit 1
}