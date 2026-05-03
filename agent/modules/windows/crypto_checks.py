import json
from agent.utils.runner import run_powershell
from agent.utils.result import cmd_to_check, make_check, make_error


def _obj_transform(stdout: str, stderr: str, rc: int):
    stdout = (stdout or "").strip()
    if stdout:
        try:
            data = json.loads(stdout)
            if isinstance(data, dict) and data.get("error"):
                return "error"
            return data
        except Exception:
            pass
    if rc != 0:
        return "error"
    return stdout if stdout else "error"


def run() -> dict:
    out = {}

    # ----------------------------------------------------------------
    # CRYPTO-WINSVR-01: TLS version enforcement
    # Read SCHANNEL registry to detect if TLS 1.0 / 1.1 are disabled
    # and TLS 1.2 / 1.3 are enabled.
    # ----------------------------------------------------------------
    tls_raw = run_powershell(r"""
    try {
      $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
      $versions = @("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
      $result = @{}

      foreach ($ver in $versions) {
        $serverPath = "$base\$ver\Server"
        $clientPath = "$base\$ver\Client"

        $serverEnabled = $null
        $clientEnabled = $null

        if (Test-Path $serverPath) {
          $val = Get-ItemProperty -Path $serverPath -Name "Enabled" -ErrorAction SilentlyContinue
          if ($val -ne $null) { $serverEnabled = $val.Enabled }
        }
        if (Test-Path $clientPath) {
          $val = Get-ItemProperty -Path $clientPath -Name "Enabled" -ErrorAction SilentlyContinue
          if ($val -ne $null) { $clientEnabled = $val.Enabled }
        }

        $key = $ver -replace " ", "_"
        $result[$key] = [PSCustomObject]@{
          server_enabled = $serverEnabled
          client_enabled = $clientEnabled
          server_path_exists = (Test-Path $serverPath)
          client_path_exists = (Test-Path $clientPath)
        }
      }
      $result | ConvertTo-Json -Depth 5
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """, timeout=20)

    out["tls_registry"] = cmd_to_check(
        tls_raw,
        transform=_obj_transform,
        source_override="HKLM SCHANNEL\\Protocols TLS registry",
    )

    # ----------------------------------------------------------------
    # CRYPTO-W10-01: BitLocker status on OS drive (C:)
    # manage-bde is available on all Windows editions with BitLocker.
    # Fallback to Get-BitLockerVolume (requires RSAT or Enterprise).
    # ----------------------------------------------------------------
    bitlocker_raw = run_powershell(r"""
    try {
      # Primary: manage-bde (available on all editions)
      $bde = manage-bde -status C: 2>&1 | Out-String
      if ($LASTEXITCODE -eq 0 -or $bde -match "Protection Status") {
        # Extract key fields
        $lines = $bde -split "`n"
        $protStatus  = ($lines | Where-Object { $_ -match "Protection Status" }  | Select-Object -First 1).Trim()
        $convStatus  = ($lines | Where-Object { $_ -match "Conversion Status" }  | Select-Object -First 1).Trim()
        $lockStatus  = ($lines | Where-Object { $_ -match "Lock Status" }        | Select-Object -First 1).Trim()
        $encMethod   = ($lines | Where-Object { $_ -match "Encryption Method" }  | Select-Object -First 1).Trim()

        [PSCustomObject]@{
          source             = "manage-bde"
          protection_status  = $protStatus
          conversion_status  = $convStatus
          lock_status        = $lockStatus
          encryption_method  = $encMethod
        } | ConvertTo-Json -Depth 3
      } else {
        throw "manage-bde returned non-zero"
      }
    } catch {
      # Fallback: Get-BitLockerVolume (Enterprise/RSAT)
      try {
        $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        [PSCustomObject]@{
          source              = "Get-BitLockerVolume"
          protection_status   = $vol.ProtectionStatus.ToString()
          volume_status       = $vol.VolumeStatus.ToString()
          encryption_method   = $vol.EncryptionMethod.ToString()
          encryption_percent  = $vol.EncryptionPercentage
        } | ConvertTo-Json -Depth 3
      } catch {
        [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
      }
    }
    """, timeout=30)

    out["bitlocker_status"] = cmd_to_check(
        bitlocker_raw,
        transform=_obj_transform,
        source_override="manage-bde -status C: / Get-BitLockerVolume C:",
    )

    return out