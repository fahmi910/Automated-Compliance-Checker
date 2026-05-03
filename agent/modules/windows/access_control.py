import json
from agent.utils.runner import run_powershell
from agent.utils.result import cmd_to_check


def run() -> dict:
    out = {}

    # 1) net accounts policy
    net_raw = run_powershell(r"""
    try {
      net accounts | Out-String | ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    def str_transform(stdout: str, stderr: str, rc: int):
        if rc != 0:
            return "error"
        try:
            return json.loads(stdout)  # json string (quoted)
        except Exception:
            return stdout if stdout else "error"

    out["net_accounts_policy"] = cmd_to_check(
        net_raw,
        transform=str_transform,
        source_override="net accounts"
    )

    # 2) password complexity (minimal output, no PS metadata)
    sec_raw = run_powershell(r"""
        try {
        $path = "C:\Temp\secpol.cfg"
        New-Item -ItemType Directory -Force -Path "C:\Temp" | Out-Null
        secedit /export /cfg $path | Out-Null

        if (Test-Path $path) {
            $line = Get-Content $path | Where-Object { $_ -match "^PasswordComplexity\s*=" } | Select-Object -First 1
            [PSCustomObject]@{
            file = $path
            password_complexity = [string]$line
            } | ConvertTo-Json -Depth 3
        } else {
            [PSCustomObject]@{ error = "secedit export failed" } | ConvertTo-Json -Depth 3
        }
        } catch {
        [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
        }
        """, timeout=60)


    def obj_transform(stdout: str, stderr: str, rc: int):
        if rc != 0:
            return "error"
        try:
            data = json.loads(stdout) if stdout else {}
            if isinstance(data, dict) and data.get("error"):
                return "error"
            return data
        except Exception:
            return stdout if stdout else "error"

    out["password_complexity_policy"] = cmd_to_check(
        sec_raw,
        transform=obj_transform,
        source_override="secedit /export + PasswordComplexity"
    )

    # 3) local users list
    users_raw = run_powershell(r"""
    try {
      Get-LocalUser |
        Select-Object Name, Enabled, PasswordNeverExpires, LastLogon |
        ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    out["local_users"] = cmd_to_check(
        users_raw,
        transform=obj_transform,
        source_override="Get-LocalUser | Select Name, Enabled, PasswordNeverExpires, LastLogon"
    )

    # 4) local admin members (PrincipalSource as string)
    admins_raw = run_powershell(r"""
    try {
      Get-LocalGroupMember -Group "Administrators" |
        Select-Object Name, ObjectClass, @{N="PrincipalSource";E={$_.PrincipalSource.ToString()}} |
        ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    out["local_admin_group_members"] = cmd_to_check(
        admins_raw,
        transform=obj_transform,
        source_override="Get-LocalGroupMember -Group Administrators"
    )

    return out


# ----------------------------------------------------------------
# AC-WINSVR-02 / AC-W10-02: Guest account disabled
# Additional check appended to Windows access_control module
# ----------------------------------------------------------------

def run_guest_check() -> dict:
    """
    Checks whether the built-in Guest account is disabled.
    Returns dict to be merged into access_control results.
    """
    import json as _json
    from agent.utils.runner import run_powershell
    from agent.utils.result import cmd_to_check

    def obj_transform(stdout: str, stderr: str, rc: int):
        stdout = (stdout or "").strip()
        if stdout:
            try:
                data = _json.loads(stdout)
                if isinstance(data, dict) and data.get("error"):
                    return "error"
                return data
            except Exception:
                pass
        if rc != 0:
            return "error"
        return stdout if stdout else "error"

    guest_raw = run_powershell(r"""
    try {
      $g = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
      if ($g) {
        [PSCustomObject]@{
          Name    = $g.Name
          Enabled = $g.Enabled
          Description = $g.Description
        } | ConvertTo-Json -Depth 3
      } else {
        [PSCustomObject]@{ note = "Guest account not found on this system" } | ConvertTo-Json -Depth 3
      }
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    return {
        "guest_account": cmd_to_check(
            guest_raw,
            transform=obj_transform,
            source_override="Get-LocalUser -Name Guest",
        )
    }