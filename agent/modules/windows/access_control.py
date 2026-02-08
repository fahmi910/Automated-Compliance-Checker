import json
from agent.utils.runner import run_powershell
from agent.utils.result import cmd_to_check


def run() -> dict:
    results = {}

    # 1) Password and lockout policy (net accounts)
    net_raw = run_powershell(r"""
    try {
      net accounts | Out-String | ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    def net_transform(stdout: str, stderr: str, rc: int):
        if rc != 0:
            return "error"
        try:
            # This is JSON string (quoted) because we ConvertTo-Json a string
            return json.loads(stdout)
        except Exception:
            return stdout if stdout else "error"

    results["net_accounts_policy"] = cmd_to_check(
        net_raw,
        transform=net_transform,
        source_override="net accounts"
    )

    # 2) Password complexity (secedit export and parse PasswordComplexity line)
    sec_raw = run_powershell(r"""
    try {
      $path = "C:\Temp\secpol.cfg"
      New-Item -ItemType Directory -Force -Path "C:\Temp" | Out-Null
      secedit /export /cfg $path | Out-Null

      if (Test-Path $path) {
        $line = (Get-Content $path | Where-Object { $_ -match "^PasswordComplexity\s*=" } | Select-Object -First 1)
        [PSCustomObject]@{
          file = $path
          password_complexity_line = $line
        } | ConvertTo-Json -Depth 3
      } else {
        [PSCustomObject]@{ error = "secedit export failed" } | ConvertTo-Json -Depth 3
      }
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    def sec_transform(stdout: str, stderr: str, rc: int):
        if rc != 0:
            return "error"
        try:
            data = json.loads(stdout) if stdout else {}
            if isinstance(data, dict) and data.get("error"):
                return "error"
            return data
        except Exception:
            return stdout if stdout else "error"

    results["password_complexity_policy"] = cmd_to_check(
        sec_raw,
        transform=sec_transform,
        source_override="secedit /export + parse PasswordComplexity"
    )

    # 3) Local users list (Guest enabled, PasswordNeverExpires)
    users_raw = run_powershell(r"""
    try {
      Get-LocalUser | Select-Object Name, Enabled, PasswordNeverExpires, LastLogon | ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    def users_transform(stdout: str, stderr: str, rc: int):
        if rc != 0:
            return "error"
        try:
            data = json.loads(stdout) if stdout else {}
            if isinstance(data, dict) and data.get("error"):
                return "error"
            return data
        except Exception:
            return stdout if stdout else "error"

    results["local_users"] = cmd_to_check(
        users_raw,
        transform=users_transform,
        source_override="Get-LocalUser | Select Name, Enabled, PasswordNeverExpires, LastLogon"
    )

    # 4) Local Administrators group membership
    admins_raw = run_powershell(r"""
    try {
      Get-LocalGroupMember -Group "Administrators" |
        Select-Object Name, ObjectClass, PrincipalSource |
        ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    results["local_admin_group_members"] = cmd_to_check(
        admins_raw,
        transform=users_transform,
        source_override="Get-LocalGroupMember -Group Administrators"
    )

    return {"access_control": results}
