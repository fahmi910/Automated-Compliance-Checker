import json
from agent.utils.runner import run_powershell
from agent.utils.result import cmd_to_check


def run() -> dict:
    results = {}

    raw = run_powershell(r"""
    try {
      $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
      )

      $apps = foreach ($p in $paths) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue |
          Where-Object { $_.DisplayName -and $_.DisplayName.Trim().Length -gt 0 } |
          Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
      }

      $apps | Sort-Object DisplayName | ConvertTo-Json -Depth 4
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """, timeout=60)

    def transform(stdout: str, stderr: str, rc: int):
        if rc != 0:
            return "error"
        try:
            data = json.loads(stdout) if stdout else []
            if isinstance(data, dict) and data.get("error"):
                return "error"
            return data
        except Exception:
            return stdout if stdout else "error"

    results["installed_software"] = cmd_to_check(
        raw,
        transform=transform,
        source_override="Registry Uninstall keys (HKLM + WOW6432Node)"
    )

    return results
