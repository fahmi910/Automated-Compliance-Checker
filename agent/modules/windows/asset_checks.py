import json
from agent.utils.runner import run_powershell
from agent.utils.result import make_check, make_error


def run() -> dict:
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
    """, timeout=90)

    rc = raw.get("returncode", -999)
    stdout = (raw.get("stdout") or "").strip()
    stderr = (raw.get("stderr") or "").strip()

    source = "Registry Uninstall keys (HKLM + WOW6432Node)"

    if rc != 0:
        return {
            "installed_software": make_error(
                message=stderr or "failed to collect installed software",
                source=source
            )
        }

    try:
        data = json.loads(stdout) if stdout else []
        if isinstance(data, dict) and data.get("error"):
            return {
                "installed_software": make_error(
                    message=str(data.get("error")),
                    source=source
                )
            }

        # Ensure list type
        apps = data if isinstance(data, list) else [data]

        # Short evidence: count + first 5 names
        names = [a.get("DisplayName") for a in apps if isinstance(a, dict) and a.get("DisplayName")]
        preview = ", ".join(names[:5])
        evidence = f"Collected {len(apps)} installed applications. Preview: {preview}"

        return {
            "installed_software": make_check(
                value=apps,
                evidence=evidence,
                source=source
            )
        }

    except Exception as e:
        return {
            "installed_software": make_error(
                message=f"parse error: {e}",
                source=source
            )
        }
