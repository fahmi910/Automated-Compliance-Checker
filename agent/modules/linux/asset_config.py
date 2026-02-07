from agent.utils.runner import run_cmd
from agent.utils.result import make_check


def _read_os_release() -> str:
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="ignore") as f:
            return f.read().strip()
    except Exception:
        return ""


def _parse_pretty_name(os_release_text: str) -> str:
    # Look for PRETTY_NAME="Ubuntu 22.04.3 LTS"
    for line in (os_release_text or "").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return "unknown"


def run() -> dict:
    results = {}

    # OS release
    os_rel = _read_os_release()
    pretty = _parse_pretty_name(os_rel) if os_rel else "unknown"

    results["os_pretty_name"] = make_check(
        value=pretty,
        evidence=pretty if pretty != "unknown" else "/etc/os-release unreadable",
        source="/etc/os-release"
    )

    # Kernel version
    kernel_raw = run_cmd(["uname", "-r"])
    kernel_val = (kernel_raw.get("stdout") or "").strip() or "unknown"
    results["kernel_version"] = make_check(
        value=kernel_val,
        evidence=kernel_val,
        source=kernel_raw.get("cmd", "uname -r")
    )

    # Pending updates count (apt)
    # Use bash -lc so pipes work
    updates_raw = run_cmd(["bash", "-lc", "apt list --upgradable 2>/dev/null | tail -n +2 | wc -l"])
    count_str = (updates_raw.get("stdout") or "").strip()

    try:
        count = int(count_str)
    except Exception:
        count = -1

    results["pending_updates_count"] = make_check(
        value=count,
        evidence=f"upgradable packages: {count_str}" if count >= 0 else (updates_raw.get("stderr") or "unable to parse"),
        source=updates_raw.get("cmd", "apt list --upgradable | wc -l")
    )

    return results
