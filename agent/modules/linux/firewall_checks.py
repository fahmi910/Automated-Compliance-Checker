from agent.utils.runner import run_cmd
from agent.utils.result import make_check


def _parse_ufw_status(stdout: str) -> str:
    """
    Extract 'active' or 'inactive' from UFW output.
    """
    for line in (stdout or "").splitlines():
        low = line.strip().lower()
        if low.startswith("status:"):
            return line.split(":", 1)[1].strip().lower()
    return "unknown"


def _shorten(text: str, max_lines: int = 12) -> str:
    """
    Keep evidence short so JSON is readable in terminal and dashboard.
    """
    lines = (text or "").splitlines()
    return "\n".join(lines[:max_lines]).strip()


def run() -> dict:
    """
    Firewall checks for Linux VM1:
    - UFW status (active/inactive/unknown)
    """
    # Try without sudo first, then sudo -n (non-interactive)
    ufw_raw = run_cmd(["ufw", "status"])
    if ufw_raw["returncode"] != 0:
        ufw_raw = run_cmd(["sudo", "-n", "ufw", "status"])

    stdout = ufw_raw.get("stdout", "") or ""
    stderr = ufw_raw.get("stderr", "") or ""
    rc = ufw_raw.get("returncode", -999)

    status = _parse_ufw_status(stdout)

    # Prefer stdout evidence, fallback to stderr
    evidence_full = stdout if stdout.strip() else stderr

    # Make evidence short
    evidence_text = _shorten(evidence_full, max_lines=12)

    # If UFW command failed and no status was detected, keep status as unknown but show why
    if status == "unknown" and rc != 0 and not evidence_text:
        evidence_text = f"ufw check failed (rc={rc})"

    ufw_check = make_check(
        value=status,
        evidence=evidence_text,
        source=ufw_raw.get("cmd", "ufw status")
    )

    return {
        "ufw_status": ufw_check
    }
