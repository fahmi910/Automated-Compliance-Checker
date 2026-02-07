from agent.utils.runner import run_cmd
from agent.utils.result import make_check, cmd_to_check


def _parse_ufw_status(stdout: str) -> str:
    for line in (stdout or "").splitlines():
        low = line.strip().lower()
        if low.startswith("status:"):
            return line.split(":", 1)[1].strip().lower()
    return "unknown"


def _shorten(text: str, max_lines: int = 20) -> str:
    lines = (text or "").splitlines()
    return "\n".join(lines[:max_lines]).strip()


def run() -> dict:
    # Try without sudo first, then sudo -n
    ufw_raw = run_cmd(["ufw", "status"])
    if ufw_raw["returncode"] != 0:
        ufw_raw = run_cmd(["sudo", "-n", "ufw", "status"])

    status = _parse_ufw_status(ufw_raw.get("stdout", ""))

    # Make evidence shorter to avoid huge JSON
    evidence_text = _shorten(ufw_raw.get("stdout", "") or ufw_raw.get("stderr", ""))

    ufw_check = make_check(
        value=status,
        evidence=evidence_text,
        source=ufw_raw.get("cmd", "ufw status")
    )

    return {
        "ufw_status": ufw_check
    }
