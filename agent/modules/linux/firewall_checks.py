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


def _shorten(text: str, max_lines: int = 8) -> str:
    """
    Keep evidence short so JSON is readable in terminal and dashboard.
    """
    lines = (text or "").splitlines()
    return "\n".join(lines[:max_lines]).strip()


def _parse_ufw_rules_exist(stdout: str) -> bool:
    """
    Determine whether UFW has any rules configured.
    Parses 'ufw status verbose' output — skips header lines and
    looks for actual rule entries (lines with TO/FROM/Action pattern).
    Returns True if at least one rule line is found.
    """
    # Lines to skip — these are header/metadata lines, not rules
    skip_prefixes = (
        "status:",
        "logging:",
        "logging level:",
        "default:",
        "new profiles:",
        "to ",       # column header row
        "--",        # separator row
    )
    for line in (stdout or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        low = stripped.lower()
        # Skip known header lines
        if any(low.startswith(p) for p in skip_prefixes):
            continue
        # A real rule line will have at least 2 tokens and contain
        # ALLOW, DENY, REJECT, or LIMIT
        upper = stripped.upper()
        if any(action in upper for action in ("ALLOW", "DENY", "REJECT", "LIMIT")):
            return True
    return False


def run() -> dict:
    """
    Firewall checks for Linux VM1:
    - ufw_status : active / inactive / unknown
    - ufw_rules  : { rules_exist: bool }  ← required by rules_engine FW-LNX-01
    """

    # ── 1. UFW status ────────────────────────────────────────────────────────
    ufw_raw = run_cmd(["ufw", "status"])
    if ufw_raw["returncode"] != 0:
        ufw_raw = run_cmd(["sudo", "-n", "ufw", "status"])

    stdout  = ufw_raw.get("stdout", "") or ""
    stderr  = ufw_raw.get("stderr", "") or ""
    rc      = ufw_raw.get("returncode", -999)
    status  = _parse_ufw_status(stdout)

    evidence_full = stdout if stdout.strip() else stderr
    evidence_text = _shorten(evidence_full, max_lines=12)

    if status == "unknown" and rc != 0 and not evidence_text:
        evidence_text = f"ufw check failed (rc={rc})"

    ufw_status_check = make_check(
        value=status,
        evidence=evidence_text,
        source=ufw_raw.get("cmd", "ufw status"),
    )

    # ── 2. UFW rules ─────────────────────────────────────────────────────────
    # Use 'ufw status verbose' which lists all active rules.
    # Try without sudo first, fall back to sudo -n.
    rules_raw = run_cmd(["ufw", "status", "verbose"])
    if rules_raw.get("returncode", -1) != 0:
        rules_raw = run_cmd(["sudo", "-n", "ufw", "status", "verbose"])

    rules_stdout  = rules_raw.get("stdout", "") or ""
    rules_stderr  = rules_raw.get("stderr", "") or ""
    rules_rc      = rules_raw.get("returncode", -999)

    rules_exist   = _parse_ufw_rules_exist(rules_stdout)
    rules_evidence = _shorten(rules_stdout if rules_stdout.strip() else rules_stderr, max_lines=15)

    if not rules_evidence:
        rules_evidence = f"ufw status verbose failed (rc={rules_rc})"

    ufw_rules_check = make_check(
        value={"rules_exist": rules_exist},
        evidence=rules_evidence,
        source=rules_raw.get("cmd", "ufw status verbose"),
    )

    return {
        "ufw_status": ufw_status_check,
        "ufw_rules":  ufw_rules_check,
    }