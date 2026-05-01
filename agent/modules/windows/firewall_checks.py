from agent.utils.runner import run_cmd
from agent.utils.result import make_check


def _parse_ufw_status(stdout: str) -> str:
    for line in (stdout or "").splitlines():
        low = line.strip().lower()
        if low.startswith("status:"):
            return line.split(":", 1)[1].strip().lower()
    return "unknown"


def _parse_ufw_rules(stdout: str) -> dict:
    """
    Extract:
    - whether rules exist
    - optionally detect if any ALLOW rules exist
    """
    rules_exist = False
    allow_rules = 0

    for line in (stdout or "").splitlines():
        low = line.strip().lower()

        if not low or low.startswith("status:") or low.startswith("to"):
            continue

        rules_exist = True

        if "allow" in low:
            allow_rules += 1

    return {
        "rules_exist": rules_exist,
        "allow_rule_count": allow_rules
    }


def _shorten(text: str, max_lines: int = 8) -> str:
    lines = (text or "").splitlines()
    return "\n".join(lines[:max_lines]).strip()


def run() -> dict:
    results = {}

    # -------------------------
    # 1. UFW STATUS
    # -------------------------
    ufw_raw = run_cmd(["ufw", "status"])
    if ufw_raw["returncode"] != 0:
        ufw_raw = run_cmd(["sudo", "-n", "ufw", "status"])

    stdout = ufw_raw.get("stdout", "") or ""
    stderr = ufw_raw.get("stderr", "") or ""
    rc = ufw_raw.get("returncode", -999)

    status = _parse_ufw_status(stdout)
    evidence_full = stdout if stdout.strip() else stderr
    evidence_text = _shorten(evidence_full, max_lines=12)

    if status == "unknown" and rc != 0 and not evidence_text:
        evidence_text = f"ufw check failed (rc={rc})"

    results["ufw_status"] = make_check(
        value=status,
        evidence=evidence_text,
        source=ufw_raw.get("cmd", "ufw status")
    )

    # -------------------------
    # 2. UFW RULES
    # -------------------------
    rules_raw = run_cmd(["ufw", "status", "numbered"])
    if rules_raw["returncode"] != 0:
        rules_raw = run_cmd(["sudo", "-n", "ufw", "status", "numbered"])

    rules_stdout = rules_raw.get("stdout", "") or ""
    rules_stderr = rules_raw.get("stderr", "") or ""
    rules_rc = rules_raw.get("returncode", -999)

    rules_info = _parse_ufw_rules(rules_stdout)

    rules_evidence = rules_stdout if rules_stdout.strip() else rules_stderr
    rules_evidence_text = _shorten(rules_evidence, max_lines=12)

    if rules_rc != 0 and not rules_evidence_text:
        rules_evidence_text = f"ufw rules check failed (rc={rules_rc})"

    results["ufw_rules"] = make_check(
        value=rules_info,
        evidence=rules_evidence_text,
        source=rules_raw.get("cmd", "ufw status numbered")
    )

    return results