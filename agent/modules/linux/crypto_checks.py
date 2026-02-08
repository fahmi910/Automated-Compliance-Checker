from agent.utils.runner import run_cmd
from agent.utils.result import make_check, make_error


def _read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def _get_config_line(conf_text: str, key: str) -> str:
    # Get last non-comment occurrence; if not set, defaults apply
    value = "default"
    for line in conf_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == key.lower():
            value = parts[1].strip()
    return value


def _detect_weak_algorithms(text: str) -> list:
    weak_markers = [
        "cbc",
        "3des",
        "arcfour",
        "hmac-sha1",
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
    ]
    found = []
    low = (text or "").lower()
    for w in weak_markers:
        if w in low:
            found.append(w)
    return found


def _extract_sshd_t_value(sshd_t_out: str, key: str) -> str:
    # sshd -T output looks like: "ciphers ..." / "macs ..." / "kexalgorithms ..."
    for line in (sshd_t_out or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == key.lower():
            return parts[1].strip()
    return "unknown"


def run() -> dict:
    path = "/etc/ssh/sshd_config"
    conf = _read_file(path)

    if not conf:
        return {
            "ssh_ciphers": make_error("cannot read sshd_config", path),
            "ssh_macs": make_error("cannot read sshd_config", path),
            "ssh_kex_algorithms": make_error("cannot read sshd_config", path),
            "sshd_effective_ciphers": make_error("cannot read sshd_config", "sshd -T"),
            "sshd_effective_macs": make_error("cannot read sshd_config", "sshd -T"),
            "sshd_effective_kex": make_error("cannot read sshd_config", "sshd -T"),
            "weak_algorithms_detected": make_error("cannot read sshd_config", path),
        }

    # Values explicitly set in sshd_config (or 'default')
    ciphers = _get_config_line(conf, "Ciphers")
    macs = _get_config_line(conf, "MACs")
    kex = _get_config_line(conf, "KexAlgorithms")

    # Effective runtime config (best evidence)
    sshd_t = run_cmd(["sshd", "-T"])
    # If permission denied, try sudo -n (non-interactive)
    stderr_low = (sshd_t.get("stderr") or "").lower()
    if "permission denied" in stderr_low:
        sshd_t = run_cmd(["sudo", "-n", "sshd", "-T"])

    sshd_t_out = (sshd_t.get("stdout") or "").strip()
    if sshd_t.get("returncode", 1) != 0 or not sshd_t_out:
        eff_ciphers = "unknown"
        eff_macs = "unknown"
        eff_kex = "unknown"
        eff_source = sshd_t.get("cmd", "sshd -T")
        eff_evidence = sshd_t.get("stderr") or "sshd -T failed"
    else:
        eff_ciphers = _extract_sshd_t_value(sshd_t_out, "ciphers")
        eff_macs = _extract_sshd_t_value(sshd_t_out, "macs")
        eff_kex = _extract_sshd_t_value(sshd_t_out, "kexalgorithms")
        eff_source = sshd_t.get("cmd", "sshd -T")
        eff_evidence = "sshd -T (effective config captured)"

    combined = f"{ciphers} {macs} {kex} {eff_ciphers} {eff_macs} {eff_kex}"
    weak = _detect_weak_algorithms(combined)

    return {
        "ssh_ciphers": make_check(
            value=ciphers,
            evidence=f"Ciphers {ciphers}",
            source=path
        ),
        "ssh_macs": make_check(
            value=macs,
            evidence=f"MACs {macs}",
            source=path
        ),
        "ssh_kex_algorithms": make_check(
            value=kex,
            evidence=f"KexAlgorithms {kex}",
            source=path
        ),
        "sshd_effective_ciphers": make_check(
            value=eff_ciphers,
            evidence=eff_evidence,
            source=eff_source
        ),
        "sshd_effective_macs": make_check(
            value=eff_macs,
            evidence=eff_evidence,
            source=eff_source
        ),
        "sshd_effective_kex": make_check(
            value=eff_kex,
            evidence=eff_evidence,
            source=eff_source
        ),
        "weak_algorithms_detected": make_check(
            value=weak,
            evidence="; ".join(weak) if weak else "none",
            source="static weak markers (cbc, 3des, sha1, group1/group14)"
        )
    }
