from agent.utils.result import make_check, make_error


def _read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def _get_config_line(conf_text: str, key: str) -> str:
    # Get last non-comment occurrence
    value = "not_set"
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


def run() -> dict:
    path = "/etc/ssh/sshd_config"
    conf = _read_file(path)

    if not conf:
        return {
            "ssh_ciphers": make_error("cannot read sshd_config", path),
            "ssh_macs": make_error("cannot read sshd_config", path),
            "ssh_kex_algorithms": make_error("cannot read sshd_config", path),
            "weak_algorithms_detected": make_error("cannot read sshd_config", path),
        }

    ciphers = _get_config_line(conf, "Ciphers")
    macs = _get_config_line(conf, "MACs")
    kex = _get_config_line(conf, "KexAlgorithms")

    combined = f"{ciphers} {macs} {kex}"
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
        "weak_algorithms_detected": make_check(
            value=weak,
            evidence="; ".join(weak) if weak else "none",
            source="static weak markers (cbc, 3des, sha1, group1/group14)"
        )
    }
