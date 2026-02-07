from agent.utils.runner import run_cmd
from agent.utils.result import make_check


def _shorten(text: str, max_lines: int = 20) -> str:
    lines = (text or "").splitlines()
    return "\n".join(lines[:max_lines]).strip()


def run() -> dict:
    raw = run_cmd(["ss", "-tuln"])
    stdout = raw.get("stdout", "") or ""
    stderr = raw.get("stderr", "") or ""

    evidence = stdout if stdout.strip() else stderr
    evidence = _shorten(evidence, 20)

    return {
        "listening_ports": make_check(
            value="captured",
            evidence=evidence,
            source=raw.get("cmd", "ss -tuln")
        )
    }
