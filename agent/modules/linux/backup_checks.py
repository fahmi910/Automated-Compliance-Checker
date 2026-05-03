import os
from agent.utils.runner import run_cmd
from agent.utils.result import make_check, make_error


def _cmd_ok(cmd: list) -> tuple:
    """Run a command, return (success, stdout)."""
    raw = run_cmd(cmd)
    stdout = (raw.get("stdout") or "").strip()
    rc = raw.get("returncode", -1)
    return rc == 0, stdout, raw.get("cmd", "")


def _which(tool: str) -> bool:
    """Check if a binary exists on PATH."""
    ok, _, _ = _cmd_ok(["which", tool])
    return ok


def _file_exists(path: str) -> bool:
    return os.path.exists(path)


def _read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def run() -> dict:
    results = {}

    # ----------------------------------------------------------------
    # 1) Backup tools installed
    #    Check for common Linux backup utilities: rsync, tar, timeshift, borgbackup, duplicati
    # ----------------------------------------------------------------
    tools_found = []
    tools_checked = ["rsync", "timeshift", "borg", "duplicati", "bacula-director"]
    for tool in tools_checked:
        if _which(tool):
            tools_found.append(tool)

    results["backup_tools_installed"] = make_check(
        value=tools_found if tools_found else [],
        evidence=f"Found: {', '.join(tools_found)}" if tools_found else "None of checked tools found: " + ", ".join(tools_checked),
        source="which rsync timeshift borg duplicati bacula-director",
    )

    # ----------------------------------------------------------------
    # 2) Cron-based backup jobs
    #    Look for backup-related entries in system crontabs and /etc/cron.*
    # ----------------------------------------------------------------
    backup_keywords = ["rsync", "backup", "tar", "borg", "timeshift", "duplicati", "dump"]

    cron_hits = []

    # /etc/crontab
    crontab_text = _read_file("/etc/crontab")
    for line in crontab_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        low = stripped.lower()
        if any(kw in low for kw in backup_keywords):
            cron_hits.append(f"/etc/crontab: {stripped[:120]}")

    # /etc/cron.d/*, /etc/cron.daily/*, /etc/cron.weekly/*
    for cron_dir in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"]:
        if not _file_exists(cron_dir):
            continue
        try:
            for fname in os.listdir(cron_dir):
                fpath = os.path.join(cron_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                content = _read_file(fpath)
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("#") or not stripped:
                        continue
                    low = stripped.lower()
                    if any(kw in low for kw in backup_keywords):
                        cron_hits.append(f"{fpath}: {stripped[:120]}")
                        break  # one hit per file is enough
        except Exception:
            pass

    # root crontab (-l may fail if no crontab set)
    ok_cron, cron_stdout, cron_cmd = _cmd_ok(["bash", "-lc", "crontab -l 2>/dev/null"])
    if cron_stdout:
        for line in cron_stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            low = stripped.lower()
            if any(kw in low for kw in backup_keywords):
                cron_hits.append(f"root crontab: {stripped[:120]}")

    results["backup_cron_jobs"] = make_check(
        value=cron_hits if cron_hits else [],
        evidence=("\n".join(cron_hits[:10]) if cron_hits else "No backup-related cron entries found"),
        source="crontab scan (/etc/crontab, /etc/cron.d, /etc/cron.daily, /etc/cron.weekly, crontab -l)",
    )

    # ----------------------------------------------------------------
    # 3) Systemd timer-based backup jobs
    #    Look for active/enabled timers with backup-related names
    # ----------------------------------------------------------------
    ok_timers, timers_stdout, timers_cmd = _cmd_ok(
        ["systemctl", "list-timers", "--all", "--no-pager"]
    )

    timer_hits = []
    if ok_timers and timers_stdout:
        for line in timers_stdout.splitlines():
            low = line.lower()
            if any(kw in low for kw in backup_keywords):
                timer_hits.append(line.strip()[:160])

    results["backup_systemd_timers"] = make_check(
        value=timer_hits if timer_hits else [],
        evidence=("\n".join(timer_hits[:10]) if timer_hits else "No backup-related systemd timers found"),
        source=timers_cmd or "systemctl list-timers --all",
    )

    # ----------------------------------------------------------------
    # 4) Timeshift configuration (if installed)
    #    Timeshift stores its config in /etc/timeshift/timeshift.json
    # ----------------------------------------------------------------
    timeshift_cfg_path = "/etc/timeshift/timeshift.json"
    if _file_exists(timeshift_cfg_path):
        cfg_text = _read_file(timeshift_cfg_path)
        # Extract schedule type from json without importing json module at module level
        schedule_value = "configured"
        try:
            import json as _json
            cfg = _json.loads(cfg_text)
            schedule_type = cfg.get("schedule_type", "unknown")
            backup_device = cfg.get("backup_device_uuid", "unknown")
            schedule_value = f"type={schedule_type}, device_uuid={backup_device}"
        except Exception:
            schedule_value = "configured (parse error)"

        results["timeshift_config"] = make_check(
            value=schedule_value,
            evidence=cfg_text[:300] if cfg_text else "empty config",
            source=timeshift_cfg_path,
        )
    else:
        results["timeshift_config"] = make_check(
            value="not_found",
            evidence=f"{timeshift_cfg_path} does not exist",
            source=timeshift_cfg_path,
        )

    # ----------------------------------------------------------------
    # 5) rsync recent usage (check if rsync has been run recently via log)
    # ----------------------------------------------------------------
    ok_rsync_log, rsync_log_stdout, rsync_cmd = _cmd_ok(
        ["bash", "-lc", "grep -i 'rsync' /var/log/syslog 2>/dev/null | tail -n 3"]
    )
    rsync_evidence = rsync_log_stdout.strip() if rsync_log_stdout else "no rsync entries in syslog"

    results["rsync_recent_log"] = make_check(
        value="found" if rsync_log_stdout else "none",
        evidence=rsync_evidence[:300],
        source=rsync_cmd or "grep rsync /var/log/syslog",
    )

    return results