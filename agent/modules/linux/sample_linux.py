from agent.modules.linux import (
    logging_checks,
    firewall_checks,
    access_control,
    ports_checks,
    asset_config,
    crypto_checks,
    backup_checks,
)


def run() -> dict:
    # Merge base access_control results with extra checks (AC-LNX-03, AC-LNX-04)
    ac_results = access_control.run()
    ac_extra = access_control.run_extra()
    ac_results.update(ac_extra)

    # Merge base logging results with logrotate check (LOG-LNX-03)
    log_results = logging_checks.run()
    log_extra = logging_checks.run_logrotate_check()
    log_results.update(log_extra)

    return {
        "logging": log_results,
        "firewall": firewall_checks.run(),
        "access_control": ac_results,
        "ports": ports_checks.run(),
        "asset": asset_config.run(),
        "crypto": crypto_checks.run(),
        "backup": backup_checks.run(),
    }