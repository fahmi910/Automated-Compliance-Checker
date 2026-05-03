from agent.modules.windows import (
    firewall_checks,
    logging_checks,
    access_control,
    update_checks,
    av_checks,
    asset_checks,
    backup_checks,
    crypto_checks,
)


def run() -> dict:
    # Merge base access_control results with guest account check (AC-WINSVR-02 / AC-W10-02)
    ac_results = access_control.run()
    ac_extra = access_control.run_guest_check()
    ac_results.update(ac_extra)

    return {
        "firewall": firewall_checks.run(),
        "logging": logging_checks.run(),
        "access_control": ac_results,
        "updates": update_checks.run(),
        "antivirus": av_checks.run(),
        "assets": asset_checks.run(),
        "backup": backup_checks.run(),
        "crypto": crypto_checks.run(),
    }