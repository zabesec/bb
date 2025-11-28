#!/usr/bin/env python3

from db.operations import (
    get_all_known_domains,
    get_current_scan_domains,
    get_previous_scan_domains,
    mark_domains_inactive,
    update_scan_stats,
)
from utils.colors import Colors
from utils.notifications import send_discord_notification, should_notify


def generate_diff_report(conn, scan_id, target, config=None):
    current_domains = get_current_scan_domains(conn, scan_id)
    total_found = len(current_domains)
    print(
        f"[{Colors.GREEN}SUC{Colors.RESET}] Total unique: {total_found} domains found"
    )

    prev_domains = get_previous_scan_domains(conn, target)
    if prev_domains is not None:
        all_known = get_all_known_domains(conn, target)
        truly_new = current_domains - all_known
        reappeared = current_domains & (all_known - prev_domains)
        disappeared = prev_domains - current_domains

        print(
            f"[{Colors.CYAN}INF{Colors.RESET}] Previous scan: {len(prev_domains)} domains found"
        )

        if truly_new:
            print(
                f"\n[{Colors.GREEN}NEW{Colors.RESET}] {len(truly_new)} new domains found"
            )
            for d in sorted(truly_new)[:20]:
                print(f"  {Colors.GREEN}+{Colors.RESET} {d}")
            if len(truly_new) > 20:
                print(f"  ... and {len(truly_new) - 20} more")

        if reappeared:
            print(
                f"\n[{Colors.DIM}{Colors.GREEN}REA{Colors.RESET}] {len(reappeared)} domains found again"
            )
            for d in sorted(reappeared)[:10]:
                print(f"  {Colors.CYAN}*{Colors.RESET} {d}")
            if len(reappeared) > 10:
                print(f"  ... and {len(reappeared) - 10} more")

        if not truly_new and not reappeared:
            print(f"[{Colors.CYAN}INF{Colors.RESET}] No new domains found.")

        if disappeared:
            print(
                f"\n[{Colors.ORANGE}GON{Colors.RESET}] {len(disappeared)} domains no longer found"
            )
            for d in sorted(disappeared)[:10]:
                print(f"  {Colors.ORANGE}-{Colors.RESET} {d}")
            if len(disappeared) > 10:
                print(f"  ... and {len(disappeared) - 10} more")
            mark_domains_inactive(conn, disappeared, target)

        if config and should_notify(
            config.get("notifications", {}), truly_new, reappeared
        ):
            webhook_url = config["notifications"]["discord"]["webhook_url"]
            send_discord_notification(
                webhook_url=webhook_url,
                target=target,
                scan_id=scan_id,
                truly_new=truly_new,
                reappeared=(
                    reappeared
                    if config["notifications"]["discord"].get("notify_on_reappeared")
                    else None
                ),
                total_found=total_found,
            )

        update_scan_stats(conn, scan_id, total_found, len(truly_new))
        return len(truly_new)
    else:
        update_scan_stats(conn, scan_id, total_found, total_found)

        if config and (truly_new := current_domains):
            notify_config = config.get("notifications", {})
            if notify_config.get("discord", {}).get("enabled") and notify_config[
                "discord"
            ].get("notify_on_new"):
                webhook_url = notify_config["discord"]["webhook_url"]
                send_discord_notification(
                    webhook_url=webhook_url,
                    target=target,
                    scan_id=scan_id,
                    truly_new=truly_new,
                    total_found=total_found,
                )

        return total_found
