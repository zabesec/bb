#!/usr/bin/env python3

from db.operations import (get_current_scan_domains, get_previous_scan_domains,
                           update_scan_stats)
from utils.colors import Colors


def generate_diff_report(conn, scan_id, target):
    current_domains = get_current_scan_domains(conn, scan_id)
    total_found = len(current_domains)

    print(
        f"[{Colors.GREEN}SUC{Colors.RESET}] Total unique: {total_found} domains found"
    )

    prev_domains = get_previous_scan_domains(conn, target)

    if prev_domains is not None:
        new_domains = current_domains - prev_domains
        disappeared = prev_domains - current_domains

        print(
            f"[{Colors.CYAN}INF{Colors.RESET}] Previous scan: {len(prev_domains)} domains found"
        )

        if new_domains:
            print(
                f"\n[{Colors.GREEN}SUC{Colors.RESET}] {len(new_domains)} new domains discovered!"
            )
            for d in sorted(new_domains)[:20]:
                print(f"  {Colors.GREEN}+{Colors.RESET} {d}")
            if len(new_domains) > 20:
                print(f"  ... and {len(new_domains) - 20} more")
        else:
            print(f"[{Colors.CYAN}INF{Colors.RESET}] No new domains discovered.")

        if disappeared:
            print(
                f"\n[{Colors.ORANGE}WRN{Colors.RESET}] {len(disappeared)} domains no longer found"
            )
            for d in sorted(disappeared)[:10]:
                print(f"  {Colors.ORANGE}-{Colors.RESET} {d}")
            if len(disappeared) > 10:
                print(f"  ... and {len(disappeared) - 10} more")

        update_scan_stats(conn, scan_id, total_found, len(new_domains))
        return len(new_domains)
    else:
        update_scan_stats(conn, scan_id, total_found, total_found)
        return total_found
