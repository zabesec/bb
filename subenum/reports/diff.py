#!/usr/bin/env python3

from db.operations import (get_all_known_domains, get_current_scan_domains,
                           get_previous_scan_domains, mark_domains_inactive,
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

        update_scan_stats(conn, scan_id, total_found, len(truly_new))
        return len(truly_new)
    else:
        update_scan_stats(conn, scan_id, total_found, total_found)
        return total_found
