#!/usr/bin/env python3

import argparse
import os
import shutil
import signal
import sys
import tempfile
import time
from pathlib import Path

import yaml

from config import RESOLVERS, SUBDOMAINS_WORDLIST
from db.connection import get_db_connection
from db.operations import (create_scan, is_first_scan, purge_target_data,
                           store_domains_batch, store_open_ports,
                           store_resolutions)
from db.schema import init_database
from reports.diff import generate_diff_report
from reports.export import export_to_files
from tools.assetfinder import run_assetfinder
from tools.chaos import run_chaos
from tools.crtsh import run_crtsh
from tools.findomain import run_findomain
from tools.httpx import resolve_domains_httpx
from tools.naabu import run_port_scan
from tools.shuffledns import run_shuffledns
from tools.subfinder import run_subfinder
from utils.colors import Colors
from utils.validators import verify_tools

START_TIME = None
INTERRUPTED = False


def signal_handler(signum, frame):
    global INTERRUPTED, conn, scan_id
    INTERRUPTED = True
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()

    elapsed = (time.time() - START_TIME) if START_TIME else 0
    print(
        f"\n[{Colors.CYAN}INF{Colors.RESET}] Scan interrupted, cleaning up... {Colors.DIM}({elapsed:.2f}s elapsed){Colors.RESET}\n"
    )

    if "conn" in globals() and conn and "scan_id" in globals() and scan_id:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = %s", (scan_id,))
        conn.commit()
        cursor.close()
        conn.close()

    sys.exit(130)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def print_banner():
    print(
        rf"""{Colors.CYAN}
           _
 ___ _   _| |__   ___ _ __  _   _ _ __ ___
/ __| | | | '_ \ / _ \ '_ \| | | | '_ ` _ \
\__ \ |_| | |_) |  __/ | | | |_| | | | | | |
|___/\__,_|_.__/ \___|_| |_|\__,_|_| |_| |_|
{Colors.RESET}
"""
    )


def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config.yml")
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    return {}


def main():
    global START_TIME, conn, scan_id

    parser = argparse.ArgumentParser(
        description="Subdomain enumeration with database tracking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-d", required=True, metavar="example.com", help="Target domain"
    )
    parser.add_argument(
        "-sd", action="store_true", help="Run DNS bruteforcing with shuffledns"
    )
    parser.add_argument(
        "-r", metavar="resolvers.txt", help="Resolvers file for shuffledns"
    )
    parser.add_argument(
        "-w", metavar="wordlist.txt", help="Wordlist file for shuffledns"
    )
    parser.add_argument("-ps", metavar="WIDTH", help="Port scan: 100, 1000, full")
    parser.add_argument("-o", metavar="output/", help="Output directory")
    parser.add_argument("-export", action="store_true", help="Export results to files")
    parser.add_argument(
        "-purge", action="store_true", help="Purge target's previous data"
    )

    args = parser.parse_args()

    if args.o:
        args.o = args.o.rstrip("/")

    if args.export and not args.o:
        print(f"[{Colors.RED}ERR{Colors.RESET}] -export requires -o (output directory)")
        sys.exit(1)

    print_banner()
    START_TIME = time.time()

    config = load_config()

    conn = get_db_connection()
    init_database(conn)

    if args.purge:
        purged = purge_target_data(conn, args.d)
        print(f"[{Colors.ORANGE}PUR{Colors.RESET}] Scan data for {args.d} erased")

    if args.sd:
        if not args.r:
            args.r = RESOLVERS
        if not args.w:
            args.w = SUBDOMAINS_WORDLIST

        if not os.path.isfile(args.r):
            print(f"[{Colors.RED}ERR{Colors.RESET}] Resolvers file not found: {args.r}")
            conn.close()
            sys.exit(1)
        if not os.path.isfile(args.w):
            print(f"[{Colors.RED}ERR{Colors.RESET}] Wordlist file not found: {args.w}")
            conn.close()
            sys.exit(1)

    if args.ps and args.ps not in ["100", "1000", "full"]:
        print(
            f"[{Colors.RED}ERR{Colors.RESET}] Port scan width must be 100, 1000, or full"
        )
        conn.close()
        sys.exit(1)

    print(f"[{Colors.CYAN}INF{Colors.RESET}] Connecting to database...")
    conn = get_db_connection()
    init_database(conn)

    print(f"[{Colors.CYAN}INF{Colors.RESET}] Checking required tools...")
    verify_tools(args)

    print(f"[{Colors.GREEN}SUC{Colors.RESET}] Ok... proceeding...\n")

    first_scan = is_first_scan(conn, args.d)
    scan_id = create_scan(conn, args.d)

    print(
        f"[{Colors.CYAN}INF{Colors.RESET}] Target: {Colors.BOLD}{args.d}{Colors.RESET} - Scan ID: {scan_id}"
    )

    if args.o:
        output_dir = os.path.abspath(args.o)
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        use_temp = False
    else:
        output_dir = tempfile.mkdtemp(prefix=f"subenum-{scan_id}-")
        use_temp = True

    all_domains = set()

    for tool_func, name in [
        (run_subfinder, "subfinder"),
        (run_findomain, "findomain"),
        (run_assetfinder, "assetfinder"),
        (run_crtsh, "crtsh"),
        (run_chaos, "chaos"),
    ]:
        domains = tool_func(args.d)
        if domains:
            store_domains_batch(conn, scan_id, domains, args.d, name)
            all_domains.update(domains)

    if args.sd:
        domains = run_shuffledns(args.d, args.r, args.w)
        if domains:
            store_domains_batch(conn, scan_id, domains, args.d, "shuffledns")
            all_domains.update(domains)

    total_found = len(all_domains)

    if all_domains:
        raw_domains_file = f"{output_dir}/domains-raw.txt"
        resolved_file = f"{output_dir}/domains-resolved.txt"

        with open(raw_domains_file, "w") as f:
            for domain in sorted(all_domains):
                f.write(f"{domain}\n")

        resolved_urls = resolve_domains_httpx(raw_domains_file, resolved_file)

        if resolved_urls:
            store_resolutions(conn, resolved_urls, args.d)

            if args.ps:
                save_port_file = args.o
                port_results = run_port_scan(
                    resolved_file, args.r, args.ps, args.o if save_port_file else None
                )
                if port_results:
                    store_open_ports(conn, scan_id, port_results, args.d)

        if not args.o:
            for file in (raw_domains_file, resolved_file):
                if os.path.exists(file):
                    os.remove(file)

    generate_diff_report(conn, scan_id, args.d, config)

    if args.export or (first_scan and args.o):
        export_to_files(conn, scan_id, args.o or output_dir)

    conn.close()

    if use_temp and os.path.exists(output_dir):
        shutil.rmtree(output_dir, ignore_errors=True)

    elapsed = time.time() - START_TIME
    print(
        f"\n[{Colors.CYAN}INF{Colors.RESET}] Scan finished {Colors.DIM}({elapsed:.2f}s time elapsed){Colors.RESET}"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()
        print(f"\n[{Colors.ORANGE}WRN{Colors.RESET}] Interrupted by user")
        sys.exit(0)
