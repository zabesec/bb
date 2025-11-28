#!/usr/bin/env python3

import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import yaml

from db.connection import get_db_connection


def load_config():
    config_paths = [
        "/app/config.yml",
        "/app/src/config.yml",
        "/root/.config/config.yml",
        os.path.join(os.path.dirname(__file__), "..", "config.yml"),
        "config.yml"
    ]

    for config_path in config_paths:
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    return yaml.safe_load(f)
            except Exception as e:
                print(f"[SCHEDULER] Error loading config from {config_path}: {e}")

    return None


def get_targets_from_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT target FROM scans ORDER BY target")
        targets = [row[0] for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        return targets
    except Exception as e:
        print(f"[SCHEDULER] Error fetching targets from database: {e}")
        return []


def run_scan(target):
    if not target:
        print("[SCHEDULER] No target provided, skipping scan")
        return 1

    script_path = Path(__file__).parent / "subenum.py"
    print(f"[SCHEDULER] Starting scan for {target} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    result = subprocess.run(
        [sys.executable, str(script_path), "-sd", "-d", target],
        stdout=sys.stdout,
        stderr=sys.stderr
    )

    if result.returncode == 0:
        print(f"[SCHEDULER] Completed scan for {target}")
    else:
        print(f"[SCHEDULER] Failed scan for {target} (exit code {result.returncode})")

    return result.returncode


def get_next_run_time(schedule_times):
    now = datetime.now()
    current_time = now.strftime("%H:%M")

    for scheduled_time in sorted(schedule_times):
        if scheduled_time > current_time:
            hour, minute = map(int, scheduled_time.split(":"))
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            return next_run

    hour, minute = map(int, sorted(schedule_times)[0].split(":"))
    next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    from datetime import timedelta
    next_run = next_run + timedelta(days=1)
    return next_run


def main():
    print("[SCHEDULER] Subdomain Enumeration Scheduler Started")

    while True:
        print(f"[SCHEDULER] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Loading configuration...")
        config = load_config()

        if not config:
            print("[SCHEDULER] No config file found. Waiting 5 minutes...")
            time.sleep(300)
            continue

        if not config.get("scheduler", {}).get("enabled"):
            print("[SCHEDULER] Scheduler is disabled in config.yml")
            print("[SCHEDULER] Waiting 5 minutes...")
            time.sleep(300)
            continue

        schedule_config = config["scheduler"]
        schedule_times = schedule_config.get("times", ["00:00"])
        config_targets = schedule_config.get("targets", [])

        if config_targets and len(config_targets) > 0:
            targets = config_targets
            print(f"[SCHEDULER] Targets from config: {', '.join(targets)}")
        else:
            targets = get_targets_from_db()
            if targets:
                print(f"[SCHEDULER] Targets from database: {', '.join(targets)}")

        if not targets:
            print("[SCHEDULER] No targets found in config or database")
            print("[SCHEDULER] Waiting 5 minutes before checking again...")
            time.sleep(300)
            continue

        notifications = config.get("notifications", {})
        discord_enabled = notifications.get("discord", {}).get("enabled", False)

        print(f"[SCHEDULER] Schedule times: {', '.join(sorted(schedule_times))}")
        print(f"[SCHEDULER] Target count: {len(targets)}")
        print(f"[SCHEDULER] Discord notifications: {'ENABLED' if discord_enabled else 'DISABLED'}")

        next_run = get_next_run_time(schedule_times)
        now = datetime.now()
        sleep_seconds = (next_run - now).total_seconds()

        print(f"[SCHEDULER] Next scan scheduled: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[SCHEDULER] Waiting {sleep_seconds:.0f} seconds ({sleep_seconds/3600:.1f} hours)...")

        remaining = sleep_seconds
        check_interval = 300

        while remaining > 0:
            if remaining <= check_interval:
                time.sleep(remaining)
                break

            time.sleep(check_interval)
            remaining -= check_interval
            hours_left = remaining / 3600
            print(f"[SCHEDULER] Still waiting... {hours_left:.1f} hours until next scan")

        print(f"[SCHEDULER] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Scan time reached!")
        print("[SCHEDULER] Reloading config before starting scans...")

        config = load_config()
        if not config or not config.get("scheduler", {}).get("enabled"):
            print("[SCHEDULER] Scheduler was disabled, skipping this cycle")
            continue

        config_targets = config.get("scheduler", {}).get("targets", [])
        if config_targets:
            targets = config_targets
        else:
            targets = get_targets_from_db()

        if not targets:
            print("[SCHEDULER] No targets found, skipping this cycle")
            continue

        print(f"[SCHEDULER] Starting scan cycle for {len(targets)} target(s)")

        success_count = 0
        fail_count = 0
        start_time = time.time()

        for i, target in enumerate(targets, 1):
            print(f"[SCHEDULER] [{i}/{len(targets)}] Scanning: {target}")
            result = run_scan(target)
            if result == 0:
                success_count += 1
            else:
                fail_count += 1

            if i < len(targets):
                time.sleep(10)

        total_duration = time.time() - start_time

        print(f"[SCHEDULER] Scan cycle completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[SCHEDULER] Duration: {total_duration/60:.1f} minutes")
        print(f"[SCHEDULER] Results: {success_count} succeeded, {fail_count} failed")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[SCHEDULER] Stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[SCHEDULER] Fatal error: {e}")
        sys.exit(1)
