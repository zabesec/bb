#!/usr/bin/env python3

import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
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
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"[{timestamp}] Error loading config from {config_path}: {e}")

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
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] Error fetching targets from database: {e}")
        return []


def run_scan(target):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if not target:
        print(f"[{timestamp}] No target provided, skipping scan")
        return 1

    script_path = Path(__file__).parent / "subenum.py"
    print(f"[{timestamp}] Starting scan for {target}")

    result = subprocess.run(
        [sys.executable, str(script_path), "-ns", "-sd", "-d", target],
        stdout=sys.stdout,
        stderr=sys.stderr
    )

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if result.returncode == 0:
        print(f"[{timestamp}] Completed scan for {target}")
    else:
        print(f"[{timestamp}] Failed scan for {target} (exit code {result.returncode})")

    return result.returncode


def get_next_run_time(schedule_times):
    now = datetime.now()
    current_time = now.time()

    schedule_time_objects = []
    for scheduled_time in schedule_times:
        hour, minute = map(int, scheduled_time.split(":"))
        schedule_time_objects.append((hour, minute))

    schedule_time_objects.sort()

    for hour, minute in schedule_time_objects:
        scheduled = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if scheduled > now:
            return scheduled

    hour, minute = schedule_time_objects[0]
    next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    next_run = next_run + timedelta(days=1)
    return next_run


def main():
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] Subdomain Enumeration Scheduler Started")

    while True:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] Loading configuration...")
        config = load_config()

        if not config:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] No config file found. Waiting 5 minutes...")
            time.sleep(300)
            continue

        if not config.get("scheduler", {}).get("enabled"):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] Scheduler is disabled in config.yml")
            print(f"[{timestamp}] Waiting 5 minutes...")
            time.sleep(300)
            continue

        schedule_config = config["scheduler"]
        schedule_times = schedule_config.get("times", ["00:00"])
        config_targets = schedule_config.get("targets", [])

        if config_targets and len(config_targets) > 0:
            targets = config_targets
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] Targets from config: {', '.join(targets)}")
        else:
            targets = get_targets_from_db()
            if targets:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"[{timestamp}] Targets from database: {', '.join(targets)}")

        if not targets:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] No targets found in config or database")
            print(f"[{timestamp}] Waiting 5 minutes before checking again...")
            time.sleep(300)
            continue

        notifications = config.get("notifications", {})
        discord_enabled = notifications.get("discord", {}).get("enabled", False)

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] Schedule times: {', '.join(sorted(schedule_times))}")
        print(f"[{timestamp}] Target count: {len(targets)}")
        print(f"[{timestamp}] Discord notifications: {'ENABLED' if discord_enabled else 'DISABLED'}")

        next_run = get_next_run_time(schedule_times)
        now = datetime.now()
        sleep_seconds = (next_run - now).total_seconds()

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] Next scan scheduled: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[{timestamp}] Waiting {sleep_seconds:.0f} seconds ({sleep_seconds/3600:.1f} hours)...")

        remaining = sleep_seconds
        check_interval = 300

        while remaining > 0:
            if remaining <= check_interval:
                time.sleep(remaining)
                break

            time.sleep(check_interval)
            remaining -= check_interval
            hours_left = remaining / 3600
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] Still waiting... {hours_left:.1f} hours until next scan")

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] Scan time reached!")
        print(f"[{timestamp}] Reloading config before starting scans...")

        config = load_config()
        if not config or not config.get("scheduler", {}).get("enabled"):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] Scheduler was disabled, skipping this cycle")
            continue

        config_targets = config.get("scheduler", {}).get("targets", [])
        if config_targets:
            targets = config_targets
        else:
            targets = get_targets_from_db()

        if not targets:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] No targets found, skipping this cycle")
            continue

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] Starting scan cycle for {len(targets)} target(s)")

        success_count = 0
        fail_count = 0
        start_time = time.time()

        for i, target in enumerate(targets, 1):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] [{i}/{len(targets)}] Scanning: {target}")
            result = run_scan(target)
            if result == 0:
                success_count += 1
            else:
                fail_count += 1

            if i < len(targets):
                time.sleep(10)

        total_duration = time.time() - start_time

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] Scan cycle completed")
        print(f"[{timestamp}] Duration: {total_duration/60:.1f} minutes")
        print(f"[{timestamp}] Results: {success_count} succeeded, {fail_count} failed")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"\n[{timestamp}] Stopped by user")
        sys.exit(0)
    except Exception as e:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"\n[{timestamp}] Fatal error: {e}")
        sys.exit(1)
