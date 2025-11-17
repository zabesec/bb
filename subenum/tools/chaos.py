#!/usr/bin/env python3

import os
import subprocess

from utils.colors import Colors
from utils.spinner import Spinner

TIMEOUT_CHAOS = 900


def run_chaos(domain):
    api_key = os.environ.get('CHAOS_API_KEY')
    if not api_key:
        print(f"[{Colors.ORANGE}SKIP{Colors.RESET}] Running chaos... CHAOS_API_KEY not set")
        return []

    spinner = Spinner("Running chaos...")
    spinner.start()

    try:
        result = subprocess.run(
            ["chaos", "-key", api_key, "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_CHAOS
        )

        spinner.stop()

        domains = [d.strip() for d in result.stdout.split('\n') if d.strip()]

        if domains:
            print(f"[{Colors.GREEN}SUC{Colors.RESET}] Running chaos... {len(domains)} found")
            return domains
        else:
            print(f"[{Colors.RED}FAIL{Colors.RESET}] Running chaos... 0 found")
            return []

    except subprocess.TimeoutExpired:
        spinner.stop()
        print(f"[{Colors.ORANGE}WRN{Colors.RESET}] Running chaos... Timeout")
        return []
    except Exception as e:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] Running chaos... {e}")
        return []
