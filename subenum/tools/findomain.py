#!/usr/bin/env python3

import subprocess

from config import TIMEOUT_DEFAULT
from utils.colors import Colors
from utils.spinner import Spinner


def run_findomain(domain):
    spinner = Spinner("Running findomain...")
    spinner.start()

    try:
        result = subprocess.run(
            ["findomain", "-t", domain, "-q"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_DEFAULT,
        )

        spinner.stop()

        domains = [d.strip() for d in result.stdout.split("\n") if d.strip()]

        if domains:
            print(
                f"[{Colors.GREEN}SUC{Colors.RESET}] Running findomain... {len(domains)} found"
            )
            return domains
        else:
            print(f"[{Colors.RED}FAIL{Colors.RESET}] Running findomain... 0 found")
            return []

    except subprocess.TimeoutExpired:
        spinner.stop()
        print(f"[{Colors.ORANGE}WRN{Colors.RESET}] Running findomain... Timeout")
        return []
    except Exception as e:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] Running findomain... {e}")
        return []
