#!/usr/bin/env python3

import subprocess

from utils.colors import Colors
from utils.spinner import Spinner

from config import FINDOMAIN_CONFIG, TIMEOUT_DEFAULT


def run_findomain(domain):
    spinner = Spinner("Running findomain...")
    spinner.start()

    try:
        cmd = ["findomain", "-t", domain, "-q"]

        if FINDOMAIN_CONFIG:
            cmd.extend(["--config", FINDOMAIN_CONFIG])

        result = subprocess.run(
            cmd,
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
            print(f"[{Colors.RED}FAI{Colors.RESET}] Running findomain... 0 found")
            return []

    except subprocess.TimeoutExpired:
        spinner.stop()
        print(f"[{Colors.ORANGE}WRN{Colors.RESET}] Running findomain... Timeout")
        return []
    except Exception as e:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] Running findomain... {e}")
        return []
