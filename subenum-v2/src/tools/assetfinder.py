#!/usr/bin/env python3

import subprocess

from config import TIMEOUT_DEFAULT
from utils.colors import Colors
from utils.spinner import Spinner


def run_assetfinder(domain, no_spinner=False):
    spinner = Spinner("Running subfinder...", disabled=no_spinner)
    spinner.start()

    try:
        result = subprocess.run(
            ["assetfinder", "-subs-only", domain],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_DEFAULT,
        )

        spinner.stop()

        domains = [d.strip() for d in result.stdout.split("\n") if d.strip()]

        if domains:
            print(
                f"[{Colors.GREEN}SUC{Colors.RESET}] Running assetfinder... {len(domains)} found"
            )
            return domains
        else:
            print(f"[{Colors.RED}FAI{Colors.RESET}] Running assetfinder... 0 found")
            return []

    except subprocess.TimeoutExpired:
        spinner.stop()
        print(f"[{Colors.ORANGE}WRN{Colors.RESET}] Running assetfinder... Timeout")
        return []
    except Exception as e:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] Running assetfinder... {e}")
        return []
