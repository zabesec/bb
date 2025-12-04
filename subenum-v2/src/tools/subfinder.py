#!/usr/bin/env python3

import subprocess

from config import SUBFINDER_CONFIG, TIMEOUT_DEFAULT
from utils.colors import Colors
from utils.spinner import Spinner


def run_subfinder(domain, no_spinner=False):
    spinner = Spinner("Running subfinder...", disabled=no_spinner)
    spinner.start()

    try:
        cmd = ["subfinder", "-silent", "-all", "-recursive", "-d", domain]

        if SUBFINDER_CONFIG:
            cmd.extend(["-pc", SUBFINDER_CONFIG])

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
                f"[{Colors.GREEN}SUC{Colors.RESET}] Running subfinder... {len(domains)} found"
            )
            return domains
        else:
            print(f"[{Colors.RED}FAI{Colors.RESET}] Running subfinder... 0 found")
            return []

    except subprocess.TimeoutExpired:
        spinner.stop()
        print(f"[{Colors.ORANGE}WRN{Colors.RESET}] Running subfinder... Timeout")
        return []
    except Exception as e:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] Running subfinder... {e}")
        return []
