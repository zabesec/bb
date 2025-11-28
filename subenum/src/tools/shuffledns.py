#!/usr/bin/env python3

import os
import subprocess

from utils.colors import Colors
from utils.spinner import Spinner

TIMEOUT_SHUFFLEDNS = 3600


def run_shuffledns(domain, resolvers, wordlist):
    if not os.path.exists(resolvers):
        print(
            f"[{Colors.RED}ERR{Colors.RESET}] Running shuffledns... Resolvers file not found"
        )
        return []

    if not os.path.exists(wordlist):
        print(
            f"[{Colors.RED}ERR{Colors.RESET}] Running shuffledns... Wordlist file not found"
        )
        return []

    spinner = Spinner("Running shuffledns...")
    spinner.start()

    try:
        result = subprocess.run(
            [
                "shuffledns",
                "-d",
                domain,
                "-r",
                resolvers,
                "-w",
                wordlist,
                "-mode",
                "bruteforce",
                "-silent",
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SHUFFLEDNS,
        )

        spinner.stop()

        domains = [d.strip() for d in result.stdout.split("\n") if d.strip()]

        if domains:
            print(
                f"[{Colors.GREEN}SUC{Colors.RESET}] Running shuffledns... {len(domains)} found"
            )
            return domains
        else:
            print(f"[{Colors.RED}FAI{Colors.RESET}] Running shuffledns... 0 found")
            return []

    except subprocess.TimeoutExpired:
        spinner.stop()
        print(
            f"[{Colors.ORANGE}WRN{Colors.RESET}] Running shuffledns... Timeout (skipped)"
        )
        return []
    except Exception as e:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] Running shuffledns... {e}")
        return []
