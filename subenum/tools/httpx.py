#!/usr/bin/env python3

import subprocess

from utils.colors import Colors
from utils.spinner import Spinner

TIMEOUT_HTTPX = 1800


def resolve_domains_httpx(raw_domains_file, output_file):
    spinner = Spinner("Resolving subdomains...")
    spinner.start()

    try:
        cmd = f"cat {raw_domains_file} | httpx -silent -nc -o {output_file}"
        subprocess.run(
            cmd,
            shell=True,
            timeout=TIMEOUT_HTTPX,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        spinner.stop()

        with open(output_file, "r") as f:
            resolved = [line.strip() for line in f if line.strip()]

        if resolved:
            print(
                f"[{Colors.GREEN}SUC{Colors.RESET}] Resolving subdomains... {len(resolved)} resolved"
            )
            return resolved
        else:
            print(
                f"[{Colors.RED}FAI{Colors.RESET}] Resolving subdomains... 0 resolved"
            )
            return []

    except subprocess.TimeoutExpired:
        spinner.stop()
        print(f"[{Colors.ORANGE}WRN{Colors.RESET}] Resolving subdomains... Timeout")
        return []
    except Exception as e:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] Resolving subdomains... {e}")
        return []
