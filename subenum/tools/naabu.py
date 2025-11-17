#!/usr/bin/env python3

import os
import subprocess

from utils.colors import Colors
from utils.spinner import Spinner

TIMEOUT_PORTSCAN = 3600


def run_port_scan(domains_file, resolvers, width, output_dir=None):
    if not os.path.exists(domains_file):
        print(
            f"[{Colors.RED}ERR{Colors.RESET}] Scanning for open ports... Domains file not found"
        )
        return []

    if width not in ["100", "1000", "full"]:
        print(
            f"[{Colors.RED}ERR{Colors.RESET}] Scanning for open ports... Invalid width"
        )
        return []

    spinner = Spinner("Scanning for open ports...")
    spinner.start()

    try:
        if resolvers and os.path.exists(resolvers):
            cmd = f"cat {domains_file} | dnsx -silent -r {resolvers} -a -resp-only | naabu -silent -tp {width}"
        else:
            cmd = f"cat {domains_file} | dnsx -silent -a -resp-only | naabu -silent -tp {width}"

        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=TIMEOUT_PORTSCAN,
        )

        spinner.stop()

        results = []
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line and ":" in line:
                results.append(line)

        if output_dir and results:
            output_file = f"{output_dir}/open-ports.txt"
            with open(output_file, "w") as f:
                for line in results:
                    f.write(f"{line}\n")

        if results:
            print(
                f"[{Colors.GREEN}SUC{Colors.RESET}] Scanning for open ports... {len(results)} found"
            )
            return results
        else:
            print(
                f"[{Colors.RED}FAIL{Colors.RESET}] Scanning for open ports... 0 open ports"
            )
            return []

    except subprocess.TimeoutExpired:
        spinner.stop()
        print(f"[{Colors.ORANGE}WRN{Colors.RESET}] Scanning for open ports... Timeout")
        return []
    except Exception as e:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] Scanning for open ports... {e}")
        return []
