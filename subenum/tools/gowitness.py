#!/usr/bin/env python3

import os
import subprocess

from utils.colors import Colors
from utils.spinner import Spinner

TIMEOUT_SCREENSHOTS = 7200


def run_screenshots(domains_file, output_dir):
    if not os.path.exists(domains_file):
        print(
            f"[{Colors.RED}ERR{Colors.RESET}] Taking screenshots... Domains file not found"
        )
        return False

    spinner = Spinner("Taking screenshots...")
    spinner.start()

    try:
        cmd = [
            "gowitness",
            "scan",
            "file",
            "-f",
            os.path.abspath(domains_file),
            "--write-none",
        ]
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=TIMEOUT_SCREENSHOTS,
            cwd=output_dir,
        )

        spinner.stop()
        print(f"[{Colors.GREEN}SUC{Colors.RESET}] Taking screenshots... Finished")
        return True

    except subprocess.TimeoutExpired:
        spinner.stop()
        print(f"[{Colors.ORANGE}WRN{Colors.RESET}] Taking screenshots... Timeout")
        return False
    except Exception as e:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] Taking screenshots... {e}")
        return False
