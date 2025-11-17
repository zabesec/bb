#!/usr/bin/env python3

import json
import time
import urllib.error
import urllib.request

from utils.colors import Colors
from utils.spinner import Spinner


def run_crtsh(domain):
    spinner = Spinner("Running crt.sh...")
    spinner.start()

    max_retries = 3
    domains = set()

    for attempt in range(max_retries):
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

            with urllib.request.urlopen(req, timeout=10) as response:
                data = response.read().decode("utf-8")

                if data:
                    results = json.loads(data)
                    for entry in results:
                        if "common_name" in entry and entry["common_name"]:
                            domains.add(entry["common_name"].lower())
                        if "name_value" in entry and entry["name_value"]:
                            for name in entry["name_value"].split("\n"):
                                if name.strip():
                                    domains.add(name.strip().lower())
                    break

        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            json.JSONDecodeError,
            Exception,
        ) as e:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            else:
                spinner.stop()
                print(
                    f"[{Colors.RED}FAIL{Colors.RESET}] Running crt.sh... Failed after {max_retries} retries"
                )
                return []

    spinner.stop()

    if domains:
        domains_list = sorted(domains)
        print(
            f"[{Colors.GREEN}SUC{Colors.RESET}] Running crt.sh... {len(domains_list)} found"
        )
        return domains_list
    else:
        print(f"[{Colors.RED}FAIL{Colors.RESET}] Running crt.sh... 0 found")
        return []
