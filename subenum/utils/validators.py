#!/usr/bin/env python3

import os
import subprocess
import sys

from utils.colors import Colors


def check_tool(tool_name):
    try:
        subprocess.run(
            [tool_name, "-h"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def verify_tools(args):
    required = ["subfinder", "findomain", "assetfinder", "httpx"]
    optional = []

    if args.sd:
        required.append("shuffledns")

    if args.ps:
        required.extend(["dnsx", "naabu"])

    if args.s:
        required.append("gowitness")

    if os.environ.get("CHAOS_API_KEY"):
        if check_tool("chaos"):
            optional.append("chaos")
        else:
            print(
                f"[{Colors.ORANGE}SKIP{Colors.RESET}] chaos (CHAOS_API_KEY set but tool not found)"
            )

    missing = []
    for tool in required:
        if not check_tool(tool):
            missing.append(tool)

    for tool in optional:
        if not check_tool(tool):
            print(f"[{Colors.ORANGE}SKIP{Colors.RESET}] {tool} (optional)")

    if missing:
        print(
            f"[{Colors.RED}ERR{Colors.RESET}] Missing required tools: {', '.join(missing)}"
        )
        sys.exit(1)
