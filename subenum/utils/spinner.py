#!/usr/bin/env python3

import sys
import threading
import time

from .colors import Colors


class Spinner:
    def __init__(self, message="Processing"):
        self.spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.message = message
        self.running = False
        self.thread = None

    def spin(self):
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()

        idx = 0
        while self.running:
            sys.stdout.write(
                f"\r\033[K{Colors.CYAN}{self.spinner[idx]}{Colors.RESET} {self.message}"
            )
            sys.stdout.flush()
            idx = (idx + 1) % len(self.spinner)
            time.sleep(0.1)

        sys.stdout.write("\r\033[K")
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.spin, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
