#!/usr/bin/env python3

import os

# Database connection
DATABASE_URL = "postgresql://subenum:subenum@localhost:5432/subenum"

# Tool timeouts in seconds
TIMEOUT_DEFAULT = 900
TIMEOUT_SHUFFLEDNS = 3600
TIMEOUT_PORTSCAN = 3600
TIMEOUT_SCREENSHOTS = 7200

# Chaos API key
CHAOS_API_KEY = os.environ.get("CHAOS_API_KEY")

# Default wordlists and resolvers paths
RESOLVERS = "/opt/resolvers.txt"
SUBDOMAINS_WORDLIST = "/opt/subdomains.txt"

