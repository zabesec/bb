#!/usr/bin/env python3

from pathlib import Path

import yaml


def load_yaml_config():
    config_path = Path(__file__).parent / "config.yml"
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f)
    return {}


config = load_yaml_config()

DATABASE_URL = config.get(
    "database_url", "postgresql://subenum:subenum@subenum-db:5432/subenum"
)

timeouts_cfg = config.get("timeouts", {})
TIMEOUT_DEFAULT = timeouts_cfg.get("default", 900)
TIMEOUT_SHUFFLEDNS = timeouts_cfg.get("shuffledns", 3600)
TIMEOUT_PORTSCAN = timeouts_cfg.get("portscan", 3600)

CHAOS_API_KEY = config.get("chaos_api_key", "")

paths_cfg = config.get("paths", {})
RESOLVERS = paths_cfg.get("resolvers", "/opt/zabe/wordlists/resolvers.txt")
SUBDOMAINS_WORDLIST = paths_cfg.get(
    "subdomains_wordlist", "/opt/zabe/wordlists/internal-subdomains.txt"
)

tool_cfg = config.get("tool_config_paths", {})
SUBFINDER_CONFIG = tool_cfg.get("subfinder", "")
FINDOMAIN_CONFIG = tool_cfg.get("findomain", "")
HTTPX_CONFIG = tool_cfg.get("httpx", "")
NAABU_CONFIG = tool_cfg.get("naabu", "")
