#!/usr/bin/env python3

import sys

import psycopg2

from config import DATABASE_URL
from utils.colors import Colors


def get_db_connection():
    if not DATABASE_URL:
        print(f"[{Colors.RED}ERR{Colors.RESET}] DATABASE_URL environment variable not set")
        print(f"[{Colors.CYAN}INF{Colors.RESET}] Set in config file: DATABASE_URL=postgresql://user:password@localhost:5432/subenum")
        sys.exit(1)

    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except psycopg2.OperationalError as e:
        print(f"[{Colors.RED}ERR{Colors.RESET}] Database connection failed: {e}")
        print(f"[{Colors.YELLOW}TIP{Colors.RESET}] Start container: docker-compose up -d")
        sys.exit(1)
    except Exception as e:
        print(f"[{Colors.RED}ERR{Colors.RESET}] Unexpected error: {e}")
        sys.exit(1)
