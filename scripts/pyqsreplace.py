#!/usr/bin/env python3

import secrets
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <domain>", file=sys.stderr)
    sys.exit(1)

domain = sys.argv[1]

for line in sys.stdin:
    url = line.strip()
    if not url:
        continue

    uid = secrets.token_hex(3)  # 6-char ID

    parts = urlsplit(url)
    if not parts.query:
        print(url)
        continue

    new_query = urlencode(
        [
            (k, f"http://{uid}.{domain}")
            for k, _ in parse_qsl(parts.query, keep_blank_values=True)
        ]
    )

    print(
        urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
    )
