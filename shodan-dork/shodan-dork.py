import json
import os
import random
import re
import subprocess
import sys
import time

import requests

COOKIES = []
cookie_index = 0
PROGRESS_FILE = "/app/output/progress.json"
SCANNED_FILE = "/app/output/scanned.txt"
TARGETS_FILE = "/app/output/targets.txt"
CHECK_INTERVAL = 14400

SEARCH_QUERIES = [
    {"hash": "2141724739", "name": "Juniper Networks"},
    {
        "query": 'http.component:"Atlassian Confluence" http.status:200',
        "name": "Confluence",
    },
    {"query": 'http.component:"PHP" port:80,443,8080', "name": "PHP CGI Windows"},
    {"query": 'http.title:"Dashboard [Jenkins]"', "name": "Jenkins"},
    {"query": "X-Jenkins port:8080", "name": "Jenkins Alt"},
    {"query": 'http.title:"HugeGraph" port:8080', "name": "HugeGraph Server"},
    {"query": 'product:"OpenSSH" port:22', "name": "OpenSSH RegreSSHion"},
    {"query": 'http.title:"HFS" "Rejetto"', "name": "Rejetto HFS"},
    {"query": 'http.html:"Rejetto" port:80,8080', "name": "Rejetto HFS Alt"},
    {"query": 'http.title:"Fortinet"', "name": "FortiOS Management"},
    {"query": 'http.html:"fortinet" port:443,4433', "name": "Fortinet Devices"},
    {"query": 'http.title:"Ivanti Connect Secure"', "name": "Ivanti Connect Secure"},
    {"query": 'http.html:"Pulse Secure"', "name": "Pulse Secure"},
    {"query": 'http.html:"NetAlertX" port:80,8080', "name": "NetAlertX"},
    {"query": 'http.component:"Next.js" http.status:200', "name": "Next.js Apps"},
    {"query": 'http.html:"__next" port:3000,80,443', "name": "Next.js Apps Alt"},
    {"query": 'http.title:"FortiNAC"', "name": "FortiNAC"},
    {"query": 'http.title:"CrushFTP" -cloudflare', "name": "CrushFTP"},
    {
        "query": 'http.html:"wp-content/plugins/elementor-pro"',
        "name": "WordPress Elementor Pro",
    },
    {"query": 'http.title:"ColdFusion Administrator"', "name": "ColdFusion Admin"},
    {"query": 'http.title:"Apache Tomcat" port:8080,8443', "name": "Tomcat Manager"},
    {"query": 'http.title:"Grafana" -login port:3000', "name": "Grafana"},
    {"query": 'http.title:"SonarQube" -auth', "name": "SonarQube"},
    {"query": 'http.title:"RabbitMQ Management"', "name": "RabbitMQ"},
    {"query": 'http.title:"Kubernetes Dashboard"', "name": "Kubernetes Dashboard"},
    {"query": 'http.html:"webvpn" cisco', "name": "Cisco ASA WebVPN"},
    {"query": '"Microsoft-IIS"', "name": "Microsoft IIS Server"},
    {"query": 'http.title:"httpbin"', "name": "HTTP Bin Server"},
]


def fetch_from_url(url):
    cmd = ["curl", "-s", url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return []
        items = []
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line:
                items.append(line)
        return items
    except Exception as e:
        return []


def load_cookies(cookie_url):
    global COOKIES
    COOKIES = []
    cookies = fetch_from_url(cookie_url)
    if cookies:
        COOKIES.extend(cookies)
        print(f"[-] Loaded {len(cookies)} cookies")
        return True
    return False


def load_progress():
    if os.path.exists(PROGRESS_FILE):
        try:
            with open(PROGRESS_FILE, "r") as f:
                return json.load(f)
        except:
            return {"total_found": 0}
    return {"total_found": 0}


def save_progress(total_found):
    os.makedirs(os.path.dirname(PROGRESS_FILE), exist_ok=True)
    with open(PROGRESS_FILE, "w") as f:
        json.dump({"total_found": total_found}, f)


def load_scanned_targets():
    if os.path.exists(SCANNED_FILE):
        with open(SCANNED_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    return set()


def mark_scanned(target):
    os.makedirs(os.path.dirname(SCANNED_FILE), exist_ok=True)
    with open(SCANNED_FILE, "a") as f:
        f.write(f"{target}\n")


def download_and_save_targets(targets_url):
    print("[-] Fetching targets...")
    targets = fetch_from_url(targets_url)

    if targets:
        os.makedirs(os.path.dirname(TARGETS_FILE), exist_ok=True)
        with open(TARGETS_FILE, "w") as f:
            f.write("\n".join(targets))
        return targets
    return []


def load_local_targets():
    if os.path.exists(TARGETS_FILE):
        with open(TARGETS_FILE, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
        return targets
    return []


def get_next_cookie():
    global cookie_index
    if not COOKIES:
        return None
    cookie = COOKIES[cookie_index]
    cookie_index = (cookie_index + 1) % len(COOKIES)
    return cookie


def scrape_shodan(query_obj, target):
    cookie = get_next_cookie()
    if not cookie:
        return False, None, None

    if "hash" in query_obj:
        search_query = f"http.favicon.hash:{query_obj['hash']} ssl:{target}"
    else:
        search_query = f"{query_obj['query']} ssl:{target}"

    url = f"https://www.shodan.io/search?query={search_query.replace(':', '%3A').replace(' ', '+').replace(chr(34), '%22')}"
    print(f"[-] Target: {target}")
    print(f"[-] Query Type: {query_obj['name']}")
    print(f"[-] Query: {search_query}")
    print(f"[-] URL: {url}")
    print(f"[-] Cookie: {cookie}")

    webhook_url = os.getenv("DISCORD_WEBHOOK_URL")

    cmd = [
        "curl",
        "-s",
        "-H",
        f"Cookie: {cookie}",
        "-H",
        "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:145.0) Gecko/20100101 Firefox/145.0",
        "-H",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        url,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        html = result.stdout
        if not html:
            return False, None, None

        if "rate limit" in html.lower() or "too many requests" in html.lower():
            print(f"[!] RATE LIMITED - Waiting 15 minutes...")
            time.sleep(900)

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            html = result.stdout

            if "rate limit" in html.lower() or "too many requests" in html.lower():
                print(f"[!] STILL RATE LIMITED - Sending alert and stopping...")
                send_discord_alert(
                    webhook_url,
                    "rate_limit",
                    "Still rate limited after 15 minute wait. Stopping script.",
                    target,
                )
                sys.exit(1)

        if "Please log in to use search filters" in html:
            print(f"[!] SESSION EXPIRED - Cookie invalid")
            send_discord_alert(
                webhook_url,
                "session_expired",
                f"Cookie session expired or invalid:\n`{cookie[:50]}...`",
                target,
            )
            print(f"[!] STOPPING SCRIPT - Fix cookie and restart")
            sys.exit(1)

        if "blocked" in html.lower() or "captcha" in html.lower():
            print(f"[!] BLOCKED - IP or cookie flagged")
            send_discord_alert(
                webhook_url,
                "blocked",
                "IP or cookie has been blocked/flagged by Shodan",
                target,
            )
            print(f"[!] STOPPING SCRIPT - Check IP/cookie and restart")
            sys.exit(1)

        if "No results found" in html:
            return False, url, None

        if '<div class="result">' in html or "search-result" in html:
            return True, url, query_obj["name"]

        return False, url, None
    except:
        return False, None, None


def send_discord_webhook(webhook_url, target, search_url, query_name):
    embed = {
        "title": "🎯 Results Found",
        "description": f"**Target:** `{target}`\n**Query Type:** {query_name}",
        "fields": [
            {
                "name": "Search URL",
                "value": f"[View on Shodan]({search_url})",
                "inline": False,
            }
        ],
    }
    payload = {"embeds": [embed]}
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        if response.status_code == 204:
            print(f"[-] Sent to Discord: {target} - {query_name}")
            return True
        else:
            print(f"[-] Discord webhook failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"[-] Discord error: {e}")
        return False


def send_discord_alert(webhook_url, alert_type, message, target=None):
    embed = {
        "title": f"⚠️ Alert: {alert_type.replace('_', ' ').title()}",
        "description": message,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    if target:
        embed["fields"] = [{"name": "Target", "value": target, "inline": False}]

    payload = {"embeds": [embed]}

    try:
        requests.post(webhook_url, json=payload, timeout=10)
    except:
        pass


def scan_targets(cookie_url, targets_url, webhook_url):
    targets = download_and_save_targets(targets_url)
    if not targets:
        print("[-] Failed to download targets from URL")
        return False

    if not load_cookies(cookie_url):
        print("[-] Failed to load cookies")
        return False

    progress = load_progress()
    scanned_targets = load_scanned_targets()
    total_results = progress.get("total_found", 0)

    new_targets = [t for t in targets if t not in scanned_targets]

    print(f"[-] Number of targets: {len(targets)}")
    print(f"[-] Total scanned: {len(scanned_targets)}")

    if not new_targets:
        print(f"[-] No new targets available...")
        return False

    for i, target in enumerate(new_targets):
        print(f"\n[{i+1}/{len(new_targets)}] Processing: {target}")

        for query_obj in SEARCH_QUERIES:
            has_results, search_url, query_name = scrape_shodan(query_obj, target)
            if has_results and search_url:
                print(f"[success] Results found for {query_obj['name']}")
                send_discord_webhook(webhook_url, target, search_url, query_name)
                total_results += 1
            else:
                print(f"[x] No results for {query_obj['name']}")

            if query_obj != SEARCH_QUERIES[-1]:
                delay = random.uniform(2, 4)
                print(f"\n[-] Waiting {delay:.1f}s before next query...\n")
                time.sleep(delay)

        mark_scanned(target)
        scanned_targets.add(target)
        save_progress(total_results)

        if i < len(new_targets) - 1:
            delay = random.uniform(7, 10)
            print(f"\n[-] Waiting {delay:.1f}s before next target...")
            time.sleep(delay)

    print("\n" + "=" * 60)
    print(f"[-] Scan complete: {total_results} results found")
    print(f"[-] Scanned targets: {len(scanned_targets)}")
    print("=" * 60)
    return True


def format_time(seconds):
    target_time = time.time() + seconds
    target_struct = time.localtime(target_time)
    return time.strftime("%Y-%m-%d %H:%M:%S", target_struct)


def main():
    print("=" * 60)
    print("Multi-Query Shodan Scanner")
    print("=" * 60)
    cookie_url = os.getenv("COOKIE_URL")
    targets_url = os.getenv("TARGETS_URL")
    webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
    if not cookie_url or not targets_url or not webhook_url:
        print("[-] Missing environment variables:")
        print("    COOKIE_URL, TARGETS_URL, DISCORD_WEBHOOK_URL")
        sys.exit(1)

    first_run = False

    while True:
        try:
            found_new = scan_targets(cookie_url, targets_url, webhook_url)

            if found_new:
                print(f"[-] Scan cycle completed. Checking for additional targets...")
                time.sleep(310)
            else:
                print(f"[-] Next scan is at {format_time(CHECK_INTERVAL)}\n")
                time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print("[!] Shutting down...")
            sys.exit(0)
        except Exception as e:
            print(f"[-] Error during scan: {e}")
            print(f"[-] Retrying scan at {format_time(CHECK_INTERVAL)}\n")
            time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
