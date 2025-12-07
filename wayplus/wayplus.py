#!/usr/bin/env python3

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import jwt
import requests

VERSION = "1.0"
START_TIME = None
INTERRUPTED = False


class Colors:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    ORANGE = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"


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


class Config:
    REQUEST_DELAY = 1.5
    MAX_RETRIES = 3
    RATE_LIMIT_PAUSE = 300
    HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; wayplus/1.0)"}

    JWT_REGEX = re.compile(
        r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"
    )
    JUICY_FIELDS = [
        "email",
        "username",
        "password",
        "api_key",
        "access_token",
        "session_id",
        "role",
        "scope",
    ]

    SECRET_PARAMS = re.compile(
        r"[?&](code|token|ticket|key|secret|password|pass|pwd|auth|session|sid|jwt|bearer|"
        r"access_token|refresh_token|api_key|apikey|client_secret|private_key|oauth|callback|"
        r"redirect|redirect_uri|state|nonce)=",
        re.IGNORECASE,
    )

    REDIRECT_PARAMS = re.compile(
        r"[?&](returnUrl|continue|dest|destination|forward|go|goto|login\?to|login_url|logout|next|next_page|out|g|redir|redirect|redirect_to|redirect_uri|redirect_url|return|returnTo|return_path|return_to|return_url|rurl|site|target|to|uri|url|qurl|rit_url|jump|jump_url|originUrl|origin|Url|desturl|u|Redirect|location|ReturnUrl|redirect_link|forward_to|forward_url|destination_url|jump_to|go_to|goto_url|target_url|view|window|next_url|load|file|folder|path|navigation|nav|open|page|show|checkout|checkout_url|success|success_url|failure|failure_url|error|error_url|done|done_url|complete|complete_url|callback_url|fallback|fallback_url|back|back_url|backurl|link|href|ref|reference|source|src|load_url|page_url|view_url|landing|landing_url|final|final_url)=",
        re.IGNORECASE,
    )

    API_PATTERNS = re.compile(
        r"^https?://api\.|^https?://[^/]+/api(/v[0-9]+)?|/graphql|/graphiql|/playground|"
        r"/api/v[0-9]+|/v[1-6]/graphql|\.api\.",
        re.IGNORECASE,
    )

    STATIC_EXTENSIONS = re.compile(
        r"\.(js|css|txt|json|xml|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|tar|gz|rar|7z|"
        r"exe|dmg|pkg|deb|rpm|iso|img|svg|ico|woff|woff2|ttf|eot|otf|mp3|mp4|wav|"
        r"avi|mov|wmv|flv|webm|ogg|png|jpg|jpeg|gif|bmp|tiff|webp)(\?.*)?$",
        re.IGNORECASE,
    )

    DEFAULT_EXTENSIONS = [".zip", ".tar.gz", ".rar", ".sql", ".bak", ".7z", ".gz"]


def signal_handler(signum, frame):
    global INTERRUPTED
    INTERRUPTED = True
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()
    elapsed = (time.time() - START_TIME) if START_TIME else 0
    print(
        f"\n[{Colors.ORANGE}WRN{Colors.RESET}] Scan interrupted {Colors.DIM}({elapsed:.3f}s time elapsed){Colors.RESET}"
    )
    sys.exit(130)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def print_banner():
    print(
        rf"""{Colors.CYAN}
                           _
__      ____ _ _   _ _ __ | |_   _ ___
\ \ /\ / / _` | | | | '_ \| | | | / __|
 \ V  V / (_| | |_| | |_) | | |_| \__ \
  \_/\_/ \__,_|\__, | .__/|_|\__,_|___/
               |___/|_|
{Colors.RESET}
{Colors.DIM}        Wayback URL Analyzer v{VERSION}{Colors.RESET}
"""
    )


def load_file(path, default=None):
    try:
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        if default:
            return default
        return []


def save_file(path, lines):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(lines))


def retry_request(url, timeout=30):
    for attempt in range(Config.MAX_RETRIES):
        try:
            response = requests.get(url, timeout=timeout)
            if response.status_code == 429:
                time.sleep(Config.RATE_LIMIT_PAUSE)
                continue
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException:
            if attempt < Config.MAX_RETRIES - 1:
                time.sleep(Config.REQUEST_DELAY * (2**attempt))
    return None


def fetch_waymore_urls(target, output_dir):
    output_file = f"{output_dir}/urls.txt"
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    cmd = [
        "waymore",
        "-mode",
        "U",
        "-t",
        "5",
        "-p",
        "2",
        "-lr",
        "60",
        "-r",
        "5",
        "-oU",
        output_file,
        "-i",
        target,
    ]

    try:
        print()
        spinner = Spinner("Fetching URLs using waymore...")
        spinner.start()

        process = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        while process.poll() is None:
            time.sleep(0.3)

        spinner.stop()

        if process.returncode == 0 and os.path.exists(output_file):
            urls = load_file(output_file)
            print(
                f"[{Colors.GREEN}SUC{Colors.RESET}] [waymore] Found {Colors.BOLD}{len(urls)}{Colors.RESET} URLs"
            )
            return urls, output_file
        else:
            print(f"[{Colors.RED}ERR{Colors.RESET}] Failed to fetch URLs")
            return [], None

    except FileNotFoundError:
        spinner.stop()
        print(
            f"[{Colors.RED}ERR{Colors.RESET}] Waymore not installed. Install: pip install waymore"
        )
        return [], None
    except Exception as e:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] Error: {e}")
        return [], None


def fetch_waybackurls(target, output_dir):
    output_file = f"{output_dir}/waybackurls.txt"

    try:
        spinner = Spinner("Fetching URLs using waybackurls...")
        spinner.start()

        process = subprocess.Popen(
            ["waybackurls"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        stdout, _ = process.communicate(input=target, timeout=600)

        spinner.stop()

        if process.returncode == 0 and stdout.strip():
            urls = [line.strip() for line in stdout.splitlines() if line.strip()]
            save_file(output_file, urls)
            print(
                f"[{Colors.GREEN}SUC{Colors.RESET}] [waybackurls] Found {Colors.BOLD}{len(urls)}{Colors.RESET} URLs"
            )
            return urls, output_file
        else:
            print(
                f"[{Colors.RED}ERR{Colors.RESET}] Failed to fetch URLs using waybackurls"
            )
            return [], None

    except FileNotFoundError:
        spinner.stop()
        print(
            f"[{Colors.RED}ERR{Colors.RESET}] waybackurls not installed. Run `{Colors.DIM}go install github.com/tomnomnom/waybackurls@latest{Colors.RESET}` to install."
        )
        return [], None
    except subprocess.TimeoutExpired:
        process.kill()
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] waybackurls timed out")
        return [], None
    except Exception as e:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] Error: {e}")
        return [], None


def crawl_with_katana(target, output_dir, depth=3):
    output_file = f"{output_dir}/katana.txt"

    cmd = [
        "katana",
        "-u", f"https://{target}",
        "-d", str(depth),
        "-jc",
        "-kf", "all",
        "-silent",
        "-nc",
        "-rl", "150",
        "-c", "10"
    ]

    try:
        spinner = Spinner(f"Crawling target site (depth: {depth})")
        spinner.start()

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        spinner.stop()

        if result.returncode == 0:
            urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]

            seen = set()
            unique_urls = []
            for url in urls:
                if url not in seen:
                    seen.add(url)
                    unique_urls.append(url)

            if unique_urls:
                save_file(output_file, unique_urls)
                print(
                    f"[{Colors.GREEN}SUC{Colors.RESET}] [katana] Found {Colors.BOLD}{len(unique_urls)}{Colors.RESET} unique URLs"
                )
                return unique_urls, output_file
            else:
                print(f"[{Colors.RED}ERR{Colors.RESET}] No URLs found during crawl")
                return [], None

        else:
            print(f"[{Colors.RED}ERR{Colors.RESET}] Failed to crawl using katana")
            return [], None

    except FileNotFoundError:
        spinner.stop()
        print(
            f"[{Colors.RED}ERR{Colors.RESET}] katana not installed. Run `{Colors.DIM}go install github.com/projectdiscovery/katana/cmd/katana@latest{Colors.RESET}` to install."
        )
        return [], None
    except subprocess.TimeoutExpired:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] katana timed out")
        return [], None
    except Exception as e:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] Error: {e}")
        return [], None


def detect_redirects_with_gf(urls_file, output_dir):
    output_file = f"{output_dir}/redirect.txt"

    try:
        spinner = Spinner("Detecting open redirect patterns with gf")
        spinner.start()

        with open(urls_file, 'r') as f:
            process = subprocess.Popen(
                ["gf", "redirect"],
                stdin=f,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )

            stdout, _ = process.communicate(timeout=120)

        spinner.stop()

        if process.returncode == 0 and stdout.strip():
            redirect_urls = [line.strip() for line in stdout.splitlines() if line.strip()]

            seen = set()
            unique_redirects = []
            for url in redirect_urls:
                if url not in seen:
                    seen.add(url)
                    unique_redirects.append(url)

            if unique_redirects:
                save_file(output_file, unique_redirects)
                return unique_redirects
            else:
                return []
        else:
            return []

    except FileNotFoundError:
        spinner.stop()
        print(
            f"[{Colors.RED}ERR{Colors.RESET}] gf not installed. Run `{Colors.DIM}go install github.com/tomnomnom/gf@latest{Colors.RESET}` to install."
        )
        print(
            f"[{Colors.ORANGE}WRN{Colors.RESET}] Also ensure gf patterns are installed: `{Colors.DIM}git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf{Colors.RESET}`"
        )
        return []
    except subprocess.TimeoutExpired:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] gf redirect timed out")
        return []
    except Exception as e:
        spinner.stop()
        print(f"[{Colors.RED}ERR{Colors.RESET}] Error running gf: {e}")
        return []


def detect_open_redirects(urls, output_dir):
    redirect_urls = [url for url in urls if Config.REDIRECT_PARAMS.search(url)]

    if not redirect_urls:
        return []

    version1_urls = []
    version2_urls = []

    try:
        qsreplace_available = subprocess.run(
            ["which", "qsreplace"],
            capture_output=True,
            text=True
        ).returncode == 0
    except Exception:
        qsreplace_available = False

    if qsreplace_available:
        try:
            process = subprocess.Popen(
                ["qsreplace", "https://google.com"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            stdout, _ = process.communicate(input="\n".join(redirect_urls), timeout=60)

            if process.returncode == 0 and stdout.strip():
                version1_urls = [line.strip() for line in stdout.splitlines() if line.strip()]
        except Exception:
            pass

    for url in redirect_urls:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        redirect_param_found = None
        for param in query_params.keys():
            if Config.REDIRECT_PARAMS.search(f"?{param}="):
                redirect_param_found = param
                break

        if redirect_param_found:
            new_params = {redirect_param_found: query_params[redirect_param_found]}
            new_query = "&".join([f"{k}={v[0]}" for k, v in new_params.items()])
            cleaned_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            version2_urls.append(cleaned_url)

    if version1_urls:
        save_file(f"{output_dir}/open-redirect-1.txt", version1_urls)

    if version2_urls:
        save_file(f"{output_dir}/open-redirect-2.txt", version2_urls)

    return version1_urls if version1_urls else version2_urls


def fetch_compressed_files_urls(target, output_dir, extensions=None):
    extensions = extensions or Config.DEFAULT_EXTENSIONS

    archive_url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=txt&fl=original&collapse=urlkey&page=/"

    spinner = Spinner("Fetching archive data")
    spinner.start()
    response = retry_request(archive_url, timeout=60)
    spinner.stop()

    if not response:
        return []

    urls = response.text.splitlines()

    all_urls = []
    for url in urls:
        if any(url.lower().endswith(ext.lower()) for ext in extensions):
            all_urls.append(url)

    if all_urls:
        compressed_path = f"{output_dir}/compressed.txt"
        save_file(compressed_path, all_urls)

    return all_urls


def extract_jwt_from_url(url):
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    for values in query_params.values():
        for value in values:
            val = unquote(value)
            if re.match(Config.JWT_REGEX, val):
                return val

    decoded_url = unquote(url)
    match = Config.JWT_REGEX.search(decoded_url)
    return match.group(0) if match else None


def check_url_status(url):
    try:
        resp = requests.head(
            url, headers=Config.HEADERS, allow_redirects=True, timeout=10
        )
        return url if resp.status_code in [200, 301, 302] else None
    except requests.exceptions.RequestException:
        return None


def analyze_jwts_from_urls(urls, output_dir):
    jwt_map = {url: token for url in urls if (token := extract_jwt_from_url(url))}

    if not jwt_map:
        return 0

    with ThreadPoolExecutor(max_workers=10) as executor:
        live_urls = list(filter(None, executor.map(check_url_status, jwt_map.keys())))

    if not live_urls:
        return 0

    results = {}
    for url in live_urls:
        token = jwt_map[url]
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            juicy = {k: v for k, v in decoded.items() if k in Config.JUICY_FIELDS}
            results[url] = {"jwt": token, "decoded": decoded, "juicy": juicy}
        except Exception:
            continue

    if results:
        jwt_path = f"{output_dir}/jwt.json"
        with open(jwt_path, "w") as f:
            json.dump(results, f, indent=2)
        return len(results)

    return 0


def extract_subdomains_from_urls(urls, root_domain=None):
    subdomains = set()
    for url in urls:
        if match := re.search(r"https?://([a-zA-Z0-9.-]+)", url):
            domain = match.group(1).lower().split(":")[0]
            if not root_domain or domain.endswith(root_domain):
                subdomains.add(domain)

    return list(subdomains)


def extract_parameters(urls):
    param_regex = re.compile(r"\?([^#]+)")
    seen = set()
    results = []

    for url in urls:
        if match := param_regex.search(url):
            param_segment = match.group(1)
            param_pairs = [
                p.split("=")[0] for p in param_segment.split("&") if "=" in p
            ]

            if param_pairs:
                key = tuple(sorted(set(param_pairs)))
                if (key, url) not in seen:
                    seen.add((key, url))
                    results.append(url)

    return results


def find_keyword(urls, keyword):
    matches = [u for u in urls if keyword.lower() in u.lower()]
    return matches


def extract_secret_urls(urls, output_dir):
    secret = [url for url in urls if Config.SECRET_PARAMS.search(url)]

    if secret:
        output_path = f"{output_dir}/secrets.txt"
        save_file(output_path, secret)

    return secret


def extract_api_urls(urls, output_dir):
    api_urls = [
        url
        for url in urls
        if Config.API_PATTERNS.search(url) and not Config.STATIC_EXTENSIONS.search(url)
    ]

    if api_urls:
        output_path = f"{output_dir}/apis.txt"
        save_file(output_path, api_urls)

    return api_urls


def extract_static_urls(urls, output_dir):
    static_urls = [url for url in urls if Config.STATIC_EXTENSIONS.search(url)]

    if static_urls:
        output_path = f"{output_dir}/static.txt"
        save_file(output_path, static_urls)

    return static_urls


def run_automated_analysis(urls, urls_file, target, output_dir):
    results = {}

    spinner = Spinner("Extracting subdomains")
    spinner.start()
    subdomains = extract_subdomains_from_urls(urls, target)
    spinner.stop()
    if subdomains:
        save_file(f"{output_dir}/subdomains.txt", subdomains)
        results["subdomains"] = len(subdomains)
        print(f"[{Colors.GREEN}+{Colors.RESET}] Subdomains: {len(subdomains)} found")
    else:
        print(f"[{Colors.RED}-{Colors.RESET}] Subdomains: 0 found")

    spinner = Spinner("Extracting parameters")
    spinner.start()
    params = extract_parameters(urls)
    spinner.stop()
    if params:
        save_file(f"{output_dir}/parameters.txt", params)
        results["parameters"] = len(params)
        print(f"[{Colors.GREEN}+{Colors.RESET}] Parameters: {len(params)} found")
    else:
        print(f"[{Colors.RED}-{Colors.RESET}] Parameters: 0 found")

    spinner = Spinner("Searching for Secret URLs")
    spinner.start()
    secret = extract_secret_urls(urls, output_dir)
    spinner.stop()
    results["secret"] = len(secret)
    if secret:
        print(f"[{Colors.GREEN}+{Colors.RESET}] Secret URLs: {len(secret)} found")
    else:
        print(f"[{Colors.RED}-{Colors.RESET}] Secret URLs: 0 found")

    spinner = Spinner("Extracting API endpoints")
    spinner.start()
    apis = extract_api_urls(urls, output_dir)
    spinner.stop()
    results["apis"] = len(apis)
    if apis:
        print(f"[{Colors.GREEN}+{Colors.RESET}] API endpoints: {len(apis)} found")
    else:
        print(f"[{Colors.RED}-{Colors.RESET}] API endpoints: 0 found")

    spinner = Spinner("Extracting static files")
    spinner.start()
    static_files = extract_static_urls(urls, output_dir)
    spinner.stop()
    results["static_files"] = len(static_files)
    if static_files:
        print(
            f"[{Colors.GREEN}+{Colors.RESET}] Static files: {len(static_files)} found"
        )
    else:
        print(f"[{Colors.RED}-{Colors.RESET}] Static files: 0 found")

    spinner = Spinner("Searching for JSON URLs")
    spinner.start()
    json_urls = find_keyword(urls, "json")
    spinner.stop()
    if json_urls:
        save_file(f"{output_dir}/json.txt", json_urls)
        results["json"] = len(json_urls)
        print(f"[{Colors.GREEN}+{Colors.RESET}] JSON URLs: {len(json_urls)} found")
    else:
        print(f"[{Colors.RED}-{Colors.RESET}] JSON URLs: 0 found")

    spinner = Spinner("Searching for config URLs")
    spinner.start()
    config_urls = find_keyword(urls, "conf")
    spinner.stop()
    if config_urls:
        save_file(f"{output_dir}/config.txt", config_urls)
        results["config"] = len(config_urls)
        print(f"[{Colors.GREEN}+{Colors.RESET}] Config URLs: {len(config_urls)} found")
    else:
        print(f"[{Colors.RED}-{Colors.RESET}] Config URLs: 0 found")

    spinner = Spinner("Detecting open redirect URLs")
    spinner.start()
    redirect_urls = detect_open_redirects(urls, output_dir)
    spinner.stop()
    results["redirects"] = len(redirect_urls)
    if redirect_urls:
        print(f"[{Colors.GREEN}+{Colors.RESET}] Open Redirect URLs: {len(redirect_urls)} found")
    else:
        print(f"[{Colors.RED}-{Colors.RESET}] Open Redirect URLs: 0 found")

    spinner = Spinner("Analyzing JWT tokens")
    spinner.start()
    jwt_count = analyze_jwts_from_urls(urls, output_dir)
    spinner.stop()
    results["jwt"] = jwt_count
    if jwt_count:
        print(f"[{Colors.GREEN}+{Colors.RESET}] JWT tokens: {jwt_count} analyzed")
    else:
        print(f"[{Colors.RED}-{Colors.RESET}] JWT tokens: 0 found")

    spinner = Spinner("Searching for compressed files")
    spinner.start()
    compressed = fetch_compressed_files_urls(
        target, output_dir, load_file("extensions.txt", Config.DEFAULT_EXTENSIONS)
    )
    spinner.stop()
    results["compressed"] = len(compressed)
    if compressed:
        print(
            f"[{Colors.GREEN}+{Colors.RESET}] Compressed files: {len(compressed)} found"
        )
    else:
        print(f"[{Colors.RED}-{Colors.RESET}] Compressed files: 0 found")

    return results


def print_summary(results, output_dir):
    print(f"\n[{Colors.CYAN}INF{Colors.RESET}] Results saved to: {output_dir}")

    elapsed = time.time() - START_TIME
    print(
        f"[{Colors.CYAN}INF{Colors.RESET}] Scan finished {Colors.DIM}({elapsed:.3f}s time elapsed){Colors.RESET}\n"
    )


def main():
    global START_TIME

    parser = argparse.ArgumentParser(description="Wayback URL Analyzer")
    parser.add_argument(
        "-d", required=True, metavar="example.com", help="Target domain"
    )
    parser.add_argument(
        "-output", required=True, metavar="output_dir/", help="Output directory"
    )
    parser.add_argument(
        "-c",
        type=int,
        metavar="depth",
        help="Enable crawling with specified depth (default: 3)",
        nargs="?",
        const=3,
    )

    args = parser.parse_args()

    print_banner()
    START_TIME = time.time()

    target = args.d.strip()
    output_dir = args.output.strip()

    urls, urls_file = fetch_waymore_urls(target, output_dir)
    if not urls:
        print(f"[{Colors.RED}ERR{Colors.RESET}] Failed to fetch URLs using waymore")
        return

    wayback_urls, wayback_file = fetch_waybackurls(target, output_dir)
    if wayback_urls:
        urls = list(set(urls + wayback_urls))

    if args.c is not None:
        depth = args.c if args.c > 0 else 3
        katana_urls, katana_file = crawl_with_katana(target, output_dir, depth)

        if katana_urls:
            urls = list(set(urls + katana_urls))

    combined_file = f"{output_dir}/combined.txt"
    save_file(combined_file, urls)
    print(f"[{Colors.CYAN}INF{Colors.RESET}] Found total of {len(urls)} unique URLs")
    urls_file = combined_file

    results = run_automated_analysis(urls, urls_file, target, output_dir)

    print_summary(results, output_dir)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()
        print(f"\n[{Colors.ORANGE}WRN{Colors.RESET}] Interrupted by user")
        sys.exit(0)
