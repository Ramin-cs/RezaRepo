#!/usr/bin/env python3
"""
Non-intrusive TP-Link Archer VR2100v web console discovery tool.

This tool scans provided IPs/ranges for common HTTP(S) management ports,
fetches landing pages without authentication, and uses lightweight heuristics
to fingerprint likely TP-Link Archer VR2100v consoles. It DOES NOT attempt login.

Usage examples:
  python3 scanner.py --targets 192.168.1.10-50,10.0.0.5 --workers 64
  python3 scanner.py --targets 192.168.1.0/24 --json report.json
  python3 scanner.py --targets ips.txt --from-file --csv report.csv
"""

import argparse
import concurrent.futures
import csv
import hashlib
import ipaddress
import json
import socket
import sys
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

import requests
from requests.exceptions import RequestException

# Reduce noisy SSL warnings common on SOHO gear
requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]


DEFAULT_TIMEOUT_SECS = 4
DEFAULT_PORTS = [80, 443, 8080, 8443]
DEFAULT_PATHS = ["/", "/login", "/userRpm/LoginRpm.htm"]

TP_LINK_MARKERS = [
    "tp-link",
    "tplink",
    "archer",
    "vr2100",
    "vr2100v",
    "tp-link technologies",
    "tp-link cloud",
    "tether",
]


@dataclass
class HttpHit:
    url: str
    status: int
    title: Optional[str]
    server: Optional[str]
    tplink_like: bool
    favicon_sha1: Optional[str]


@dataclass
class HostSummary:
    ip: str
    hits: List[HttpHit]
    has_http: bool
    has_https: bool
    tplink_detected: bool
    likely_login_url: Optional[str]


def is_tcp_open(host: str, port: int, timeout: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def http_get(url: str, timeout: int) -> Tuple[int, Dict[str, str], str]:
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (AuditBot/1.0)"},
        )
        text = resp.text[:100_000] if resp.text else ""
        return resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, text
    except RequestException:
        return 0, {}, ""


def http_get_bytes(url: str, timeout: int) -> Tuple[int, Dict[str, str], bytes]:
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (AuditBot/1.0)"},
        )
        content = resp.content[:200_000] if resp.content else b""
        return resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, content
    except RequestException:
        return 0, {}, b""


def extract_title(html: str) -> Optional[str]:
    if not html:
        return None
    lower = html.lower()
    start = lower.find("<title>")
    end = lower.find("</title>")
    if start != -1 and end != -1 and end > start:
        return html[start + 7 : end].strip()
    return None


def looks_like_tplink(title: Optional[str], headers: Dict[str, str], body: str) -> bool:
    haystacks: List[str] = []
    if title:
        haystacks.append(title.lower())
    server = headers.get("server", "")
    if server:
        haystacks.append(server.lower())
    haystacks.append(body[:5000].lower() if body else "")
    for marker in TP_LINK_MARKERS:
        if any(marker in h for h in haystacks):
            return True
    return False


def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def try_fetch_favicon(base_url: str, timeout: int) -> Optional[str]:
    # Common favicon locations
    for path in ["/favicon.ico", "/images/favicon.ico", "/favicon.png"]:
        status, _, content = http_get_bytes(f"{base_url}{path}", timeout)
        if status and status < 500 and content:
            return sha1(content)
    return None


def probe_host(ip: str, ports: List[int], paths: List[str], timeout: int) -> HostSummary:
    hits: List[HttpHit] = []

    for port in ports:
        if not is_tcp_open(ip, port, timeout):
            continue
        scheme = "https" if port in (443, 8443) else "http"
        base = f"{scheme}://{ip}:{port}"
        best_hit: Optional[HttpHit] = None
        favicon_hash: Optional[str] = try_fetch_favicon(base, timeout)
        for path in paths:
            url = f"{base}{path}"
            status, headers, body = http_get(url, timeout)
            if status == 0:
                continue
            title = extract_title(body)
            is_tplink = looks_like_tplink(title, headers, body)
            hit = HttpHit(
                url=url,
                status=status,
                title=title,
                server=headers.get("server"),
                tplink_like=is_tplink,
                favicon_sha1=favicon_hash,
            )
            hits.append(hit)
            if is_tplink and status in (200, 301, 302):
                best_hit = best_hit or hit
        # prefer a strong hit on this port and avoid probing many paths
        if best_hit:
            continue

    has_http = any(h.url.startswith(f"http://{ip}:") for h in hits)
    has_https = any(h.url.startswith(f"https://{ip}:") for h in hits)
    tplink_detected = any(h.tplink_like for h in hits)
    likely_login_url = next((h.url for h in hits if h.tplink_like), None)

    return HostSummary(
        ip=ip,
        hits=hits,
        has_http=has_http,
        has_https=has_https,
        tplink_detected=tplink_detected,
        likely_login_url=likely_login_url,
    )


def expand_targets(targets: List[str]) -> List[str]:
    ips: List[str] = []
    for part in targets:
        part = part.strip()
        if not part:
            continue
        # CIDR
        try:
            if "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                for ip in net.hosts():
                    ips.append(str(ip))
                continue
        except ValueError:
            pass
        # simple last-octet range 192.168.1.10-50
        if "-" in part:
            try:
                base = ".".join(part.split(".")[:-1])
                rng = part.split(".")[-1]
                start, end = [int(x) for x in rng.split("-")]
                for x in range(start, end + 1):
                    ips.append(f"{base}.{x}")
                continue
            except Exception:
                pass
        # single IP
        ips.append(part)
    # de-dup preserve order
    seen = set()
    unique_ips: List[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)
    return unique_ips


def load_targets_from_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f.readlines()]
    return [ln for ln in lines if ln and not ln.startswith("#")]


def filter_ips(ips: List[str], allowlist: Optional[List[str]], denylist: Optional[List[str]]) -> List[str]:
    allowed = set(ips)
    if allowlist:
        allowed = {ip for ip in ips for net in allowlist if ip_in_net(ip, net)}
    if denylist:
        denied = {ip for ip in ips for net in denylist if ip_in_net(ip, net)}
        allowed = [ip for ip in allowed if ip not in denied]
    return list(allowed)


def ip_in_net(ip: str, net: str) -> bool:
    try:
        if "/" in net:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
        return ip == net
    except ValueError:
        return False


def write_json(path: str, summaries: List[HostSummary]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(s) for s in summaries], f, indent=2)


def write_csv(path: str, summaries: List[HostSummary]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "tplink_detected", "has_http", "has_https", "likely_login_url", "hit_count"])
        for s in summaries:
            writer.writerow([s.ip, s.tplink_detected, s.has_http, s.has_https, s.likely_login_url or "", len(s.hits)])


def post_webhook(url: str, payload: Dict[str, object], timeout: int) -> None:
    try:
        requests.post(url, json=payload, timeout=timeout)
    except RequestException:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Discover TP-Link Archer VR2100v-like web consoles (non-intrusive, no login).",
    )
    parser.add_argument("--targets", help="Comma-separated targets, ranges, or CIDRs (or file if --from-file)")
    parser.add_argument("--from-file", action="store_true", help="Interpret --targets as a file path")
    parser.add_argument("--ports", default=",".join(str(p) for p in DEFAULT_PORTS), help="Comma-separated ports")
    parser.add_argument("--paths", default=",".join(DEFAULT_PATHS), help="Comma-separated URL paths to probe")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECS, help="Per-request timeout seconds")
    parser.add_argument("--workers", type=int, default=64, help="Concurrency (default 64)")
    parser.add_argument("--allow", help="Allowlist CIDRs/IPs (comma-separated)")
    parser.add_argument("--deny", help="Denylist CIDRs/IPs (comma-separated)")
    parser.add_argument("--json", help="Write JSON report to file")
    parser.add_argument("--csv", help="Write CSV report to file")
    parser.add_argument("--webhook", help="POST JSON detections to webhook URL")
    args = parser.parse_args()

    if not args.targets:
        print("--targets is required (or use --from-file with a file path)", file=sys.stderr)
        sys.exit(2)

    raw_targets: List[str]
    if args.from_file:
        raw_targets = load_targets_from_file(args.targets)
    else:
        raw_targets = [t.strip() for t in args.targets.split(",") if t.strip()]

    ips = expand_targets(raw_targets)

    allowlist = [t.strip() for t in args.allow.split(",")] if args.allow else None
    denylist = [t.strip() for t in args.deny.split(",")] if args.deny else None
    if allowlist or denylist:
        ips = filter_ips(ips, allowlist, denylist)

    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    paths = [p if p.startswith("/") else f"/{p}" for p in [x.strip() for x in args.paths.split(",") if x.strip()]]

    summaries: List[HostSummary] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        future_map = {pool.submit(probe_host, ip, ports, paths, args.timeout): ip for ip in ips}
        for fut in concurrent.futures.as_completed(future_map):
            s = fut.result()
            summaries.append(s)
            mark = "TP-LINK" if s.tplink_detected else "UNKNOWN"
            print(f"{s.ip}: {mark} http={s.has_http} https={s.has_https} login_hint={s.likely_login_url}")
            if args.webhook and s.tplink_detected:
                post_webhook(
                    args.webhook,
                    {
                        "ip": s.ip,
                        "likely_login_url": s.likely_login_url,
                        "has_https": s.has_https,
                        "has_http": s.has_http,
                        "hits": [asdict(h) for h in s.hits],
                    },
                    args.timeout,
                )

    if args.json:
        write_json(args.json, summaries)
    if args.csv:
        write_csv(args.csv, summaries)


if __name__ == "__main__":
    main()

