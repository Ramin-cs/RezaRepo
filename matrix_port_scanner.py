#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Matrix Port Scanner - Fast, Smart, Cross-Platform TCP scanner in one file

Features:
- Asyncio high-concurrency TCP connect scanning
- Intelligent target parsing: single host/IP, CIDR, IP range, file list
- Port parsing: numbers, ranges, names (http), presets (top100, top1000)
- Matrix-styled banner and themed console output (ANSI colors, no deps)
- Basic banner grabbing with protocol-aware probes (HTTP/SMTP/SSH/TLS sniff)
- CLI options for concurrency, timeout, retries, and output (JSON/TXT)
- Works on Linux, macOS, and Windows (ANSI colors auto-detected)

Usage examples:
  python matrix_port_scanner.py 192.168.1.10 -p 22,80,443
  python matrix_port_scanner.py 10.0.0.0/24 -p top1000 --concurrency 2000
  python matrix_port_scanner.py targets.txt -p http,https,8080-8090 --json-out result.json

This program is intentionally dependency-free and self-contained.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional, Set, Tuple, Dict


# =============================
# Console styling (Matrix theme)
# =============================

class Style:
    ENABLE_COLOR = sys.platform != "win32" or os.environ.get("WT_SESSION") or os.environ.get("ANSICON") or os.environ.get("TERM_PROGRAM")

    RESET = "\033[0m" if ENABLE_COLOR else ""
    BOLD = "\033[1m" if ENABLE_COLOR else ""
    DIM = "\033[2m" if ENABLE_COLOR else ""
    GREEN = "\033[38;5;46m" if ENABLE_COLOR else ""
    DARK_GREEN = "\033[38;5;34m" if ENABLE_COLOR else ""
    CYAN = "\033[38;5;51m" if ENABLE_COLOR else ""
    GRAY = "\033[90m" if ENABLE_COLOR else ""
    YELLOW = "\033[33m" if ENABLE_COLOR else ""
    RED = "\033[31m" if ENABLE_COLOR else ""


MATRIX_BANNER = r"""
 __  __       _   _             _          ____            _     ____                 _            
|  \/  | __ _| |_| |__   ___   / \   _ __ |  _ \ ___  _ __| |_  / ___|  ___  ___  ___| |_ ___  _ __ 
| |\/| |/ _` | __| '_ \ / _ \ / _ \ | '_ \| |_) / _ \| '__| __| \___ \ / _ \/ __|/ _ \ __/ _ \| '__|
| |  | | (_| | |_| | | |  __// ___ \| | | |  __/ (_) | |  | |_   ___) |  __/ (__|  __/ || (_) | |   
|_|  |_|\__,_|\__|_| |_|\___/_/   \_\_| |_|_|   \___/|_|   \__| |____/ \___|\___|\___|\__\___/|_|   
                                                                                                      
"""


def print_banner(matrix_intro: bool = True) -> None:
    if matrix_intro:
        _matrix_intro_animation(duration_sec=1.2)
    print(f"{Style.GREEN}{Style.BOLD}{MATRIX_BANNER}{Style.RESET}")
    print(f"{Style.DARK_GREEN}Fast · Smart · Async · Cross-Platform{Style.RESET}\n")


def _matrix_intro_animation(duration_sec: float = 1.2) -> None:
    if not Style.ENABLE_COLOR:
        return
    columns = min(80, _get_terminal_size()[0])
    rows = min(14, max(8, _get_terminal_size()[1] // 3))
    charset = list("01\u30a1\u30a2\u30ab\u30af\u30b1\u30b3")
    end_time = time.time() + duration_sec
    # simple falling code effect
    while time.time() < end_time:
        line = ''.join(random.choice(charset) for _ in range(columns))
        print(f"{Style.DARK_GREEN}{line}{Style.RESET}")
        time.sleep(0.03)
    # clear lines
    print("\n" * (max(0, rows - 2)))


def _get_terminal_size() -> Tuple[int, int]:
    try:
        import shutil

        size = shutil.get_terminal_size(fallback=(80, 24))
        return size.columns, size.lines
    except Exception:
        return 80, 24


# ==============
# Data structures
# ==============

COMMON_PORTS: Dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    2483: "oracle",
    2484: "oracle-tls",
    3000: "http-alt",
    3306: "mysql",
    3389: "rdp",
    5000: "http-alt",
    5432: "postgres",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    6379: "redis",
    6443: "k8s-apiserver",
    6667: "irc",
    7001: "weblogic",
    7002: "weblogic-tls",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8443: "https-alt",
    9000: "http-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
    50051: "grpc",
}


TOP_100: List[int] = [
    80, 443, 22, 21, 23, 25, 53, 110, 139, 143, 445, 993, 995, 587, 3306, 1433, 1521, 5432, 6379,
    27017, 3389, 8080, 8443, 8000, 8008, 8888, 5900, 9200, 11211, 5000, 9000, 5601, 389, 636, 465,
    123, 135, 111, 631, 69, 161, 179, 2049, 7001, 7002, 2375, 2376, 8081, 27018, 27019, 27015, 10250,
    10255, 6443, 7946, 2379, 2380, 4143, 25, 26, 995, 993, 143, 110, 53, 8088, 9001, 15672, 1883,
    61613, 61616, 1122, 6697, 6667, 5901, 5902, 81, 82, 83, 84, 85, 86, 87, 88, 1111, 2222, 4444,
    5555, 7777, 8082, 8083, 8444, 10000, 50051
]

# A compact top1000 derived from various lists (kept small yet useful)
TOP_1000: List[int] = sorted(set(TOP_100 + list(COMMON_PORTS.keys()) + [
    7, 9, 13, 15, 17, 19, 37, 88, 102, 113, 119, 179, 254, 255, 500, 514, 515, 520, 873, 992, 2048,
    222, 554, 7070, 9002, 1883, 27015, 27018, 27019, 5671, 15672, 27017, 1122, 8448, 25565, 19132,
    19133, 25575, 49152, 49153, 49154, 49155
]))


@dataclass
class ScanResult:
    target: str
    port: int
    service: str
    banner: Optional[str]
    tls: bool
    elapsed_ms: int


# ==================
# Parsing and helpers
# ==================

def parse_targets(value: str) -> List[str]:
    # file input
    if os.path.isfile(value):
        targets: List[str] = []
        with open(value, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                targets.extend(parse_targets(line))
        return list(dict.fromkeys(targets))

    # CIDR
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
            return [str(ip) for ip in network.hosts()] or [str(network.network_address)]
        except Exception:
            pass

    # IP range: 192.168.1.10-192.168.1.200 or 192.168.1.10-200
    m = re.match(r"^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$", value)
    if m:
        base, start, end = m.group(1), int(m.group(2)), int(m.group(3))
        start, end = max(0, start), min(255, end)
        if start <= end:
            return [f"{base}.{i}" for i in range(start, end + 1)]

    m2 = re.match(r"^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$", value)
    if m2:
        try:
            a = int(ipaddress.IPv4Address(m2.group(1)))
            b = int(ipaddress.IPv4Address(m2.group(2)))
            if a <= b:
                return [str(ipaddress.IPv4Address(i)) for i in range(a, b + 1)]
        except Exception:
            pass

    # single IP or hostname
    return [value]


def parse_ports(spec: str) -> List[int]:
    spec = spec.strip().lower()
    if spec in ("top100", "top-100"):
        return list(dict.fromkeys(TOP_100))
    if spec in ("top1000", "top-1000"):
        return list(dict.fromkeys(TOP_1000))

    ports: Set[int] = set()
    for part in re.split(r"[,\s]+", spec):
        if not part:
            continue
        if part.isdigit():
            ports.add(int(part))
            continue
        # range like 8000-8100
        m = re.match(r"^(\d+)-(\d+)$", part)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if a <= b:
                ports.update(range(max(1, a), min(65535, b) + 1))
            continue
        # service names like http, https
        try:
            ports.add(socket.getservbyname(part, "tcp"))
            continue
        except Exception:
            pass
        # common map fallback
        for p, name in COMMON_PORTS.items():
            if name == part:
                ports.add(p)
                break
    result = sorted(ports)
    # put common/top ports first for faster early results
    result.sort(key=lambda x: (x not in set(TOP_100), x))
    return result


def guess_service(port: int) -> str:
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return "unknown"


# =================
# Scanning primitives
# =================

async def try_connect(host: str, port: int, timeout: float) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter, float]]:
    start = time.perf_counter()
    try:
        conn = asyncio.open_connection(host=host, port=port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000.0
        return reader, writer, elapsed
    except Exception:
        return None


async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, port: int, timeout: float) -> Tuple[Optional[str], bool]:
    # Send lightweight probes based on common ports
    probes: List[Tuple[Set[int], bytes]] = [
        ({80, 8000, 8008, 8080, 8081, 8888, 5000, 3000}, b"HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: MatrixScanner/1.0\r\n\r\n" % host.encode(errors="ignore")),
        ({443, 8443}, b""),  # We will attempt TLS sniff below
        ({22}, b"\n"),  # SSH banner usually arrives first
        ({25, 465, 587}, b"EHLO matrix.scanner\r\n"),
        ({110}, b"\r\n"),
        ({143}, b"\r\n"),
        ({3389}, b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00"),  # RDP X.224 connection request
    ]

    # Attempt TLS sniff for likely TLS ports
    likely_tls = port in {443, 8443, 9443, 993, 995, 465, 636, 2376}
    tls_established = False
    try:
        if likely_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls_reader, tls_writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=timeout)
            tls_writer.write(b"\n")
            await asyncio.wait_for(tls_writer.drain(), timeout=timeout)
            try:
                data = await asyncio.wait_for(tls_reader.read(512), timeout=timeout)
            except Exception:
                data = b""
            try:
                tls_writer.close()
                await tls_writer.wait_closed()
            except Exception:
                pass
            banner = data.decode(errors="ignore").strip()
            return (banner or None), True
    except Exception:
        pass

    # Non-TLS banner grabbing
    # choose probe by port group
    payload: Optional[bytes] = None
    for ports, probe in probes:
        if port in ports:
            payload = probe
            break

    try:
        if payload:
            writer.write(payload)
            await asyncio.wait_for(writer.drain(), timeout=timeout)
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        except Exception:
            data = b""
        text = data.decode(errors="ignore").strip()
        return (text or None), tls_established
    except Exception:
        return None, tls_established


async def scan_one(host: str, port: int, timeout: float, retries: int) -> Optional[ScanResult]:
    attempt = 0
    last_err: Optional[str] = None
    while attempt <= retries:
        attempt += 1
        opened = await try_connect(host, port, timeout)
        if opened is None:
            continue
        reader, writer, elapsed = opened
        try:
            banner, is_tls = await grab_banner(reader, writer, host, port, timeout)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            service = guess_service(port)
            return ScanResult(target=host, port=port, service=service, banner=banner, tls=is_tls, elapsed_ms=int(elapsed))
        except Exception as e:
            last_err = str(e)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    return None


async def scan_targets(
    targets: List[str],
    ports: List[int],
    concurrency: int,
    timeout: float,
    retries: int,
    progress: bool = True,
) -> List[ScanResult]:
    connector_sem = asyncio.Semaphore(concurrency)
    results: List[ScanResult] = []

    async def worker(host: str, port: int):
        async with connector_sem:
            res = await scan_one(host, port, timeout, retries)
            if res:
                results.append(res)
                if progress:
                    show_open(res)

    tasks: List[asyncio.Task] = []

    # Shuffle order: interleave targets and top ports first
    ports_prioritized = sorted(ports, key=lambda p: (p not in set(TOP_100), p))
    random.shuffle(targets)

    for host in targets:
        for port in ports_prioritized:
            tasks.append(asyncio.create_task(worker(host, port)))

    # Progress spinner
    spinner = asyncio.create_task(_progress_spinner(len(tasks))) if progress else None
    try:
        await asyncio.gather(*tasks)
    finally:
        if spinner:
            spinner.cancel()
            with contextlib.suppress(Exception):
                await spinner

    return results


async def _progress_spinner(total_tasks: int):
    if not Style.ENABLE_COLOR:
        return
    frames = [
        f"{Style.DARK_GREEN}scanning{Style.RESET}",
        f"{Style.GREEN}scanning{Style.RESET}",
        f"{Style.CYAN}scanning{Style.RESET}",
    ]
    idx = 0
    try:
        while True:
            sys.stdout.write("\r" + frames[idx % len(frames)] + f" {Style.GRAY}(high speed){Style.RESET}   ")
            sys.stdout.flush()
            idx += 1
            await asyncio.sleep(0.08)
    except asyncio.CancelledError:
        sys.stdout.write("\r" + " " * 40 + "\r")
        sys.stdout.flush()


def show_open(res: ScanResult) -> None:
    service = res.service or "unknown"
    tls_tag = f" {Style.CYAN}[TLS]{Style.RESET}" if res.tls else ""
    banner = f" — {Style.GRAY}{_shorten(res.banner, 80)}{Style.RESET}" if res.banner else ""
    print(f"{Style.GREEN}[OPEN]{Style.RESET} {res.target}:{Style.BOLD}{res.port}{Style.RESET} ({service}){tls_tag} {Style.DIM}{res.elapsed_ms}ms{Style.RESET}{banner}")


def _shorten(text: str, limit: int) -> str:
    text = text.replace("\n", " | ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ==========
# CLI driver
# ==========

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Matrix Port Scanner — fast, smart, single-file TCP scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("target", help="Target: host/IP, CIDR, IP range, or file containing targets")
    p.add_argument("-p", "--ports", default="top100", help="Ports: numbers, ranges, names (http), or presets: top100, top1000")
    p.add_argument("-c", "--concurrency", type=int, default=1000, help="Max concurrent connections")
    p.add_argument("-t", "--timeout", type=float, default=1.0, help="Connection/banner timeout in seconds")
    p.add_argument("-r", "--retries", type=int, default=0, help="Retries per port")
    p.add_argument("--no-anim", action="store_true", help="Disable intro animation and spinner")
    p.add_argument("--json-out", help="Write results to JSON file")
    p.add_argument("--txt-out", help="Write results to TXT file")
    p.add_argument("--resolve", action="store_true", help="Resolve hostnames for IPs (reverse lookup)")
    return p


def resolve_if_needed(targets: List[str], do_resolve: bool) -> List[str]:
    if not do_resolve:
        return targets
    resolved: List[str] = []
    for item in targets:
        try:
            # If it's an IP, try reverse lookup
            ipaddress.ip_address(item)
            try:
                name, _, _ = socket.gethostbyaddr(item)
                resolved.append(f"{item} ({name})")
            except Exception:
                resolved.append(item)
        except Exception:
            # Hostname — resolve to IP
            try:
                ip = socket.gethostbyname(item)
                resolved.append(f"{item} ({ip})")
            except Exception:
                resolved.append(item)
    return resolved


def write_outputs(results: List[ScanResult], json_out: Optional[str], txt_out: Optional[str]) -> None:
    if json_out:
        data = [asdict(r) for r in results]
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"{Style.GRAY}Saved JSON: {json_out}{Style.RESET}")
    if txt_out:
        with open(txt_out, "w", encoding="utf-8") as f:
            for r in results:
                line = f"{r.target}:{r.port} {r.service} {'TLS ' if r.tls else ''}{r.elapsed_ms}ms"
                if r.banner:
                    line += f" | {r.banner.replace('\n', ' | ')}"
                f.write(line + "\n")
        print(f"{Style.GRAY}Saved TXT: {txt_out}{Style.RESET}")


# =====
# Main
# =====

import contextlib


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    print_banner(matrix_intro=not args.no_anim)

    try:
        targets = parse_targets(args.target)
        if not targets:
            print(f"{Style.RED}No valid targets found.{Style.RESET}")
            return 2
        ports = parse_ports(args.ports)
        if not ports:
            print(f"{Style.RED}No valid ports found.{Style.RESET}")
            return 3
    except KeyboardInterrupt:
        print()
        return 130

    targets_display = resolve_if_needed(targets, args.resolve)
    print(f"{Style.GRAY}Targets: {len(targets)}  |  Ports: {len(ports)}  |  Concurrency: {args.concurrency}{Style.RESET}")
    if len(targets_display) <= 6:
        print(f"{Style.DIM}{', '.join(targets_display)}{Style.RESET}")

    start = time.perf_counter()
    try:
        results: List[ScanResult] = asyncio.run(
            scan_targets(
                targets=targets,
                ports=ports,
                concurrency=max(1, args.concurrency),
                timeout=max(0.05, args.timeout),
                retries=max(0, args.retries),
                progress=not args.no_anim,
            )
        )
    except KeyboardInterrupt:
        print()
        print(f"{Style.YELLOW}Interrupted by user.{Style.RESET}")
        return 130

    elapsed = (time.perf_counter() - start)
    print(f"\n{Style.BOLD}{Style.GREEN}Scan complete{Style.RESET} in {elapsed:.2f}s — {len(results)} open services")

    # Sort and show summary
    results_sorted = sorted(results, key=lambda r: (r.target, r.port))
    for r in results_sorted:
        show_open(r)

    write_outputs(results_sorted, args.json_out, args.txt_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

