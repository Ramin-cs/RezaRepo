from __future__ import annotations

import json
import signal
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme
from rich import box

from .nmap_parser import parse_nmap_xml
from .scoring import analyze_hosts
from .report import save_html_report, save_json_report


MATRIX_THEME = Theme({
    "matrix": "bold green",
    "accent": "bright_cyan",
    "warn": "yellow",
    "error": "bold red",
})


console = Console(theme=MATRIX_THEME)


def banner() -> None:
    ascii_art = r"""
 __  __ _      _            _          _ _ _   
|  \/  (_)_ _ (_)___ _ _   /_\  _ _ __| (_) |_ 
| |\/| | | ' \| / -_) ' \ / _ \| '_/ _` | |  _|
|_|  |_|_|_||_|_\___|_||_/_/ \_\_| \__,_|_|\__|
  Router Audit Reporter (Auth-Only) v0.1.0      
    """
    console.print(Panel(ascii_art, style="matrix", title="Matrix", border_style="matrix"))


def handle_sigint(signum, frame):
    console.print("\n[warn]Gracefully stopping...[/warn]")
    sys.exit(130)


def run_cli(argv: Optional[list[str]] = None) -> int:
    import argparse

    signal.signal(signal.SIGINT, handle_sigint)

    parser = argparse.ArgumentParser(
        prog="router-audit",
        description=(
            "Safe, authorization-first router audit reporter. Parses Nmap XML results and generates scored reports."
        ),
    )
    parser.add_argument("xml", help="Path to Nmap XML results (with http-title, http-server-header, http-favicon)")
    parser.add_argument("--kb", required=False, default=str(Path(__file__).with_name("kb.json")), help="Knowledge base JSON path")
    parser.add_argument("--out-dir", default="./audit_report", help="Directory to write reports")
    parser.add_argument("--html", default="report.html", help="HTML report filename")
    parser.add_argument("--json", default="report.json", help="JSON report filename")
    args = parser.parse_args(argv)

    banner()

    xml_path = Path(args.xml)
    kb_path = Path(args.kb)
    out_dir = Path(args.out_dir)
    templates_dir = Path(__file__).with_name("templates")
    assets_dir = Path(__file__).with_name("assets")

    if not xml_path.exists():
        console.print(f"[error]XML not found:[/error] {xml_path}")
        return 2
    if not kb_path.exists():
        console.print(f"[warn]KB not found, using minimal defaults:[/warn] {kb_path}")
        kb = {"brands": {}}
    else:
        kb = json.loads(kb_path.read_text(encoding="utf-8"))

    console.print("[accent]Parsing Nmap XML...[/accent]")
    hosts = parse_nmap_xml(str(xml_path))

    console.print(f"[accent]Analyzing {len(hosts)} hosts...[/accent]")
    analyzed = analyze_hosts(hosts, kb)

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / args.json
    html_path = out_dir / args.html

    save_json_report(analyzed, json_path)
    save_html_report(analyzed, html_path, assets_dir=assets_dir, templates_dir=templates_dir)

    # Console summary
    table = Table(title="Hosts", box=box.SIMPLE, style="matrix")
    table.add_column("Address")
    table.add_column("Open Web Ports")
    table.add_column("Top Brand")
    table.add_column("Login Score")
    for h in analyzed:
        web_ports = [str(p["port"]) for p in h["ports"]]
        best = 0.0
        best_brand = "-"
        best_login = 0.0
        for p in h["ports"]:
            if p["brand"]["score"] > best:
                best = p["brand"]["score"]
                best_brand = p["brand"]["name"] or "-"
            best_login = max(best_login, float(p["login"]["score"]))
        table.add_row(h["address"], ", ".join(web_ports) or "-", best_brand, f"{best_login:.1f}")
    console.print(table)

    console.print(f"[matrix]HTML:[/matrix] {html_path}")
    console.print(f"[matrix]JSON:[/matrix] {json_path}")
    return 0


def main():
    sys.exit(run_cli())


if __name__ == "__main__":
    main()
