import argparse
import asyncio
import os
import signal
from typing import Dict, Any

from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.table import Table

from targets import expand_targets
from scanner import scan_ports_for_targets
from http_fingerprint import fingerprint_http_interfaces
from report import generate_reports
from theme import render_banner


console = Console()


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Router Inspector (Safe): Async web-port scan + fingerprint + report"
	)
	parser.add_argument(
		"--targets",
		type=str,
		required=True,
		help="Comma-separated targets: IP/host, CIDR, or @file path (one per line)"
	)
	parser.add_argument(
		"--ports",
		type=str,
		default=(
			"80,443,8080,8888,8000,8081,8443,8800,8880,8088,8008,"
			"8082,8083,8084,8085,8086,8087,8089,8090"
		),
		help="Comma-separated ports to scan"
	)
	parser.add_argument("--scan-concurrency", type=int, default=800, help="TCP connect concurrency")
	parser.add_argument("--http-concurrency", type=int, default=120, help="HTTP fetch concurrency")
	parser.add_argument("--timeout", type=float, default=3.0, help="TCP/HTTP timeout seconds")
	parser.add_argument("--max-pages", type=int, default=3, help="Max crawl pages per host:port")
	parser.add_argument("--out", type=str, default="out", help="Output directory")
	parser.add_argument("--user-agent", type=str, default="RouterInspectorSafe/1.0", help="HTTP User-Agent")
	parser.add_argument("--no-verify-tls", action="store_true", help="Disable TLS verification for HTTPS")
	return parser.parse_args()


def build_status_table(progress: Dict[str, Any]) -> Table:
	table = Table(title="Router Inspector (Safe) - Progress", expand=True)
	table.add_column("Phase")
	table.add_column("Detail")
	table.add_column("Counts")

	table.add_row("Targets", "Expanded", str(progress.get("num_targets", 0)))
	table.add_row("Scan", "Open web sockets found", str(progress.get("num_open", 0)))
	table.add_row("HTTP", "Interfaces fingerprinted", str(progress.get("num_http", 0)))
	table.add_row("Report", "Written files", ", ".join(progress.get("reports", [])))
	return table


async def main_async() -> None:
	args = parse_args()

	os.makedirs(args.out, exist_ok=True)

	# Graceful shutdown flag
	stop_event = asyncio.Event()

	def handle_sigint(signum, frame):
		console.print("[yellow]\nCtrl+C received. Finishing current tasks and shutting down...[/yellow]")
		stop_event.set()

	signal.signal(signal.SIGINT, handle_sigint)

	console.clear()
	console.print(render_banner())

	progress_state: Dict[str, Any] = {"num_targets": 0, "num_open": 0, "num_http": 0, "reports": []}

	targets = expand_targets(args.targets)
	progress_state["num_targets"] = len(targets)

	with Live(build_status_table(progress_state), console=console, refresh_per_second=8) as live:
		if stop_event.is_set():
			return

		ports = [int(p.strip()) for p in args.ports.split(',') if p.strip()]

		open_map = await scan_ports_for_targets(
			targets=targets,
			ports=ports,
			concurrency=args.scan_concurrency,
			timeout=args.timeout,
			stop_event=stop_event,
		)
		num_open = sum(len(v) for v in open_map.values())
		progress_state["num_open"] = num_open
		live.update(build_status_table(progress_state))

		if stop_event.is_set():
			return

		http_results = await fingerprint_http_interfaces(
			open_map=open_map,
			http_concurrency=args.http_concurrency,
			timeout=args.timeout,
			max_pages=args.max_pages,
			user_agent=args.user_agent,
			verify_tls=not args.no_verify_tls,
			stop_event=stop_event,
		)
		progress_state["num_http"] = sum(len(v) for v in http_results.values())
		live.update(build_status_table(progress_state))

		if stop_event.is_set():
			return

		report_files = generate_reports(
			out_dir=args.out,
			targets=targets,
			open_map=open_map,
			http_results=http_results,
		)
		progress_state["reports"] = [os.path.basename(p) for p in report_files]
		live.update(build_status_table(progress_state))

	console.print(Panel.fit("[bold green]Done.[/bold green] Reports written to: " + ", ".join(report_files)))


def main() -> None:
	try:
		asyncio.run(main_async())
	except KeyboardInterrupt:
		console.print("[yellow]Interrupted by user.[/yellow]")


if __name__ == "__main__":
	main()