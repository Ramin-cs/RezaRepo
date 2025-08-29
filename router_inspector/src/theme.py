from rich.panel import Panel
from rich.text import Text


def render_banner() -> Panel:
	text = Text()
	text.append("\n")
	text.append("  ██████  ██████  ██    ██ ████████ ███████ ██████  \n", style="bold green")
	text.append("  ██   ██ ██   ██ ██    ██    ██    ██      ██   ██ \n", style="green")
	text.append("  ██   ██ ██████  ██    ██    ██    █████   ██████  \n", style="bold green")
	text.append("  ██   ██ ██   ██ ██    ██    ██    ██      ██   ██ \n", style="green")
	text.append("  ██████  ██   ██  ██████     ██    ███████ ██   ██ \n", style="bold green")
	text.append("\n   Router Inspector (Safe)  |  Async Scan · Fingerprint · Report\n", style="bold bright_green")
	text.append("   Authorized use only. No credential testing.\n\n", style="bright_black")
	return Panel.fit(text, border_style="green")