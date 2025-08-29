# Router Audit Reporter (Authorization-First)

This tool is a safe, non-invasive reporter designed to parse existing Nmap XML results and generate a clean HTML/JSON report with confidence scoring for likely router brands and potential login portals. It does not scan, brute-force, or attempt to authenticate. Use it only in authorized environments.

## Features
- Parse Nmap XML (hosts, open web ports, http-title, server headers, favicon hashes if present)
- Confidence-based scoring for brand identification and presence of a login portal
- Matrix-themed HTML and JSON reports with per-IP cards
- Minimal knowledge base (`router_audit/kb.json`) extensible by users
- CLI with graceful Ctrl+C

## Installation
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Prepare Nmap XML
Run Nmap separately (authorized ranges only). Example with HTTP NSE scripts:
```bash
nmap -p 80,443,8000,8008,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8443,8800,8880,8888 \
  --script http-title,http-server-header,http-favicon \
  -oX scan.xml <targets>
```

## Usage
```bash
python -m router_audit.cli scan.xml --out-dir out
```
Generated files:
- `out/report.html`
- `out/report.json`

## Extending Knowledge Base
Edit `router_audit/kb.json` and add brands, indicators, and defaults as needed.

## Scope & Ethics
- Authorization-first. No scanning, auth attempts, or brute-force is performed by this tool.
- Intended for internal validation and reporting where data was collected lawfully.