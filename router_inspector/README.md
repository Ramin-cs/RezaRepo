## Router Inspector (Safe)

A safe network auditing tool for authorized environments that:
- Scans specified web ports asynchronously
- Fingerprints potential router web interfaces
- Scores evidence for login pages and brand indicators
- Generates clean JSON and HTML reports

This tool does not attempt login, credential testing, brute force, or evasion. Use only on systems you own or have explicit written permission to assess.

### Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python src/main.py --targets 192.168.1.0/24 --ports 80,443,8080,8081 --out out
```

### Inputs
- `--targets`: Comma-separated items (single IP/host, CIDR, or `@file` path). Examples:
  - `192.168.1.1`
  - `192.168.1.0/24`
  - `@targets.txt` (one target per line)

### Output
- JSON: `out/report.json`
- HTML: `out/report.html`

### Safety
- No credential testing is performed.
- Respect legal and ethical boundaries.
- Obtain explicit authorization before scanning.