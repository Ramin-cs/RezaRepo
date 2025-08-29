import asyncio
from typing import Dict, List, Any, Tuple
from urllib.parse import urljoin

import aiohttp
from bs4 import BeautifulSoup


DEFAULT_WEB_PORTS = {80: "http", 8080: "http", 8000: "http", 8081: "http", 8888: "http", 8800: "http", 8880: "http", 8088: "http", 8008: "http", 8082: "http", 8083: "http", 8084: "http", 8085: "http", 8086: "http", 8087: "http", 8089: "http", 8090: "http", 443: "https", 8443: "https"}


def _base_url(host: str, port: int, scheme_hint: str | None = None) -> str:
	if scheme_hint:
		scheme = scheme_hint
	else:
		scheme = DEFAULT_WEB_PORTS.get(port, "http")
	return f"{scheme}://{host}:{port}/"


async def _fetch(session: aiohttp.ClientSession, url: str, timeout: float) -> Tuple[int | None, str, Dict[str, str]]:
	try:
		async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
			status = resp.status
			text = await resp.text(errors="ignore")
			headers = {k.lower(): v for k, v in resp.headers.items()}
			return status, text, headers
	except Exception:
		return None, "", {}


def _score_login_and_brand(url: str, status: int | None, html: str, headers: Dict[str, str]) -> Dict[str, Any]:
	score = 0
	reasons: List[str] = []
	brand: str | None = None
	model: str | None = None
	soup = BeautifulSoup(html or "", "html.parser")

	# Indicators
	title_text = (soup.title.text.strip() if soup.title else "").lower()
	meta_gen = "".join(m.get("content", "").lower() for m in soup.find_all("meta", attrs={"name": "generator"}))
	meta_desc = "".join(m.get("content", "").lower() for m in soup.find_all("meta", attrs={"name": "description"}))
	body_text = soup.get_text(" ", strip=True).lower()[:5000]
	favicon = soup.find("link", rel=lambda v: v and "icon" in v.lower())
	forms = soup.find_all("form")
	inputs = soup.find_all("input")

	# Basic auth indicator from headers
	www_auth = headers.get("www-authenticate", "").lower()
	if "basic" in www_auth:
		score += 2
		reasons.append("Header indicates Basic auth")

	# Login keywords
	keywords = ["login", "sign in", "administrator", "router", "gateway"]
	if any(k in title_text for k in keywords):
		score += 1
		reasons.append("Title has login/router keywords")
	if any(k in meta_desc for k in keywords) or any(k in meta_gen for k in keywords):
		score += 1
		reasons.append("Meta mentions login/router")
	if any(k in body_text for k in ["password", "username", "admin"]):
		score += 1
		reasons.append("Body mentions credentials")

	# Forms
	if forms:
		score += 1
		reasons.append("Has HTML form(s)")
		# Check for username/password inputs
		input_names = " ".join((i.get("name") or i.get("id") or "").lower() for i in inputs)
		if any(n in input_names for n in ["user", "login", "name"]):
			score += 1
			reasons.append("Username-like input present")
		if any((i.get("type") or "").lower() == "password" for i in inputs):
			score += 2
			reasons.append("Password input present")

	# Favicon / logos
	if favicon and (".ico" in (favicon.get("href") or "") or "icon" in (favicon.get("rel") or [])):
		score += 1
		reasons.append("Has favicon/icon")

	# Server header / X-Powered-By
	server = headers.get("server", "").lower()
	x_powered = headers.get("x-powered-by", "").lower()
	if server:
		reasons.append(f"Server: {server}")
	if x_powered:
		reasons.append(f"X-Powered-By: {x_powered}")

	# Very simple brand heuristics (extendable with data file)
	brand_markers = {
		"mikrotik": ["mikrotik", "routeros"],
		"tp-link": ["tp-link", "tplink"],
		"d-link": ["d-link", "dlink"],
		"huawei": ["huawei"],
		"zte": ["zte"],
		"tenda": ["tenda"],
		"netgear": ["netgear"],
		"asus": ["asus"],
		"ubiquiti": ["ubiquiti", "unifi", "edgemax", "airos"],
		"cisco": ["cisco"],
		"juniper": ["juniper", "junOS".lower()],
	}
	blob = "\n".join([title_text, meta_desc, body_text, server, x_powered])
	for b, indicators in brand_markers.items():
		if any(ind in blob for ind in indicators):
			brand = b
			score += 2
			reasons.append(f"Brand indicators: {b}")
			break

	# Thresholds
	login_detected = score >= 4
	brand_detected = brand is not None

	return {
		"url": url,
		"status": status,
		"score": score,
		"login_detected": login_detected,
		"brand": brand,
		"model": model,
		"reasons": reasons[:12],
	}


async def fingerprint_http_interfaces(
	open_map: Dict[str, List[int]],
	http_concurrency: int,
	timeout: float,
	max_pages: int,
	user_agent: str,
	verify_tls: bool,
	stop_event: asyncio.Event,
) -> Dict[str, List[Dict[str, Any]]]:
	results: Dict[str, List[Dict[str, Any]]] = {}
	semaphore = asyncio.Semaphore(http_concurrency)

	conn = aiohttp.TCPConnector(ssl=verify_tls)
	headers = {"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}

	async with aiohttp.ClientSession(connector=conn, headers=headers) as session:
		async def crawl_one(host: str, port: int):
			if stop_event.is_set():
				return
			async with semaphore:
				base = _base_url(host, port)
				pages_to_try = [base]
				visited = set()
				items: List[Dict[str, Any]] = []
				while pages_to_try and len(visited) < max_pages:
					url = pages_to_try.pop(0)
					if url in visited:
						continue
					visited.add(url)
					status, html, hdrs = await _fetch(session, url, timeout)
					items.append(_score_login_and_brand(url, status, html, hdrs))
					if not html:
						continue
					soup = BeautifulSoup(html, "html.parser")
					for a in soup.find_all("a", href=True):
						href = a.get("href")
						if not href:
							continue
						if href.startswith("javascript:"):
							continue
						candidate = urljoin(url, href)
						if host not in candidate:
							continue
						if any(k in candidate.lower() for k in ["login", "admin", "index", "user", "manage"]):
							pages_to_try.append(candidate)
				return host, port, items

			return None

		tasks = []
		for host, ports in open_map.items():
			for port in ports:
				tasks.append(crawl_one(host, port))
		for res in await asyncio.gather(*tasks, return_exceptions=True):
			if not res or isinstance(res, Exception):
				continue
			host, port, items = res
			key = f"{host}:{port}"
			results.setdefault(key, []).extend(items)
	return results