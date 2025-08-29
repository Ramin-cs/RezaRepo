from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .nmap_parser import HostInfo, PortInfo, ServiceInfo


@dataclass
class BrandMatch:
    brand: Optional[str]
    model: Optional[str]
    score: float
    matched_indicators: List[str]


def score_brand(service: ServiceInfo, kb: Dict) -> BrandMatch:
    indicators_hit: List[str] = []
    best_brand: Optional[str] = None
    best_model: Optional[str] = None
    best_score: float = 0.0

    http_title = (service.http_title or "").lower()
    server_hdr = (service.http_server_header or "").lower()
    product = (service.product or "").lower()
    name = (service.name or "").lower()
    favicon = (service.http_favicon_md5 or "").lower()

    for brand, meta in kb.get("brands", {}).items():
        brand_score = 0.0
        these_hits: List[str] = []
        indicators = meta.get("indicators", {})

        for ind in indicators.get("title_contains", []):
            if ind.lower() in http_title:
                brand_score += 1.0
                these_hits.append(f"title:{ind}")

        for ind in indicators.get("server_header_contains", []):
            if ind.lower() in server_hdr:
                brand_score += 1.0
                these_hits.append(f"server:{ind}")

        for ind in indicators.get("product_contains", []):
            if ind.lower() in product:
                brand_score += 1.0
                these_hits.append(f"product:{ind}")

        for ind in indicators.get("service_name_contains", []):
            if ind.lower() in name:
                brand_score += 0.5
                these_hits.append(f"service:{ind}")

        for ind in indicators.get("favicon_md5", []):
            if ind.lower() in favicon:
                brand_score += 2.0
                these_hits.append(f"favicon:{ind}")

        # Normalize slightly by number of distinct families matched
        if brand_score > best_score:
            best_score = brand_score
            best_brand = brand
            best_model = None  # Model inference optional; requires deeper signatures
            indicators_hit = these_hits

    return BrandMatch(brand=best_brand, model=best_model, score=best_score, matched_indicators=indicators_hit)


def score_login_page(service: ServiceInfo) -> Tuple[float, List[str]]:
    score = 0.0
    hits: List[str] = []

    title = (service.http_title or "")
    server_hdr = (service.http_server_header or "")

    # Heuristics for login pages
    title_lower = title.lower()
    if any(k in title_lower for k in ["login", "sign in", "router", "webfig", "webui", "administration", "firewall", "gateway"]):
        score += 1.5
        hits.append(f"title:{title}")

    if any(k in server_hdr.lower() for k in ["boa", "routeros", "thttpd", "goahead", "ubiquiti", "mikrotik", "tp-link", "huawei", "zte", "tomcat", "jetty", "lighttpd", "nginx"]):
        score += 0.5
        hits.append(f"server:{server_hdr}")

    if service.product and any(k in service.product.lower() for k in ["router", "routeros", "openwrt", "dd-wrt", "airmax", "edgeos"]):
        score += 0.5
        hits.append(f"product:{service.product}")

    return score, hits


def analyze_hosts(hosts: List[HostInfo], kb: Dict) -> List[Dict]:
    results: List[Dict] = []
    for host in hosts:
        host_entry: Dict = {
            "address": host.address,
            "hostnames": host.hostnames,
            "os": host.os,
            "ports": [],
        }

        for port in host.ports:
            service = port.service
            brand_match = score_brand(service, kb)
            login_score, login_hits = score_login_page(service)

            port_entry = {
                "port": port.port,
                "protocol": port.protocol,
                "state": port.state,
                "reason": port.reason,
                "service": {
                    "name": service.name,
                    "product": service.product,
                    "version": service.version,
                    "tunnel": service.tunnel,
                    "extrainfo": service.extrainfo,
                    "http_title": service.http_title,
                    "http_server_header": service.http_server_header,
                    "http_favicon_md5": service.http_favicon_md5,
                },
                "brand": {
                    "name": brand_match.brand,
                    "model": brand_match.model,
                    "score": brand_match.score,
                    "matched_indicators": brand_match.matched_indicators,
                },
                "login": {
                    "score": login_score,
                    "matched_indicators": login_hits,
                },
            }
            host_entry["ports"].append(port_entry)

        results.append(host_entry)
    return results
