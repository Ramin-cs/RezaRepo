from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import xml.etree.ElementTree as ET


@dataclass
class ServiceInfo:
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    tunnel: Optional[str] = None
    extrainfo: Optional[str] = None
    http_title: Optional[str] = None
    http_server_header: Optional[str] = None
    http_favicon_md5: Optional[str] = None
    scripts: Dict[str, str] = field(default_factory=dict)


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    reason: Optional[str] = None
    service: ServiceInfo = field(default_factory=ServiceInfo)


@dataclass
class HostInfo:
    address: str
    hostnames: List[str] = field(default_factory=list)
    ports: List[PortInfo] = field(default_factory=list)
    os: Optional[str] = None


def _get_text(elem: Optional[ET.Element], attr: str) -> Optional[str]:
    if elem is None:
        return None
    return elem.attrib.get(attr)


def parse_nmap_xml(xml_path: str) -> List[HostInfo]:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    hosts: List[HostInfo] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.attrib.get("state") != "up":
            continue

        addr_elem = host.find("address[@addrtype='ipv4']") or host.find("address")
        if addr_elem is None:
            continue
        address = addr_elem.attrib.get("addr")
        if not address:
            continue

        hostnames = [hn.attrib.get("name") for hn in host.findall("hostnames/hostname") if hn.attrib.get("name")]

        host_info = HostInfo(address=address, hostnames=hostnames)

        # OS (optional)
        os_elem = host.find("os/osmatch")
        if os_elem is not None:
            host_info.os = os_elem.attrib.get("name")

        for port_elem in host.findall("ports/port"):
            protocol = port_elem.attrib.get("protocol", "tcp")
            port_id = int(port_elem.attrib.get("portid", "0"))
            state_elem = port_elem.find("state")
            state = state_elem.attrib.get("state") if state_elem is not None else "unknown"
            reason = state_elem.attrib.get("reason") if state_elem is not None else None

            service_elem = port_elem.find("service")
            service = ServiceInfo(
                name=_get_text(service_elem, "name"),
                product=_get_text(service_elem, "product"),
                version=_get_text(service_elem, "version"),
                tunnel=_get_text(service_elem, "tunnel"),
                extrainfo=_get_text(service_elem, "extrainfo"),
            )

            # Parse scripts for HTTP-related data
            for script in port_elem.findall("script"):
                sid = script.attrib.get("id")
                out = script.attrib.get("output")
                if not sid or not out:
                    continue
                service.scripts[sid] = out
                if sid == "http-title":
                    service.http_title = out
                elif sid == "http-server-header":
                    service.http_server_header = out
                elif sid in ("http-favicon", "http-favicon-hash"):
                    service.http_favicon_md5 = out

            host_info.ports.append(
                PortInfo(
                    port=port_id,
                    protocol=protocol,
                    state=state,
                    reason=reason,
                    service=service,
                )
            )

        # Only keep hosts with at least one open port
        host_info.ports = [p for p in host_info.ports if p.state == "open"]
        if host_info.ports:
            hosts.append(host_info)

    return hosts
