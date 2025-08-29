import ipaddress
from typing import List


def _load_file(path: str) -> List[str]:
	items: List[str] = []
	with open(path, "r", encoding="utf-8", errors="ignore") as f:
		for line in f:
			s = line.strip()
			if not s or s.startswith("#"):
				continue
			items.append(s)
	return items


def expand_targets(spec: str) -> List[str]:
	raw_items: List[str] = []
	for part in spec.split(","):
		s = part.strip()
		if not s:
			continue
		if s.startswith("@"):
			raw_items.extend(_load_file(s[1:]))
		else:
			raw_items.append(s)

	final_targets: List[str] = []

	for item in raw_items:
		try:
			if "/" in item:
				net = ipaddress.ip_network(item, strict=False)
				for host in net.hosts():
					final_targets.append(str(host))
			else:
				# Single IP or hostname
				final_targets.append(item)
		except ValueError:
			# Treat as hostname or invalid IP – include as-is
			final_targets.append(item)

	# De-duplicate while preserving order
	seen = set()
	unique_targets: List[str] = []
	for t in final_targets:
		if t not in seen:
			seen.add(t)
			unique_targets.append(t)
	return unique_targets