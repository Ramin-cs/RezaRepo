import asyncio
from typing import Dict, List, Set


async def _probe(host: str, port: int, timeout: float) -> bool:
	try:
		conn = asyncio.open_connection(host=host, port=port)
		reader, writer = await asyncio.wait_for(conn, timeout=timeout)
		writer.close()
		try:
			await writer.wait_closed()
		except Exception:
			pass
		return True
	except Exception:
		return False


async def scan_ports_for_targets(
	targets: List[str],
	ports: List[int],
	concurrency: int,
	timeout: float,
	stop_event: asyncio.Event,
) -> Dict[str, List[int]]:
	semaphore = asyncio.Semaphore(concurrency)
	result: Dict[str, Set[int]] = {t: set() for t in targets}

	async def task(host: str, port: int):
		if stop_event.is_set():
			return
		async with semaphore:
			if await _probe(host, port, timeout):
				result[host].add(port)

	tasks = [task(host, port) for host in targets for port in ports]
	await asyncio.gather(*tasks, return_exceptions=True)
	return {k: sorted(list(v)) for k, v in result.items() if v}