import json
import os
from typing import Dict, List, Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


def _ensure_dir(path: str) -> None:
	os.makedirs(path, exist_ok=True)


def generate_reports(
	out_dir: str,
	targets: List[str],
	open_map: Dict[str, List[int]],
	http_results: Dict[str, List[Dict[str, Any]]],
) -> List[str]:
	_ensure_dir(out_dir)
	data = {
		"targets": targets,
		"open_map": open_map,
		"http_results": http_results,
	}
	json_path = os.path.join(out_dir, "report.json")
	with open(json_path, "w", encoding="utf-8") as f:
		json.dump(data, f, ensure_ascii=False, indent=2)

	env = Environment(
		loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "..", "templates")),
		autoescape=select_autoescape(["html", "xml"]) 
	)
	template = env.get_template("report.html.j2")
	html = template.render(data=data)
	html_path = os.path.join(out_dir, "report.html")
	with open(html_path, "w", encoding="utf-8") as f:
		f.write(html)
	return [json_path, html_path]