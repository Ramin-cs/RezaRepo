from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape


def _load_template_env(templates_dir: Path) -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
        enable_async=False,
    )
    return env


def save_json_report(data: List[Dict], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def save_html_report(data: List[Dict], output_path: Path, assets_dir: Path, templates_dir: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    env = _load_template_env(templates_dir)
    tmpl = env.get_template("report.html.j2")

    css_rel = Path("assets") / "matrix.css"
    html = tmpl.render(results=data, css_path=str(css_rel))
    output_path.write_text(html, encoding="utf-8")

    # Copy assets next to report
    target_assets = output_path.parent / "assets"
    target_assets.mkdir(parents=True, exist_ok=True)
    (target_assets / "matrix.css").write_text((assets_dir / "matrix.css").read_text(encoding="utf-8"), encoding="utf-8")
