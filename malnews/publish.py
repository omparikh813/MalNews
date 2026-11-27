from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
from datetime import date
from pathlib import Path

from .enrich import CVE_ID_RE, band as score_band
from .render import TEMPLATES, jinja_env
from .safety import safe_href

log = logging.getLogger(__name__)

REPO_URL = "https://github.com/omparikh813/Security-News-Daily"
SITE_FILES = ("index.css", "app.js", "theme.js", "favicon.svg")
SEVERITY_LABELS = ("Critical", "High", "Medium", "Low", "None", "Pending")
SECTIONS = (("story_of_week", "Story of the Week"), ("news_of_the_day", "News of the Day"),
            ("new_threats", "New Threats"), ("headlines", "Other Headlines"))
_PDF_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\.pdf$")


def _entry(section: str, v: dict) -> dict:
    top = v["top"]
    fix = v["mitigation"] or next((t for label, t in v.get("parts", []) if label == "Fix"), None)
    return {
        "section": section, "title": v["title"], "summary": v["summary"], "fix": fix,
        "band": top["band"] if top else None, "score": top["score"] if top else None,
        "kev": v["kev"], "zero_day": v["zero_day"],
        "cves": [{"id": c["id"], "band": c["band"], "score": c["score"], "status": c["status"], "kev": c["kev"],
                  "url": c["nvd_url"]} for c in v["cves"]],
        "links": [[publisher, href] for publisher, href in v["links"]],
    }


def _snapshot(snap: dict | None) -> dict | None:
    if not snap:
        return None
    return {"total": snap["total"], "kev": snap["kev"], "zero_days": snap["zero_days"], "highest": snap["highest"],
            "segments": [[s["label"], s["count"]] for s in snap["segments"]]}


def edition_data(context: dict, day: str, pdf_bytes: int) -> dict:
    stories = []
    for key, label in SECTIONS:
        items = context[key]
        for v in ([items] if isinstance(items, dict) else items or []):
            stories.append(_entry(label, v))
    return {
        "date": day, "date_long": context["date_long"], "edition": context["edition"],
        "read_minutes": context["read_minutes"], "generated": context["generated"],
        "snapshot": _snapshot(context["snapshot"]), "stories": stories, "pdf_kb": max(1, round(pdf_bytes / 1024)),
    }


def _text(value, limit: int) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


def _safe_story(raw: dict) -> dict | None:
    """Only known fields survive, and every link must still be a plain https URL."""
    title = _text(raw.get("title"), 300)
    section = raw.get("section")
    if not title or section not in {label for _, label in SECTIONS}:
        return None
    links = [[item[0][:60], item[1]] for item in raw.get("links", [])
             if isinstance(item, list) and len(item) == 2 and isinstance(item[0], str)
             and isinstance(item[1], str) and safe_href(item[1]) == item[1]]
    cves = [{"id": c["id"], "band": _text(c.get("band"), 12), "score": _text(c.get("score"), 5),
             "status": _text(c.get("status"), 12), "kev": c.get("kev") is True, "url": c["url"]}
            for c in raw.get("cves", [])
            if isinstance(c, dict) and CVE_ID_RE.match(str(c.get("id"))) and isinstance(c.get("url"), str)
            and safe_href(c["url"]) == c["url"]]
    return {"section": section, "title": title, "summary": _text(raw.get("summary"), 1500) or "",
            "fix": _text(raw.get("fix"), 600), "band": _text(raw.get("band"), 12), "score": _text(raw.get("score"), 5),
            "kev": raw.get("kev") is True, "zero_day": raw.get("zero_day") is True, "cves": cves, "links": links}


def _clean_snapshot(snap: dict | None) -> dict | None:
    if not snap:
        return None
    segments = [[label, count] for label, count in snap.get("segments", [])
                if label in SEVERITY_LABELS and isinstance(count, int) and count > 0]
    return {"total": int(snap.get("total", 0)), "kev": int(snap.get("kev", 0)), "zero_days": int(snap.get("zero_days", 0)),
            "highest": _text(snap.get("highest"), 5), "segments": segments}


def severity_bar(snap: dict | None) -> list[dict]:
    """Geometry for the SVG bar: x and width as percentages of 100."""
    segments = snap["segments"] if snap else []
    total = sum(count for _, count in segments)
    bar, x = [], 0.0
    for label, count in segments:
        width = count / total * 100
        bar.append({"label": label, "count": count, "cls": label.lower(), "x": f"{x:.2f}", "w": f"{width:.2f}"})
        x += width
    return bar


def headline_groups(data: dict) -> list[tuple[str, list[dict]]]:
    return [(label, items) for _, label in SECTIONS if (items := [s for s in data["stories"] if s["section"] == label])]


def headline_counts(data: dict) -> dict:
    stories = data["stories"]
    return {"all": len(stories), "critical": sum(1 for s in stories if s["band"] == "Critical"),
            "high": sum(1 for s in stories if s["band"] == "High"), "kev": sum(1 for s in stories if s["kev"]),
            "zero": sum(1 for s in stories if s["zero_day"])}


def load_edition(path: Path) -> dict | None:
    """An archived edition's data, or None if the file is missing or unusable."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        date.fromisoformat(raw["date"])
        snap = raw.get("snapshot") if isinstance(raw.get("snapshot"), dict) else None
        return {
            "date": raw["date"], "date_long": _text(raw.get("date_long"), 60) or raw["date"],
            "edition": int(raw.get("edition", 0)), "read_minutes": int(raw.get("read_minutes", 0)),
            "generated": _text(raw.get("generated"), 20) or "", "pdf_kb": int(raw.get("pdf_kb", 0)),
            "snapshot": _clean_snapshot(snap),
            "stories": [st for r in raw["stories"] if isinstance(r, dict) and (st := _safe_story(r))],
        }
    except (OSError, ValueError, KeyError, TypeError) as e:
        log.warning("skipping %s: %s", path.name, e)
        return None


def _archive_row(day: str, data: dict | None) -> dict:
    d = date.fromisoformat(day)
    row = {"day": day, "href": f"archive/{day}.pdf", "label": f"{d:%a} {d:%b} {d.day}", "month": f"{d:%B %Y}"}
    stories = data["stories"] if data else []
    lead = next((s for s in stories if s["section"] == "News of the Day"), stories[0] if stories else None)
    scored = [float(s["score"]) for s in stories if s.get("score")]
    top = max(scored) if scored else None
    row.update(title=lead["title"] if lead else None, count=len(stories), kev=sum(1 for s in stories if s["kev"]),
               highest=f"{top:.1f}" if top is not None else None, band=score_band(top))
    return row


def archive_months(archive: Path) -> list[dict]:
    rows = []
    for pdf in sorted((f for f in archive.iterdir() if _PDF_RE.match(f.name)), reverse=True):
        rows.append(_archive_row(pdf.stem, load_edition(archive / f"{pdf.stem}.json")))
    months: list[dict] = []
    for row in rows:
        if not months or months[-1]["label"] != row["month"]:
            months.append({"label": row["month"], "rows": []})
        months[-1]["rows"].append(row)
    return months


def search_index(archive: Path) -> dict[str, str]:
    """One lowercase string per edition (titles and CVE IDs) for the archive search box."""
    index = {}
    for path in sorted(archive.glob("*.json")):
        if data := load_edition(path):
            index[data["date"]] = " ".join(
                [s["title"] for s in data["stories"]] + [c["id"] for s in data["stories"] for c in s["cves"]]).lower()
    return index


def asset_versions() -> dict[str, str]:
    """A short fingerprint per site file. Browsers cache Pages files for 10 minutes, so each file is linked with
    ?v=<fingerprint>: when a file changes its address changes, and nobody sees a stale copy."""
    return {name: hashlib.sha256((TEMPLATES / name).read_bytes()).hexdigest()[:10] for name in SITE_FILES}


def write_site(pdf: bytes, out_dir: Path, day: str, context: dict) -> None:
    archive = out_dir / "archive"
    archive.mkdir(parents=True, exist_ok=True)
    (out_dir / "data").mkdir(exist_ok=True)
    (archive / f"{day}.pdf").write_bytes(pdf)
    (out_dir / "latest.pdf").write_bytes(pdf)
    data = edition_data(context, day, len(pdf))
    (archive / f"{day}.json").write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    (out_dir / "data" / "search.json").write_text(json.dumps(search_index(archive), separators=(",", ":")), encoding="utf-8")

    today = load_edition(archive / f"{day}.json")
    snap = today["snapshot"] if today else None
    html = jinja_env().get_template("index.html.j2").render(
        today=today, months=archive_months(archive), repo_url=REPO_URL,
        groups=headline_groups(today) if today else [], counts=headline_counts(today) if today else {},
        kpis={"cves": snap["total"] if snap else 0, "kev": snap["kev"] if snap else 0,
              "highest": (snap["highest"] if snap else None) or "–"},
        bar=severity_bar(snap), assets=asset_versions())
    (out_dir / "index.html").write_text(html, encoding="utf-8")
    for name in SITE_FILES:
        shutil.copyfile(TEMPLATES / name, out_dir / name)
