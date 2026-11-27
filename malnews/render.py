from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from weasyprint import HTML

from .enrich import CVE_ID_RE, CveInfo, KevEntry
from .images import StoryImage
from .models import Story
from .rank import similar_titles
from .safety import RenderURLFetcher, safe_href
from .settings import Config
from .state import StoryOfWeek, StoryRecord, WeeklyContent

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"
FONTS = ROOT / "fonts"


def jinja_env() -> Environment:
    # Autoescape everything; templates never use |safe on external data.
    return Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _words(*texts: str | None) -> int:
    return sum(len(re.findall(r"\S+", t or "")) for t in texts)


def _cve_view(i: CveInfo) -> dict | None:
    if not CVE_ID_RE.match(i.id):
        return None
    return {
        "id": i.id,
        # Both records are linked; the ID is regex-checked, so it is safe in a URL.
        "cve_url": f"https://www.cve.org/CVERecord?id={i.id}",
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{i.id}",
        "score": f"{i.cvss:.1f}" if i.cvss is not None else None,
        "band": i.band,
        "status": i.status,
        "kev": i.kev,
        "kev_detail": _kev_detail(i.kev_entry),
        "epss": f"{i.epss:.0%}" if i.epss is not None else None,
    }


def _day(d) -> str:
    return f"{d:%b} {d.day}"


def _kev_detail(k: KevEntry | None) -> str | None:
    if not k:
        return None
    parts = [f"{k.vendor} {k.product}".strip()]
    if k.due:
        parts.append(f"federal fix due {_day(k.due)}")
    if k.ransomware:
        parts.append("used in ransomware")
    return " · ".join(p for p in parts if p)


def _roundup_view(i: CveInfo) -> dict:
    k = i.kev_entry
    v = _cve_view(i)
    return {
        **v,
        "vendor": f"{k.vendor} {k.product}".strip()[:38] if k else "",
        "name": (k.name[:56].rstrip() + "…") if k and len(k.name) > 56 else (k.name if k else ""),
        "added": _day(k.added) if k and k.added else "",
        "ransomware": bool(k and k.ransomware),
    }


def _cve_views(infos: list[CveInfo]) -> list[dict]:
    return [v for i in infos if (v := _cve_view(i))]


def _top_band(cves: list[dict]) -> dict | None:
    scored = [c for c in cves if c["score"] is not None]
    return max(scored, key=lambda c: float(c["score"]), default=None)


def _links(pairs) -> list[tuple[str, str]]:
    # Links come only from feed metadata, re-checked here.
    return [(p, h) for p, u in pairs if (h := safe_href(u))]


def _image_view(image: StoryImage | None, title: str) -> dict | None:
    href = safe_href(image.link) if image else None
    if not image or not href:
        return None
    return {"src": image.path.resolve().as_uri(), "credit": image.credit, "href": href, "alt": title}


def _view(title, summary, mitigation, links, cves, image=None, zero_day=False) -> dict:
    return {
        "title": title, "summary": summary or "", "mitigation": mitigation, "zero_day": zero_day,
        "links": _links(links), "cves": cves, "top": _top_band(cves), "kev": any(c["kev"] for c in cves),
        "image": _image_view(image, title),
        "words": _words(title, summary, mitigation) + 2 * len(links) + 4 * len(cves),
    }


def story_view(s: Story, image: StoryImage | None = None) -> dict:
    sm = s.summary
    return _view(s.title, sm.summary if sm else "", sm.mitigation if sm else None, s.links,
                 _cve_views(s.cve_infos), image, s.zero_day)


def _record_cves(record: StoryRecord, infos: dict[str, CveInfo], cfg: Config) -> list[dict]:
    found = sorted((infos[c] for c in record.cves if c in infos), key=lambda i: -i.priority(cfg))
    return _cve_views(found[: cfg.enrich.max_cves_per_story])


def usable(content: WeeklyContent | None) -> bool:
    return content is not None and not content.is_excerpt


def record_summary(record: StoryRecord, content: WeeklyContent | None = None) -> str | None:
    return record.summary or (content.what_happened if usable(content) else None)


def record_view(record: StoryRecord, infos: dict[str, CveInfo], cfg: Config, summary: str,
                image: StoryImage | None = None) -> dict:
    return _view(record.title, summary, None, [(lk.publisher, lk.url) for lk in record.links],
                 _record_cves(record, infos, cfg), image)


def weekly_view(sw: StoryOfWeek, infos: dict[str, CveInfo], cfg: Config,
                image: StoryImage | None = None) -> dict:
    content = sw.content
    v = record_view(sw.story, infos, cfg, content.what_happened, image)
    v.update({
        "parts": [(label, text) for label, text in (
            ("What happened", content.what_happened), ("Who is affected", content.who_affected),
            ("What changed", content.what_changed), ("Fix", content.mitigation)) if text],
        "updated": f"Updated {sw.updated_on:%A}" if sw.updated_on else None,
    })
    v["words"] = _words(v["title"], *(t for _, t in v["parts"])) + 2 * len(v["links"]) + 4 * len(v["cves"])
    return v


def same_event(s: Story, record: StoryRecord, cfg: Config) -> bool:
    return s.id == record.id or bool(s.cves & set(record.cves)) or similar_titles(s.title, record.title, cfg)


def sections(stories: list[Story], sotw: StoryRecord | None, cfg: Config) -> tuple[list, list, list]:
    remaining = [s for s in stories if not (sotw and same_event(s, sotw, cfg))]
    n = cfg.ranking.news_of_the_day
    top, rest = remaining[:n], remaining[n:]
    return top, [s for s in rest if s.zero_day], [s for s in rest if not s.zero_day]


SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "None")


def snapshot(views: list[dict], zero_days: int) -> dict | None:
    """Counts of the distinct CVEs printed in the edition, for the strip under the masthead."""
    cves = {c["id"]: c for v in views for c in v["cves"]}.values()
    if not cves:
        return None
    counts = {name: sum(1 for c in cves if c["band"] == name) for name in SEVERITY_ORDER}
    counts["Pending"] = sum(1 for c in cves if c["score"] is None)
    total = len(cves)
    shown = {name: n for name, n in counts.items() if n}
    raw = {name: max(n / total * 100, 11.0) for name, n in shown.items()}
    scale = 100 / sum(raw.values())
    scores = [float(c["score"]) for c in cves if c["score"] is not None]
    return {
        "segments": [{"label": name, "count": n, "width": f"{raw[name] * scale:.1f}%", "cls": name.lower()}
                     for name, n in shown.items()],
        "total": total, "kev": sum(1 for c in cves if c["kev"]), "zero_days": zero_days,
        "highest": f"{max(scores):.1f}" if scores else None,
    }


FIXED_WORDS = 150  # masthead, section headings, footer


@dataclass
class Edition:
    context: dict
    words: int
    dropped: int


def build_edition(stories: list[Story], cfg: Config, now: datetime, source_names: list[str],
                  sotw: StoryOfWeek | None = None, replaced: StoryRecord | None = None,
                  infos: dict[str, CveInfo] | None = None, replaced_summary: str | None = None,
                  images: dict[str, StoryImage] | None = None, kev_candidates: list[CveInfo] | None = None) -> Edition:
    """Every story shown has an AI summary; stories without one are left out."""
    infos, images = infos or {}, images or {}
    stories = [s for s in stories if s.summary]
    top, threats, others = sections(stories, sotw.story if sotw else None, cfg)
    weekly = weekly_view(sotw, infos, cfg, images.get(sotw.story.id)) if sotw and usable(sotw.content) else None
    top_v = [story_view(s, images.get(s.id) if i == 0 else None) for i, s in enumerate(top)]
    threat_v = [story_view(s) for s in threats]
    # The replaced pick moves to Other Headlines on the day it is replaced.
    replaced_v = [record_view(replaced, infos, cfg, replaced_summary)] if replaced and replaced_summary else []
    other_v = replaced_v + [story_view(s) for s in others]

    words = FIXED_WORDS + sum(v["words"] for v in (*top_v, *threat_v, *other_v)) + (weekly["words"] if weekly else 0)
    dropped = 0
    while other_v and words > cfg.layout.max_words:
        words -= other_v.pop()["words"]
        dropped += 1

    local = now.astimezone(timezone(timedelta(hours=cfg.edition.utc_offset_hours)))
    edition_no = max((local.date() - cfg.edition.launch_date).days + 1, 1)
    context = {
        "date_long": f"{local:%A, %B} {local.day}, {local.year}",
        "edition": edition_no,
        "read_minutes": max(1, math.ceil(words / cfg.layout.words_per_minute)),
        "generated": f"{local:%I:%M %p} PST".lstrip("0"),
        "story_of_week": weekly,
        "news_of_the_day": top_v,
        "new_threats": threat_v,
        "headlines": other_v,
        "sources": source_names,
    }
    views = [v for v in (weekly, *top_v, *threat_v, *other_v) if v]
    context["snapshot"] = snapshot(views, sum(1 for s in (*top, *threats, *others) if s.zero_day))
    printed = {c["id"] for v in views for c in v["cves"]}
    context["roundup"] = [_roundup_view(i) for i in (kev_candidates or []) if i.id not in printed][
        : cfg.roundup.max_rows]
    return Edition(context, words, dropped)


@dataclass
class RenderResult:
    pdf: bytes
    blocked: list[str]
    pages: int = 0
    roundup_rows: int = 0


def _layout(html: str, image_dir: Path | None) -> tuple[HTML, RenderURLFetcher]:
    fetcher = RenderURLFetcher([TEMPLATES, FONTS, *([image_dir] if image_dir else [])])
    return HTML(string=html, base_url=str(TEMPLATES) + "/", url_fetcher=fetcher), fetcher


def _finish(document, fetcher: RenderURLFetcher, rows: int = 0) -> RenderResult:
    meta = document.metadata
    meta.attachments = []  # never embed files, whatever the HTML asks for
    meta.authors, meta.keywords, meta.description = [], [], None
    meta.generator = None
    meta.custom = {}
    return RenderResult(document.write_pdf(), fetcher.blocked, len(document.pages), rows)


def render_html_to_pdf(html: str, image_dir: Path | None = None) -> RenderResult:
    """The renderer can read only templates/, fonts/ and the image folder."""
    page, fetcher = _layout(html, image_dir)
    return _finish(page.render(), fetcher)


def fit_rows(pages_for, total: int, min_rows: int) -> int:
    """The most rows that keep the page count at what it is with none; 0 if even min_rows would add a page."""
    if total < min_rows:
        return 0
    base = pages_for(0)
    if pages_for(min_rows) > base:
        return 0
    low, high, best = min_rows, total, min_rows
    while low <= high:
        mid = (low + high) // 2
        if pages_for(mid) <= base:
            best, low = mid, mid + 1
        else:
            high = mid - 1
    return best


def render_pdf(edition: Edition, image_dir: Path | None = None, min_rows: int = 4) -> RenderResult:
    """Renders the edition, with as many Known Exploited roundup rows as fit on the last page."""
    template = jinja_env().get_template("edition.html.j2")
    rows = edition.context["roundup"]

    def layout(n: int):
        page, fetcher = _layout(template.render(**{**edition.context, "roundup": rows[:n]}), image_dir)
        return page.render(), fetcher

    fit = fit_rows(lambda n: len(layout(n)[0].pages), len(rows), min_rows)
    document, fetcher = layout(fit)
    return _finish(document, fetcher, fit)
