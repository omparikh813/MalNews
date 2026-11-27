import json
import re
from datetime import date

import pytest

from malnews.publish import (
    SITE_FILES, archive_months, edition_data, headline_counts, load_edition, search_index, severity_bar, write_site,
)

from .conftest import ROOT

SEGMENTS = [{"label": "Critical", "count": 2, "width": "40%", "cls": "critical"},
            {"label": "Pending", "count": 3, "width": "60%", "cls": "pending"}]


def view(title="Acme VPN flaw exploited", **kw):
    base = {"title": title, "summary": "A short summary.", "mitigation": None, "zero_day": False, "kev": False,
            "top": None, "cves": [], "links": [("BleepingComputer", "https://www.bleepingcomputer.com/a")], "parts": []}
    return {**base, **kw}


def cve(i="CVE-2026-10001", band="Critical", score="9.8"):
    return {"id": i, "band": band, "score": score, "status": "scored", "kev": True, "nvd_url": f"https://nvd.nist.gov/vuln/detail/{i}"}


def context(**kw):
    ctx = {
        "date_long": "Monday, November 16, 2026", "edition": 16, "read_minutes": 4, "generated": "6:00 AM PST",
        "story_of_week": view("Week story", summary="What happened.", parts=[("What happened", "x"), ("Fix", "Patch it.")]),
        "news_of_the_day": [view(top={"band": "Critical", "score": "9.8"}, kev=True, cves=[cve()])],
        "new_threats": [view("Zero-day in Fabrikam gateway", zero_day=True)], "headlines": [view("Other news item here")],
        "snapshot": {"total": 5, "kev": 2, "zero_days": 1, "highest": "9.8", "segments": SEGMENTS},
    }
    return {**ctx, **kw}


def build(tmp_path, days=("2026-11-16",), **kw):
    for day in days:
        write_site(b"%PDF-1.4 fake", tmp_path, day, context(**kw))
    return tmp_path


def test_site_files_are_written(tmp_path):
    build(tmp_path)
    for name in (*SITE_FILES, "index.html", "latest.pdf", "archive/2026-11-16.pdf", "archive/2026-11-16.json", "data/search.json"):
        assert (tmp_path / name).is_file(), name


def test_edition_data_covers_every_section_in_order():
    data = edition_data(context(), "2026-11-16", 40_000)
    assert [(s["section"], s["title"]) for s in data["stories"]] == [
        ("Story of the Week", "Week story"), ("News of the Day", "Acme VPN flaw exploited"),
        ("New Threats", "Zero-day in Fabrikam gateway"), ("Other Headlines", "Other news item here")]
    assert data["stories"][0]["fix"] == "Patch it." and data["stories"][2]["zero_day"] and data["pdf_kb"] == 39
    assert data["snapshot"]["segments"] == [["Critical", 2], ["Pending", 3]]


def test_page_shows_today_headlines_scores_and_links(tmp_path):
    html = (build(tmp_path) / "index.html").read_text()
    for expected in ("Monday, November 16, 2026", "Open today’s PDF", "Today’s headlines", "Critical 9.8", "Known Exploited",
                     "Zero-day", "CVE-2026-10001", "https://nvd.nist.gov/vuln/detail/CVE-2026-10001", "Past editions"):
        assert expected in html, expected


def test_content_policy_allows_only_this_site(tmp_path):
    html = (build(tmp_path) / "index.html").read_text()
    csp = re.search(r'Content-Security-Policy" content="([^"]+)"', html).group(1)
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "object-src 'none'" in csp and "frame-src 'self'" in csp
    assert not re.search(r"<script(?![^>]*\bsrc=)", html), "inline script"
    assert not re.search(r"\sstyle=", html), "inline style attribute"
    assert not re.search(r"\son[a-z]+=", html), "inline event handler"
    assert not re.search(r'(?:src|href)="http://', html)


def test_hostile_text_is_escaped_and_bad_links_never_render(tmp_path):
    evil = view('<img src=x onerror=alert(1)>', summary="<script>alert(2)</script>",
                links=[("<b>Pub</b>", "https://pub.example.com/a")], cves=[])
    html = (build(tmp_path, headlines=[evil]) / "index.html").read_text()
    assert "<img src=x" not in html and "<script>alert" not in html and "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "<b>Pub</b>" not in html


def test_tampered_archive_data_is_cleaned_on_read(tmp_path):
    build(tmp_path)
    path = tmp_path / "archive" / "2026-11-16.json"
    data = json.loads(path.read_text())
    data["stories"][0]["links"] = [["P", "javascript:alert(1)"], ["Q", "https://ok.example.com/a"], ["R", "http://plain.example.com"]]
    data["stories"][0]["cves"] = [{"id": "not-a-cve", "url": "https://x.example.com"}, {"id": "CVE-2026-1111", "url": "javascript:x"}]
    data["stories"][0]["section"] = "Hacked"
    data["stories"].append({"section": "Other Headlines", "title": 7})
    data["evil_field"] = "x"
    path.write_text(json.dumps(data))
    loaded = load_edition(path)
    assert "evil_field" not in loaded and len(loaded["stories"]) == len(data["stories"]) - 2
    assert all(s["section"] != "Hacked" for s in loaded["stories"])


def test_unreadable_archive_files_are_skipped(tmp_path):
    build(tmp_path, days=("2026-11-15", "2026-11-16"))
    (tmp_path / "archive" / "2026-11-15.json").write_text("{not json")
    (tmp_path / "archive" / "2026-11-14.json").write_text(json.dumps({"date": "tomorrow", "stories": []}))
    (tmp_path / "archive" / "2026-11-14.pdf").write_bytes(b"%PDF")
    assert load_edition(tmp_path / "archive" / "2026-11-15.json") is None
    assert set(search_index(tmp_path / "archive")) == {"2026-11-16"}
    build(tmp_path, days=("2026-11-17",))
    html = (tmp_path / "index.html").read_text()
    assert "2026-11-15.pdf" in html and "Daily briefing" in html


def test_archive_is_grouped_by_month_newest_first(tmp_path):
    build(tmp_path, days=("2026-10-31", "2026-11-02", "2026-11-01", "2026-12-05"))
    months = archive_months(tmp_path / "archive")
    assert [m["label"] for m in months] == ["December 2026", "November 2026", "October 2026"]
    assert [r["day"] for r in months[1]["rows"]] == ["2026-11-02", "2026-11-01"]
    row = months[0]["rows"][0]
    assert row["label"] == "Sat Dec 5" and row["title"] == "Acme VPN flaw exploited" and row["highest"] == "9.8" and row["band"] == "Critical"
    assert row["kev"] == 1 and row["count"] == 4


def test_search_index_has_titles_and_cve_ids_in_lowercase(tmp_path):
    build(tmp_path, days=("2026-11-15", "2026-11-16"))
    index = json.loads((tmp_path / "data" / "search.json").read_text())
    assert set(index) == {"2026-11-15", "2026-11-16"}
    assert "acme vpn flaw exploited" in index["2026-11-16"] and "cve-2026-10001" in index["2026-11-16"]


def test_rerunning_a_day_replaces_it(tmp_path):
    build(tmp_path)
    build(tmp_path, headlines=[view("Replacement story")])
    assert len(list((tmp_path / "archive").glob("*.pdf"))) == 1
    assert "Replacement story" in (tmp_path / "index.html").read_text()


def test_severity_bar_fills_the_width():
    bar = severity_bar({"segments": [["Critical", 1], ["High", 3]]})
    assert [(b["label"], b["x"], b["w"]) for b in bar] == [("Critical", "0.00", "25.00"), ("High", "25.00", "75.00")]
    assert severity_bar(None) == []


def test_filter_counts(tmp_path):
    data = load_edition(build(tmp_path) / "archive" / "2026-11-16.json")
    assert headline_counts(data) == {"all": 4, "critical": 1, "high": 0, "kev": 1, "zero": 1}


def test_page_without_cves_still_builds(tmp_path):
    ctx = context(snapshot=None, news_of_the_day=[view("A breach with no CVE at all")])
    write_site(b"%PDF", tmp_path, "2026-11-16", ctx)
    html = (tmp_path / "index.html").read_text()
    assert "A breach with no CVE at all" in html and "<svg" not in html and ">–<" in html


@pytest.mark.parametrize("name", ["app.js", "theme.js"])
def test_scripts_never_build_html_from_data(name):
    source = (ROOT / "templates" / name).read_text()
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setTimeout(\""):
        assert banned not in source, banned


def test_scripts_only_talk_to_this_site():
    source = (ROOT / "templates" / "app.js").read_text()
    assert re.findall(r'fetch\("([^"]+)"', source) == ["data/search.json"]
    assert "http://" not in source and "https://" not in source


def test_archive_row_dates_parse():
    assert date.fromisoformat("2026-11-16").strftime("%a") == "Mon"


def test_site_files_are_linked_with_a_version_that_tracks_their_content(tmp_path, monkeypatch):
    html = (build(tmp_path) / "index.html").read_text()
    versions = dict(re.findall(r'(?:href|src)="((?:index\.css|app\.js|theme\.js|favicon\.svg))\?v=([0-9a-f]{10})"', html))
    assert set(versions) == set(SITE_FILES)

    from malnews import publish

    before = publish.asset_versions()
    css = ROOT / "templates" / "index.css"
    monkeypatch.setattr(publish, "TEMPLATES", tmp_path)
    for name in SITE_FILES:
        (tmp_path / name).write_text("same")
    same = publish.asset_versions()
    (tmp_path / "index.css").write_text("changed")
    changed = publish.asset_versions()
    assert before["index.css"] == versions["index.css"] and css.exists()
    assert same["app.js"] == changed["app.js"] and same["index.css"] != changed["index.css"]
