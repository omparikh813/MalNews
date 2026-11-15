from __future__ import annotations

import io
from datetime import date, timedelta

import pypdf
import pytest

from malnews.enrich import CveInfo, KevEntry
from malnews.models import Story, Summary
from malnews.render import build_edition, render_pdf
from malnews.state import LinkRecord, StoryOfWeek, StoryRecord, WeeklyContent

from .conftest import NOW, image_bytes, make_article

SENT = ("Attackers are exploiting the flaw to gain initial access to corporate networks and deploy "
        "web shells for persistence. ")


def full_edition(cfg, n_stories=16, images=None):
    infos = {
        "CVE-2026-10001": CveInfo("CVE-2026-10001", "scored", 9.8, "3.1", kev=True, epss=0.94),
        "CVE-2026-10002": CveInfo("CVE-2026-10002", "scored", 7.5, "3.1", epss=0.12),
        "CVE-2026-10003": CveInfo("CVE-2026-10003", "pending"),
        "CVE-2026-10004": CveInfo("CVE-2026-10004", "unavailable"),
    }
    stories = []
    for i in range(n_stories):
        cves = list(infos)[i % 4: i % 4 + 1] if i % 3 == 0 else []
        s = Story(articles=[make_article(f"Story number {i} about a security incident at a vendor",
                                         url=f"https://news.example.com/{i}", cves=cves)])
        s.cve_infos = [infos[c] for c in cves]
        s.zero_day = i in (4, 7)
        s.score = 1 - i / 100
        s.summary = Summary(SENT * 2, "Apply the vendor update and rotate credentials." if i % 2 else None)
        stories.append(s)
    weekly = StoryOfWeek(
        story=StoryRecord(id="https://news.example.com/sotw", day=date(2026, 10, 27), title="Week's biggest breach story",
                          score=0.9, links=[LinkRecord(publisher="CISA", url="https://www.cisa.gov/a")],
                          cves=["CVE-2026-10001"], text="Body."),
        content=WeeklyContent(what_happened=SENT * 2, who_affected=SENT, what_changed=SENT, mitigation=SENT),
        set_on=date(2026, 10, 27), updated_on=date(2026, 10, 29))
    replaced = StoryRecord(id="https://news.example.com/old", day=date(2026, 10, 26), title="Last pick of the week",
                           score=0.5, links=[LinkRecord(publisher="Krebs", url="https://krebsonsecurity.com/x")],
                           text="Previous pick summary sentence. Another one.", summary=None)
    return build_edition(stories, cfg, NOW, ["CISA", "Krebs"], weekly, replaced, infos,
                         replaced_summary="The previous pick, summarized by AI when it was chosen.", images=images)


def pdf_text(pdf):
    reader = pypdf.PdfReader(io.BytesIO(pdf))
    return reader, " ".join(p.extract_text() for p in reader.pages)


def test_full_edition_is_three_to_four_pages(cfg, no_network):
    edition = full_edition(cfg)
    assert edition.words <= cfg.layout.max_words
    result = render_pdf(edition)
    reader, text = pdf_text(result.pdf)
    assert 2 <= len(reader.pages) <= 4, len(reader.pages)
    assert len(result.pdf) < 1_000_000 and result.blocked == []

    for expected in ("Story of the Week", "Updated Thursday", "What happened", "Who is affected",
                     "News of the Day", "New Threats", "Other Headlines", "Last pick of the week",
                     "Critical 9.8", "High 7.5", "Score pending", "Score unavailable", "Known Exploited", "EPSS 94%"):
        # Badges print in capitals and pypdf may split them ("UNAV AILABLE"): compare without spaces.
        assert expected.lower().replace(" ", "") in text.lower().replace(" ", ""), expected


def test_cve_links_point_to_cve_org_and_nvd(cfg, no_network):
    reader, _ = pdf_text(render_pdf(full_edition(cfg)).pdf)
    links = {str(a.get_object()["/A"]["/URI"]) for p in reader.pages for a in p.get("/Annots") or []}
    assert "https://www.cve.org/CVERecord?id=CVE-2026-10001" in links
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-10001" in links
    assert all(u.startswith("https://") for u in links)


def test_word_budget_drops_lowest_headlines(cfg):
    edition = full_edition(cfg, n_stories=40)
    assert edition.words <= cfg.layout.max_words and edition.dropped > 0
    assert len(edition.context["new_threats"]) == 2


@pytest.mark.parametrize("cvss, label", [(9.0, "Critical 9.0"), (0.0, "None 0.0")])
def test_score_and_band_name_both_printed(cfg, cvss, label, no_network):
    info = CveInfo("CVE-2026-10009", "scored", cvss, "3.1")
    s = Story(articles=[make_article("A single story title here", cves=["CVE-2026-10009"])],
              cve_infos=[info], summary=Summary("Summary.", None))
    _, text = pdf_text(render_pdf(build_edition([s], cfg, NOW, ["X"])).pdf)
    assert label.lower().replace(" ", "") in text.lower().replace(" ", "")


def test_story_of_week_shown_once(cfg):
    today = Story(articles=[make_article("Week's biggest breach story", url="https://news.example.com/sotw")],
                  summary=Summary("S.", None))
    weekly = StoryOfWeek(story=StoryRecord(id="https://news.example.com/sotw", day=NOW.date() - timedelta(1),
                                           title="Week's biggest breach story", score=0.9,
                                           links=[LinkRecord(publisher="P", url="https://news.example.com/sotw")]),
                         content=WeeklyContent(what_happened="AI write-up."), set_on=NOW.date())
    ctx = build_edition([today], cfg, NOW, ["X"], weekly).context
    assert ctx["story_of_week"] and ctx["news_of_the_day"] == []


def test_no_excerpts_anywhere(cfg, no_network):
    ai = Story(articles=[make_article("Story with an AI summary", url="https://a.example.com/1")],
               summary=Summary("Written by the model.", None))
    raw = Story(articles=[make_article("Story the model could not summarize", url="https://a.example.com/2",
                                       text="Raw article text that must never be printed.")])
    old = StoryOfWeek(story=StoryRecord(id="https://a.example.com/w", day=NOW.date(), title="Old weekly pick",
                                        score=0.5, links=[LinkRecord(publisher="P", url="https://a.example.com/w")]),
                      content=WeeklyContent(what_happened="First two sentences of the article.", is_excerpt=True),
                      set_on=NOW.date())
    replaced = StoryRecord(id="https://a.example.com/r", day=NOW.date(), title="Replaced pick with no summary",
                           score=0.4, links=[LinkRecord(publisher="P", url="https://a.example.com/r")])
    edition = build_edition([ai, raw], cfg, NOW, ["X"], old, replaced)
    ctx = edition.context
    assert ctx["story_of_week"] is None
    assert [v["title"] for v in ctx["news_of_the_day"] + ctx["headlines"]] == ["Story with an AI summary"]
    _, text = pdf_text(render_pdf(edition).pdf)
    assert "excerpt" not in text.lower() and "Raw article text" not in text and "First two sentences" not in text


def with_photos(cfg, tmp_path, keys=("https://news.example.com/sotw", "https://news.example.com/1")):
    from malnews.images import StoryImage

    images = {}
    for i, key in enumerate(keys):
        path = tmp_path / f"{i}.jpg"
        path.write_bytes(image_bytes(1000, 560))
        images[key] = StoryImage(path, f"Publisher {i}", f"https://news.example.com/{i}")
    return full_edition(cfg, images=images), images


def test_photos_appear_with_credit_and_link(cfg, tmp_path, no_network):
    edition, _ = with_photos(cfg, tmp_path)
    ctx = edition.context
    assert ctx["story_of_week"]["image"]["credit"] == "Publisher 0"
    assert ctx["news_of_the_day"][0]["image"]["href"] == "https://news.example.com/1"
    result = render_pdf(edition, tmp_path)
    reader, text = pdf_text(result.pdf)
    assert result.blocked == [] and len({im.name for p in reader.pages for im in p.images}) == 2
    assert "Image: Publisher 0" in text and "Image: Publisher 1" in text
    assert 2 <= len(reader.pages) <= 4 and len(result.pdf) < 1_000_000


def test_only_the_top_news_story_gets_a_photo(cfg, tmp_path):
    edition, _ = with_photos(cfg, tmp_path, keys=("https://news.example.com/2", "https://news.example.com/3"))
    ctx = edition.context
    assert ctx["story_of_week"]["image"] is None
    assert all(s["image"] is None for s in ctx["news_of_the_day"] + ctx["new_threats"] + ctx["headlines"])


def test_photo_with_unsafe_credit_link_is_dropped(cfg, tmp_path):
    from malnews.images import StoryImage

    path = tmp_path / "x.jpg"
    path.write_bytes(image_bytes(1000, 560))
    bad = {"https://news.example.com/1": StoryImage(path, "P", "javascript:alert(1)")}
    assert full_edition(cfg, images=bad).context["news_of_the_day"][0]["image"] is None


def kev(i, vendor="Acme", added=date(2026, 11, 10), ransomware=False):
    return KevEntry(f"CVE-2026-2{i:04d}", vendor, "Gateway", "Acme Gateway authentication bypass", added, date(2026, 12, 1), ransomware)


def candidates(n, start=0):
    out = []
    for i in range(start, start + n):
        entry = kev(i, ransomware=i % 4 == 0)
        out.append(CveInfo(entry.id, "scored", [9.8, 7.5, 5.3][i % 3], "3.1", True, 0.3, entry))
    return out


def test_every_cve_is_printed_with_a_score_or_status(cfg, no_network):
    infos = [CveInfo("CVE-2026-30001", "scored", 9.8, "3.1", True, 0.9, kev(1)),
             CveInfo("CVE-2026-30002", "pending"), CveInfo("CVE-2026-30003", "unavailable"),
             CveInfo("CVE-2026-30004", "scored", 4.3, "3.1")]
    s = Story(articles=[make_article("A story about four CVEs at once", cves=[i.id for i in infos])],
              cve_infos=infos, summary=Summary("Summary.", None))
    _, text = pdf_text(render_pdf(build_edition([s], cfg, NOW, ["X"])).pdf)
    flat = text.replace(" ", "").lower()
    for expected in ("cve-2026-30001", "critical9.8", "cve-2026-30002", "scorepending", "cve-2026-30003",
                     "scoreunavailable", "cve-2026-30004", "medium4.3"):
        assert expected in flat, expected


def test_known_exploited_details_come_from_cisa_data(cfg, no_network):
    entry = KevEntry("CVE-2026-30001", "Acme", "VPN Gateway", "x", date(2026, 11, 10), date(2026, 12, 1), True)
    info = CveInfo("CVE-2026-30001", "scored", 9.8, "3.1", True, 0.9, entry)
    s = Story(articles=[make_article("Acme VPN exploited in the wild now", cves=[info.id])], cve_infos=[info],
              summary=Summary("Summary.", None))
    cve = build_edition([s], cfg, NOW, ["X"]).context["news_of_the_day"][0]["cves"][0]
    assert cve["kev_detail"] == "Acme VPN Gateway · federal fix due Dec 1 · used in ransomware"


def test_snapshot_counts_distinct_cves(cfg):
    shared = CveInfo("CVE-2026-30001", "scored", 9.8, "3.1", True)
    stories = [Story(articles=[make_article(f"Story {i} headline about {'a' * i}", url=f"https://n.example.com/{i}")],
                     cve_infos=infos, summary=Summary("S.", None), zero_day=i == 0)
               for i, infos in enumerate(([shared, CveInfo("CVE-2026-30002", "pending")], [shared],
                                          [CveInfo("CVE-2026-30003", "scored", 5.0, "3.1")]))]
    snap = build_edition(stories, cfg, NOW, ["X"]).context["snapshot"]
    assert (snap["total"], snap["kev"], snap["zero_days"], snap["highest"]) == (3, 1, 1, "9.8")
    assert {seg["label"]: seg["count"] for seg in snap["segments"]} == {"Critical": 1, "Medium": 1, "Pending": 1}
    assert sum(float(seg["width"].rstrip("%")) for seg in snap["segments"]) == pytest.approx(100, abs=0.5)


def test_no_snapshot_without_cves(cfg):
    s = Story(articles=[make_article("A breach with no CVE at all")], summary=Summary("S.", None))
    assert build_edition([s], cfg, NOW, ["X"]).context["snapshot"] is None


def test_roundup_skips_cves_already_printed(cfg):
    shown = CveInfo("CVE-2026-20000", "scored", 9.8, "3.1", True)
    s = Story(articles=[make_article("A story that already covers a KEV CVE", cves=[shown.id])], cve_infos=[shown],
              summary=Summary("S.", None))
    rows = build_edition([s], cfg, NOW, ["X"], kev_candidates=candidates(5)).context["roundup"]
    assert "CVE-2026-20000" not in [r["id"] for r in rows] and len(rows) == 4


def test_roundup_is_capped(cfg):
    assert len(build_edition([], cfg, NOW, ["X"], kev_candidates=candidates(60)).context["roundup"]) == cfg.roundup.max_rows


def test_fit_rows_picks_the_largest_count_that_adds_no_page():
    from malnews.render import fit_rows

    pages = lambda n: 2 + (n > 9)  # noqa: E731  rows 0..9 fit on page 2, a tenth spills to page 3
    assert fit_rows(pages, total=30, min_rows=4) == 9
    assert fit_rows(pages, total=6, min_rows=4) == 6
    assert fit_rows(pages, total=3, min_rows=4) == 0
    assert fit_rows(lambda n: 2 + (n > 2), total=30, min_rows=4) == 0


def test_roundup_fills_the_last_page_without_adding_one(cfg, no_network):
    from malnews.render import _layout, jinja_env

    stories = [Story(articles=[make_article(f"Story {i} about an incident at a vendor", url=f"https://n.example.com/{i}")],
                     summary=Summary(SENT * 2, None)) for i in range(9)]
    edition = build_edition(stories, cfg, NOW, ["X"], kev_candidates=candidates(60))
    template = jinja_env().get_template("edition.html.j2")

    def pages(n):
        html = template.render(**{**edition.context, "roundup": edition.context["roundup"][:n]})
        return len(_layout(html, None)[0].render().pages)

    result = render_pdf(edition)
    base = pages(0)
    assert result.pages == base and cfg.roundup.min_rows <= result.roundup_rows <= cfg.roundup.max_rows
    if result.roundup_rows < len(edition.context["roundup"]):
        assert pages(result.roundup_rows + 1) > base


def test_roundup_table_is_printed_with_links_and_ransomware_mark(cfg, no_network):
    edition = build_edition([], cfg, NOW, ["X"], kev_candidates=candidates(8))
    reader, text = pdf_text(render_pdf(edition).pdf)
    assert "knownexploitedroundup" in text.lower().replace(" ", "") and "†" in text and "Acme Gateway" in text
    links = {str(a.get_object()["/A"]["/URI"]) for p in reader.pages for a in p.get("/Annots") or []}
    assert "https://www.cve.org/CVERecord?id=CVE-2026-20000" in links and "https://nvd.nist.gov/vuln/detail/CVE-2026-20001" in links
