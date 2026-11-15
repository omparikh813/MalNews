from __future__ import annotations

import io
import json
import logging
import re
import subprocess
from datetime import datetime, timedelta, timezone

import pypdf
import pytest

import main
from malnews.enrich import Enricher
from malnews.errors import RateLimitStop

from .conftest import ROOT, FakeFetcher, image_bytes, rss

KEY = "sk-or-v1-test-key-0123456789"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("OPENROUTER_API_KEY", KEY)
    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)


def page(og: str) -> bytes:
    return (f'<html><head><meta property="og:image" content="{og}"></head><body><article><p>'
            + "Full article text. " * 40 + "</p></article></body></html>").encode()


NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss"


@pytest.fixture
def fake_world(monkeypatch):
    now = datetime.now(timezone.utc)
    pages = {
        "https://www.cisa.gov/cybersecurity-advisories/all.xml": rss(
            ("Vendor flaw CVE-2026-1111 exploited as a zero-day", "https://www.cisa.gov/a", now - timedelta(hours=1),
             "Advisory about CVE-2026-1111 and CVE-2026-2222.")),
        "https://krebsonsecurity.com/feed/": rss(
            ("Data broker breach exposes records", "https://krebsonsecurity.com/b", now - timedelta(hours=2), "Breach.")),
        "https://www.cisa.gov/a": page("https://img.example.com/cisa.png"),
        "https://krebsonsecurity.com/b": page("https://img.example.com/krebs.jpg"),
        "https://img.example.com/cisa.png": image_bytes(1400, 800, "PNG"),
        "https://img.example.com/krebs.jpg": image_bytes(900, 500),
        KEV: json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-1111"}]}).encode(),
        f"{EPSS}?cve=CVE-2026-1111,CVE-2026-2222": json.dumps({"data": [{"cve": "CVE-2026-1111", "epss": "0.9"}]}).encode(),
        f"{NVD}?cveId=CVE-2026-1111": json.dumps({"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [
            {"type": "Primary", "cvssData": {"baseScore": 9.8}}]}}}]}).encode(),
        f"{NVD}?cveId=CVE-2026-2222": json.dumps({"vulnerabilities": []}).encode(),  # not scored yet
    }

    class Model:
        def __init__(self, **kw):
            assert kw["api_key"] == KEY

        def complete(self, system, user, max_tokens=None):
            if "Story of the Week" in system:
                return ("What happened: Weekly happened.\nWho is affected: Everyone.\n"
                        "What changed: Nothing yet.\nFix: Patch it.")
            return "A short summary.\nFix: Patch it."

    fetcher = FakeFetcher(pages)
    monkeypatch.setattr(main, "SafeFetcher", lambda **kw: fetcher)
    monkeypatch.setattr(main, "OpenRouterClient", Model)
    monkeypatch.setattr(main, "Enricher", lambda f, c, k: Enricher(f, c, k, interval=0))
    Model.fetcher = fetcher
    return Model


def test_full_run_writes_site(tmp_path, env, fake_world, no_network):
    assert main.main([], out_dir=tmp_path, state_path=tmp_path / "state.json") == 0
    assert (tmp_path / "state.json").exists()
    pdf = (tmp_path / "latest.pdf").read_bytes()
    assert len(list((tmp_path / "archive").glob("*.pdf"))) == 1 and len(pdf) < 1_000_000
    text = " ".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(pdf)).pages)
    assert "A short summary." in text and "Patch it." in text
    flat = text.lower().replace(" ", "")
    assert "storyoftheweek" in flat and "weeklyhappened." in flat
    assert "critical9.8" in flat and "knownexploited" in flat and "scorepending" in flat
    index = (tmp_path / "index.html").read_text()
    assert "default-src 'none'" in index and "<script" not in index


def test_pending_cves_are_tracked_between_runs(tmp_path, env, fake_world, no_network):
    state_path = tmp_path / "state.json"
    assert main.main([], out_dir=tmp_path / "site", state_path=state_path) == 0
    state = json.loads(state_path.read_text())
    assert list(state["pending"]) == ["CVE-2026-2222"] and state["story_of_week"]
    assert main.main([], out_dir=tmp_path / "site", state_path=state_path) == 0
    assert json.loads(state_path.read_text())["pending"] == state["pending"]


def test_nvd_key_only_sent_to_nvd(tmp_path, env, fake_world, monkeypatch, no_network):
    monkeypatch.setenv("NVD_API_KEY", "nvd-test-key-123")
    assert main.main([], out_dir=tmp_path, state_path=tmp_path / "state.json") == 0
    for url, headers in fake_world.fetcher.headers.items():
        assert (headers == {"apiKey": "nvd-test-key-123"}) == url.startswith(NVD), url


def test_tampered_state_stops_before_network(tmp_path, env, no_network):
    (tmp_path / "state.json").write_text('{"version": 1, "evil": true}')
    assert main.main([], out_dir=tmp_path / "site", state_path=tmp_path / "state.json") == 7
    assert not (tmp_path / "site").exists()


def test_429_publishes_nothing(tmp_path, env, fake_world, monkeypatch, no_network):
    def limited(self, system, user, max_tokens=None):
        raise RateLimitStop("429")

    monkeypatch.setattr(fake_world, "complete", limited)
    assert main.main([], out_dir=tmp_path / "site", state_path=tmp_path / "state.json") == 3
    assert not (tmp_path / "site").exists() and not (tmp_path / "state.json").exists()


def test_missing_key_exits_before_network(tmp_path, env, monkeypatch, no_network):
    monkeypatch.delenv("OPENROUTER_API_KEY")
    assert main.main([], out_dir=tmp_path, state_path=tmp_path / "state.json") == 2


def test_disallowed_model_exits_before_network(tmp_path, env, monkeypatch, no_network):
    monkeypatch.setenv("OPENROUTER_MODEL", "some/other-model")
    assert main.main([], out_dir=tmp_path, state_path=tmp_path / "state.json") == 2


def test_keys_redacted_from_logs(env):
    rec = logging.LogRecord("x", logging.ERROR, "", 0, "request failed: Bearer %s", (KEY,), None)
    main.RedactSecrets().filter(rec)
    assert KEY not in rec.getMessage() and "[REDACTED]" in rec.getMessage()


def test_dotenv_is_git_ignored():
    out = subprocess.run(["git", "check-ignore", ".env"], cwd=ROOT, capture_output=True, text=True)
    assert out.stdout.strip() == ".env"


# Real OpenRouter keys are "sk-or-v1-" plus 64 hex characters. The fake KEY above does not match.
REAL_KEY_RE = re.compile(r"sk-or-v1-[0-9a-f]{64}")


def test_no_real_keys_committed():
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    for name in files:
        path = ROOT / name
        if path.is_file() and path.suffix not in (".ttf", ".pdf"):
            assert not REAL_KEY_RE.search(path.read_text(errors="ignore")), name


def pdf_text_of(path) -> str:
    return " ".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(path.read_bytes())).pages)


def test_story_without_ai_summary_is_left_out(tmp_path, env, fake_world, monkeypatch, no_network):
    answer = fake_world.complete

    def picky(self, system, user, max_tokens=None):
        return "" if "Data broker" in user else answer(self, system, user, max_tokens)

    monkeypatch.setattr(fake_world, "complete", picky)
    assert main.main([], out_dir=tmp_path, state_path=tmp_path / "state.json") == 0
    text = pdf_text_of(tmp_path / "latest.pdf")
    assert "Data broker" not in text and "Vendor flaw" in text


def test_excerpt_in_old_state_is_replaced_by_ai(tmp_path, env, fake_world, no_network):
    state_path = tmp_path / "state.json"
    assert main.main([], out_dir=tmp_path, state_path=state_path) == 0
    state = json.loads(state_path.read_text())
    state["story_of_week"]["content"] = {"what_happened": "OLD EXCERPT TEXT.", "is_excerpt": True}
    state_path.write_text(json.dumps(state))
    assert main.main([], out_dir=tmp_path, state_path=state_path) == 0
    text = pdf_text_of(tmp_path / "latest.pdf")
    assert "OLD EXCERPT TEXT" not in text and "Weekly happened." in text
    assert json.loads(state_path.read_text())["story_of_week"]["content"]["is_excerpt"] is False


def test_two_images_with_credits(tmp_path, env, fake_world, no_network):
    assert main.main([], out_dir=tmp_path, state_path=tmp_path / "state.json") == 0
    reader = pypdf.PdfReader(io.BytesIO((tmp_path / "latest.pdf").read_bytes()))
    assert len({im.name for p in reader.pages for im in p.images}) == 2
    text = " ".join(p.extract_text() for p in reader.pages)
    assert "Image: CISA" in text and "Image: Krebs on Security" in text
    links = {str(a.get_object()["/A"]["/URI"]) for p in reader.pages for a in p.get("/Annots") or []}
    assert "https://www.cisa.gov/a" in links and "https://krebsonsecurity.com/b" in links


def test_broken_images_are_skipped_not_fatal(tmp_path, env, fake_world, no_network):
    fake_world.fetcher.pages["https://img.example.com/cisa.png"] = b"not an image"
    fake_world.fetcher.pages["https://img.example.com/krebs.jpg"] = 404
    assert main.main([], out_dir=tmp_path, state_path=tmp_path / "state.json") == 0
    reader = pypdf.PdfReader(io.BytesIO((tmp_path / "latest.pdf").read_bytes()))
    assert len({im.name for p in reader.pages for im in p.images}) == 0
    assert "Image:" not in " ".join(p.extract_text() for p in reader.pages)


def test_image_survives_in_state_for_the_week(tmp_path, env, fake_world, no_network):
    state_path = tmp_path / "state.json"
    assert main.main([], out_dir=tmp_path, state_path=state_path) == 0
    story = json.loads(state_path.read_text())["story_of_week"]["story"]
    assert story["image_url"] == "https://img.example.com/cisa.png" and story["image_credit"] == "CISA"


def test_roundup_lists_new_known_exploited_cves(tmp_path, env, fake_world, no_network):
    rows = [{"cveID": f"CVE-2026-{5000 + i}", "vendorProject": "Acme", "product": f"Gateway {i}", "vulnerabilityName": "Bypass",
             "dateAdded": f"2026-11-{10 + i:02d}", "dueDate": "2026-12-01", "knownRansomwareCampaignUse": "Known"} for i in range(6)]
    rows.append({"cveID": "CVE-2026-1111", "vendorProject": "Northwind", "product": "VPN", "vulnerabilityName": "Bypass",
                 "dateAdded": "2026-11-15", "dueDate": "2026-12-01", "knownRansomwareCampaignUse": "Unknown"})
    fake_world.fetcher.pages[KEV] = json.dumps({"vulnerabilities": rows}).encode()
    fake_world.fetcher.pages["https://img.example.com/cisa.png"] = 404  # no photos: leaves room on the page
    fake_world.fetcher.pages["https://img.example.com/krebs.jpg"] = 404
    assert main.main([], out_dir=tmp_path, state_path=tmp_path / "state.json") == 0
    text = pdf_text_of(tmp_path / "latest.pdf")
    flat = text.replace(" ", "").lower()
    assert "knownexploitedroundup" in flat and "CVE-2026-5005" in text and "Acme Gateway 0" in text
    assert text.count("CVE-2026-1111") <= 3  # already covered by a story, so not repeated in the roundup table
    assert f"{NVD}?cveId=CVE-2026-5000" in fake_world.fetcher.requested
