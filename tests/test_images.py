import io

import pytest
from PIL import Image

from malnews.collect import collect
from malnews.images import fetch_image, prepare, story_images
from malnews.render import render_html_to_pdf
from malnews.state import LinkRecord, StoryRecord

from .conftest import NOW, FakeFetcher, image_bytes, rss


def decode(data: bytes) -> Image.Image:
    return Image.open(io.BytesIO(data))


def test_large_image_is_scaled_down_to_a_jpeg(cfg):
    out = decode(prepare(image_bytes(2400, 1400), cfg))
    assert out.format == "JPEG" and out.size == (cfg.images.max_width, round(1400 * cfg.images.max_width / 2400))


def test_mid_size_image_is_not_enlarged(cfg):
    assert decode(prepare(image_bytes(800, 500), cfg)).size == (800, 500)


@pytest.mark.parametrize("fmt, mode", [("PNG", "RGB"), ("PNG", "RGBA"), ("WEBP", "RGB")])
def test_png_and_webp_become_jpeg(cfg, fmt, mode):
    assert decode(prepare(image_bytes(900, 500, fmt, mode), cfg)).format == "JPEG"


def test_narrow_image_is_skipped(cfg):
    assert prepare(image_bytes(399, 300), cfg) is None
    assert prepare(image_bytes(400, 300), cfg) is not None


@pytest.mark.parametrize("data", [
    b"", b"<html><script>alert(1)</script></html>", b"GIF89a" + b"\x00" * 50, image_bytes(900, 500, "GIF", "P"),
    image_bytes(900, 500, "BMP"),
])
def test_other_formats_and_junk_are_skipped(cfg, data):
    assert prepare(data, cfg) is None


def test_pixel_limit(cfg):
    small = cfg.images.model_copy(update={"max_pixels": 100_000})
    assert prepare(image_bytes(1200, 700), cfg.model_copy(update={"images": small})) is None


def test_exif_and_appended_payload_are_dropped(cfg):
    exif = Image.Exif()
    exif[0x010E] = "SECRET-GPS-NOTE"
    base = image_bytes(900, 500, exif=exif.tobytes())
    assert b"SECRET-GPS-NOTE" in base
    out = prepare(base + b"<?php system($_GET['c']); ?>", cfg)
    assert b"SECRET-GPS-NOTE" not in out and b"<?php" not in out


def test_fetch_image_saves_and_reports_failure(cfg, tmp_path):
    fetcher = FakeFetcher({"https://img.example.com/a.png": image_bytes(900, 500, "PNG"),
                           "https://img.example.com/tiny.jpg": image_bytes(100, 100), "https://img.example.com/err": 500})
    assert fetch_image(fetcher, "https://img.example.com/a.png", tmp_path / "a.jpg", cfg)
    assert (tmp_path / "a.jpg").read_bytes()[:3] == b"\xff\xd8\xff"
    assert not fetch_image(fetcher, "https://img.example.com/tiny.jpg", tmp_path / "t.jpg", cfg)
    assert not fetch_image(fetcher, "https://img.example.com/err", tmp_path / "e.jpg", cfg)
    assert not (tmp_path / "t.jpg").exists() and not (tmp_path / "e.jpg").exists()
    assert fetcher.caps["https://img.example.com/a.png"] == cfg.images.max_bytes


def test_story_images_skips_missing(cfg, tmp_path):
    fetcher = FakeFetcher({"https://img.example.com/a.jpg": image_bytes(900, 500)})
    found = story_images(fetcher, {"one": ("https://img.example.com/a.jpg", "CISA", "https://x.com/1"),
                                   "two": (None, "Krebs", "https://x.com/2")}, tmp_path, cfg)
    assert list(found) == ["one"] and found["one"].credit == "CISA" and found["one"].path.exists()


def article(og: str) -> bytes:
    return (f'<html><head><meta property="og:image" content="{og}"></head><body><article><p>'
            + "Full advisory text. " * 30 + "</p></article></body></html>").encode()


@pytest.mark.parametrize("og, expected", [
    ("https://cdn.example.com/pic.jpg", "https://cdn.example.com/pic.jpg"),
    ("/images/pic.jpg", "https://www.cisa.gov/images/pic.jpg"),
    ("http://cdn.example.com/pic.jpg", "https://cdn.example.com/pic.jpg"),
    ("javascript:alert(1)", None),
    ("data:image/png;base64,AAAA", None),
    ("file:///etc/passwd", None),
])
def test_og_image_is_collected_and_checked(cfg, sources, no_network, og, expected):
    fetcher = FakeFetcher({
        "https://www.cisa.gov/cybersecurity-advisories/all.xml": rss(("Vendor flaw exploited today", "https://www.cisa.gov/a", NOW, "x")),
        "https://www.cisa.gov/a": article(og),
    })
    articles, _ = collect(sources, fetcher, NOW, cfg)
    assert articles[0].image_url == expected


def test_state_record_rejects_unsafe_image_links():
    kw = dict(id="https://x.com/a", day=NOW.date(), title="T", score=0.5, links=[LinkRecord(publisher="P", url="https://x.com/a")])
    assert StoryRecord(**kw, image_url="https://cdn.example.com/p.jpg").image_url
    for bad in ("javascript:alert(1)", "http://cdn.example.com/p.jpg", "file:///etc/passwd"):
        with pytest.raises(ValueError):
            StoryRecord(**kw, image_url=bad)


def test_renderer_reads_only_the_image_folder(tmp_path, no_network):
    (tmp_path / "ok.jpg").write_bytes(image_bytes(600, 300))
    other = tmp_path.parent / "elsewhere.jpg"
    other.write_bytes(image_bytes(600, 300))
    html = f'<img src="{(tmp_path / "ok.jpg").as_uri()}"><img src="{other.as_uri()}">'
    allowed = render_html_to_pdf(html, tmp_path)
    assert [u for u in allowed.blocked] == [other.as_uri()]
    assert render_html_to_pdf(html).blocked == [(tmp_path / "ok.jpg").as_uri(), other.as_uri()]
