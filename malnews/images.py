from __future__ import annotations

import io
import logging
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from .safety import FetchError
from .settings import Config

log = logging.getLogger(__name__)

ALLOWED_FORMATS = {"JPEG", "PNG", "WEBP"}


@dataclass
class StoryImage:
    path: Path
    credit: str
    link: str


def prepare(data: bytes, cfg: Config) -> bytes | None:
    """Re-encoding as a new JPEG drops EXIF data and anything appended to the file."""
    ic = cfg.images
    Image.MAX_IMAGE_PIXELS = ic.max_pixels
    try:
        with Image.open(io.BytesIO(data)) as img:
            width, height = img.size
            if img.format not in ALLOWED_FORMATS or getattr(img, "is_animated", False):
                return None
            if width < ic.min_width or width * height > ic.max_pixels:
                return None
            img.load()
            rgba = img.convert("RGBA")
        flat = Image.new("RGB", rgba.size, "white")
        flat.paste(rgba, mask=rgba.getchannel("A"))
        if width > ic.max_width:
            flat = flat.resize((ic.max_width, round(height * ic.max_width / width)), Image.LANCZOS)
        out = io.BytesIO()
        flat.save(out, "JPEG", quality=ic.jpeg_quality, optimize=True)
        return out.getvalue()
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        return None


def fetch_image(fetcher, url: str, dest: Path, cfg: Config) -> bool:
    try:
        data = fetcher.get(url, max_bytes=cfg.images.max_bytes).content
    except FetchError as e:
        log.info("image skipped, download failed: %s", e)
        return False
    jpeg = prepare(data, cfg)
    if jpeg is None:
        log.info("image skipped: not a JPEG, PNG or WebP of at least %d px wide", cfg.images.min_width)
        return False
    dest.write_bytes(jpeg)
    return True


def story_images(fetcher, wanted: dict[str, tuple[str | None, str, str]], folder: Path,
                 cfg: Config) -> dict[str, StoryImage]:
    """wanted: story id -> (image URL, publisher, article link). Missing or bad images are skipped."""
    found = {}
    for n, (key, (url, credit, link)) in enumerate(wanted.items()):
        if url and fetch_image(fetcher, url, folder / f"story-{n}.jpg", cfg):
            found[key] = StoryImage(folder / f"story-{n}.jpg", credit, link)
    return found
