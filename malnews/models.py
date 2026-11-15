from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .enrich import CveInfo


@dataclass
class Article:
    source: str
    tier: str
    title: str
    url: str
    published: datetime
    excerpt: str
    text: str
    text_is_excerpt: bool
    cves: set[str] = field(default_factory=set)
    image_url: str | None = None


@dataclass
class Summary:
    summary: str
    mitigation: str | None


@dataclass
class Story:
    articles: list[Article]
    score: float = 0.0
    priority: float = 0.0
    impact: bool = False
    zero_day: bool = False
    cve_infos: list[CveInfo] = field(default_factory=list)
    summary: Summary | None = None

    @property
    def kev(self) -> bool:
        return any(i.kev for i in self.cve_infos)

    @property
    def id(self) -> str:
        """Stable across runs: the primary article's URL."""
        return self.primary.url

    @property
    def primary(self) -> Article:
        """Official first, then full text over feed excerpt, then longest."""
        return max(
            self.articles,
            key=lambda a: (a.tier == "official", not a.text_is_excerpt, len(a.text)),
        )

    @property
    def image_source(self) -> Article | None:
        with_image = [a for a in self.articles if a.image_url]
        return max(with_image, key=lambda a: (a.tier == "official", not a.text_is_excerpt, len(a.text)), default=None)

    @property
    def title(self) -> str:
        return self.primary.title

    @property
    def publishers(self) -> list[str]:
        return sorted({a.source for a in self.articles})

    @property
    def cves(self) -> set[str]:
        return set().union(*(a.cves for a in self.articles))

    @property
    def latest(self) -> datetime:
        return max(a.published for a in self.articles)

    @property
    def links(self) -> list[tuple[str, str]]:
        seen: set[str] = set()
        out = []
        for a in sorted(self.articles, key=lambda a: (a.tier != "official", a.source)):
            if a.url not in seen:
                seen.add(a.url)
                out.append((a.source, a.url))
        return out
