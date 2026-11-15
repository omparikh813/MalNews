"""Weeks run Monday to Sunday (PST). The pick resets each Monday; after that a story replaces it only when
it scores replace_ratio higher, and follow-up coverage of the same event never counts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from .models import Story
from .rank import similar_titles
from .settings import Config
from .state import LinkRecord, State, StoryOfWeek, StoryRecord, WeeklyContent


def week_start(day: date) -> date:
    return day - timedelta(days=day.weekday())


def to_record(story: Story, day: date, cfg: Config) -> StoryRecord:
    pic = story.image_source
    return StoryRecord(
        id=story.id,
        day=day,
        title=story.title,
        score=round(min(max(story.score, 0), 1), 4),
        links=[LinkRecord(publisher=p[:60], url=u) for p, u in story.links[:20]],
        cves=sorted(story.cves)[:50],
        text=story.primary.text[: cfg.story_of_week.max_text_chars],
        summary=story.summary.summary[:2000] if story.summary else None,
        image_url=pic.image_url if pic else None,
        image_credit=pic.source[:60] if pic else None,
        image_link=pic.url if pic else None,
    )


def same_event(a: StoryRecord, b: StoryRecord, cfg: Config) -> bool:
    return a.id == b.id or bool(set(a.cves) & set(b.cves)) or similar_titles(a.title, b.title, cfg)


@dataclass
class WeeklyOutcome:
    status: str
    replaced: StoryRecord | None = None
    replaced_content: WeeklyContent | None = None


def update_story_of_week(state: State, today: list[StoryRecord], day: date, cfg: Config) -> WeeklyOutcome:
    """today must be sorted best first."""
    sw = cfg.story_of_week
    start = week_start(day)
    recent = [r for r in state.history if r.day > day - timedelta(days=sw.history_days) and r.day < day]
    candidates = recent + today

    if state.story_of_week is None or state.week_start != start:
        state.week_start = start
        if not today:
            state.story_of_week = None
            return WeeklyOutcome("none")
        state.story_of_week = StoryOfWeek(story=today[0], set_on=day)
        return WeeklyOutcome("reset")

    current = state.story_of_week
    others = []
    for r in candidates:
        if same_event(r, current.story, cfg):
            if r.score > current.story.score:  # more coverage of the same event: keep it, raise the bar
                current.story = current.story.model_copy(update={"score": r.score})
        else:
            others.append(r)

    best = max(others, key=lambda r: r.score, default=None)
    if best and best.score > 0 and best.score >= current.story.score * sw.replace_ratio:
        previous = current.story
        state.story_of_week = StoryOfWeek(story=best, set_on=day, updated_on=day)
        return WeeklyOutcome("replaced", replaced=previous, replaced_content=current.content)
    return WeeklyOutcome("kept")


def remember(state: State, today: list[StoryRecord], day: date, cfg: Config) -> None:
    sw = cfg.story_of_week
    keep = [r for r in state.history if day - timedelta(days=sw.history_days) < r.day < day]
    state.history = keep + today[: sw.records_per_day]
