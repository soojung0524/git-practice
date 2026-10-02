"""NormalizedEvent 목록에 대한 구조적 요약 통계.

공격 여부를 판단하지 않으며, 이후 Agent가 재사용할 수 있는 순수 집계 기능만 제공한다.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from src.models import NormalizedEvent, date_key


@dataclass
class EventSummary:
    total_events: int = 0
    by_source_type: Counter = field(default_factory=Counter)
    by_host: Counter = field(default_factory=Counter)
    by_event_type: Counter = field(default_factory=Counter)
    by_user: Counter = field(default_factory=Counter)
    by_date: Counter = field(default_factory=Counter)
    earliest_timestamp: datetime | None = None
    latest_timestamp: datetime | None = None


def summarize_events(events: Iterable[NormalizedEvent]) -> EventSummary:
    summary = EventSummary()

    for event in events:
        summary.total_events += 1
        summary.by_source_type[event.source_type] += 1
        summary.by_host[event.host] += 1
        summary.by_date[date_key(event)] += 1
        if event.event_type is not None:
            summary.by_event_type[event.event_type] += 1
        if event.user is not None:
            summary.by_user[event.user] += 1

        if event.timestamp is not None:
            if summary.earliest_timestamp is None or event.timestamp < summary.earliest_timestamp:
                summary.earliest_timestamp = event.timestamp
            if summary.latest_timestamp is None or event.timestamp > summary.latest_timestamp:
                summary.latest_timestamp = event.timestamp

    return summary
