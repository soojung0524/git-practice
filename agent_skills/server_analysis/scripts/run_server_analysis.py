"""Server Analysis Skill wrapper.

기존 find_metric_anomaly를 호출만 한다. threshold/severity/지원 metric 목록은 모두
src/skills/gaia_metric_anomaly.py의 것을 그대로 쓴다.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from agent_skills.event_filter import partition_events
from src.models import Finding, NormalizedEvent
from src.skills import find_metric_anomaly

SKILL_NAME = "server_analysis"

DETECTORS: tuple[str, ...] = ("find_metric_anomaly",)

SOURCE_TYPES: tuple[str, ...] = ("gaia_metric",)


def run_server_analysis(
    events: Iterable[NormalizedEvent],
    *,
    dataset: str | None = None,
    host: str | None = None,
    service: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    source_types: Iterable[str] | None = None,
) -> list[Finding]:
    """CPU / Memory / Filesystem 등 resource metric의 이상 구간을 분석한다.

    어떤 metric을 분석하는지는 find_metric_anomaly의 SUPPORTED_METRICS가 결정한다.
    wrapper는 metric 목록을 늘리거나 줄이지 않는다.

    network metric(docker_network_in_packets)도 find_metric_anomaly가 다루므로
    category="network" Finding이 함께 나올 수 있다. 그 Finding만 따로 보려면
    network_analysis Skill을 쓴다.
    """
    buckets = partition_events(
        events,
        keep_source_types=SOURCE_TYPES,
        dataset=dataset,
        host=host,
        service=service,
        start_time=start_time,
        end_time=end_time,
        source_types=source_types,
    )

    metric_events = buckets.get("gaia_metric")
    if not metric_events:
        return []
    return find_metric_anomaly(metric_events)
