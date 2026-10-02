"""Network Analysis Skill wrapper.

전용 network detector는 아직 없다. 지금 할 수 있는 것은 find_metric_anomaly가 network
metric에서 만든 Finding(category == "network")을 골라 보여주는 것까지다.
DNS/VPN 분석 기능은 구현하지 않는다.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from agent_skills.event_filter import partition_events
from src.models import Finding, NormalizedEvent
from src.skills import find_metric_anomaly

SKILL_NAME = "network_analysis"

DETECTORS: tuple[str, ...] = ("find_metric_anomaly",)

SOURCE_TYPES: tuple[str, ...] = ("gaia_metric",)

# 이 Skill이 골라내는 Finding.category.
NETWORK_CATEGORY = "network"


def select_network_findings(findings: Iterable[Finding]) -> list[Finding]:
    """이미 만들어진 Finding 중 category == "network"인 것만 골라 그대로 돌려준다.

    이미 server_analysis 등으로 metric Finding을 만들어 둔 workflow에서는 detector를
    다시 돌리지 말고 이 함수를 쓰면 된다(중복 실행 회피). Finding을 수정하지 않는다.
    """
    return [finding for finding in findings if finding.category == NETWORK_CATEGORY]


def run_network_analysis(
    events: Iterable[NormalizedEvent],
    *,
    dataset: str | None = None,
    host: str | None = None,
    service: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    source_types: Iterable[str] | None = None,
) -> list[Finding]:
    """network metric의 이상 구간만 분석한다.

    find_metric_anomaly를 호출한 뒤 category == "network" Finding만 골라 반환한다.
    골라내기만 하며 재분류·재판정은 하지 않는다.
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
    return select_network_findings(find_metric_anomaly(metric_events))
