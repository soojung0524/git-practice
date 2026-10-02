"""Application Analysis Skill wrapper.

기존 src/skills detector를 호출만 한다. 새로운 탐지 규칙, threshold, severity 판정,
root cause 분석, correlation, LLM 호출은 일절 하지 않는다.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from agent_skills.event_filter import partition_events
from src.models import Finding, NormalizedEvent
from src.skills import (
    find_latency_anomaly,
    find_log_error_spike,
    find_request_spike,
    find_scan_pattern,
)

SKILL_NAME = "application_analysis"

# SKILLS.md의 "6. 사용하는 기존 detector 함수"와 일치해야 한다(tests/test_agent_skills_docs.py).
DETECTORS: tuple[str, ...] = (
    "find_request_spike",
    "find_scan_pattern",
    "find_log_error_spike",
    "find_latency_anomaly",
)

# SKILLS.md의 "7. 사용 가능한 source_type / event_type"과 일치해야 한다.
SOURCE_TYPES: tuple[str, ...] = ("apache_access", "gaia_log", "gaia_trace")


def run_application_analysis(
    events: Iterable[NormalizedEvent],
    *,
    dataset: str | None = None,
    host: str | None = None,
    service: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    source_types: Iterable[str] | None = None,
) -> list[Finding]:
    """웹 요청 급증 / 스캐닝 패턴 / 애플리케이션 ERROR 증가 / 서비스 지연을 분석한다.

    인자는 모두 "분석 입력 범위 지정"이다. 범위를 좁히면 그 범위의 이벤트만 detector에
    들어가므로 baseline도 그 범위에서 다시 계산된다(결과를 사후에 걸러내는 것이 아니다).

    반환값은 기존 detector가 만든 Finding을 그대로 이어붙인 것이다. 어떤 필드도
    수정하지 않는다.
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

    findings: list[Finding] = []

    apache_events = buckets.get("apache_access")
    if apache_events:
        findings.extend(find_request_spike(apache_events))
        findings.extend(find_scan_pattern(apache_events))

    log_events = buckets.get("gaia_log")
    if log_events:
        findings.extend(find_log_error_spike(log_events))

    trace_events = buckets.get("gaia_trace")
    if trace_events:
        findings.extend(find_latency_anomaly(trace_events))

    return findings
