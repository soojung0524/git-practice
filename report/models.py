"""Incident Report 모델.

사실(fact)은 전부 결정론적으로 만들고, LLM은 완성된 보고서를 읽어 산문 요약만 쓴다.
LLM이 수치·시각·식별자를 만들지 않는다.

=== 정상/경고/장애 상태에 대한 정책 ===

이 시스템은 "이상"만 관측한다. 소스에 정상 상태를 나타내는 모델이 없고, Finding 0건은
"threshold를 넘은 관측이 없었다"는 뜻이며 detector 미구현일 때도 0건이다.

또 Finding.severity의 "high"는 detector마다 다른 기준에서 나온다(CPU 사용률 95%,
지연 30초, 에러율 50%, 4xx/5xx 비율 50%). 이를 운영 장애로 환산할 근거가 데이터에
없으므로 severity를 정상/경고/장애로 매핑하지 않는다.

따라서 OperationalStateCounts는 normal/warning/failure를 None으로 두고 그 사유를
policy 문자열로 남긴다. AgentResult.status는 execution_status로 그대로 보존한다.

이 모듈은 llm / orchestration을 import하지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# === 결정론 범위 ===
#
# deterministic (고정 입력 -> 고정 출력, 바이트 동일 JSON):
#   report_id / agent_statistics / findings / timeline / correlation /
#   hypotheses / impact / evidence / limitations
#
# non-deterministic (외부 시스템 출력):
#   security_guidance.items[].response  - 기존 RAG Agent(LLM + 문서 검색)의 응답
#   narrative_summary.text              - LLM 요약
#
# 따라서 "같은 Report 입력 -> 같은 serialization"과 "외부 LLM/RAG 재호출 -> 같은 응답"은
# 다른 문제다. 전자는 보장하고 테스트하지만, 후자는 보장하지 않는다. 실제 LLM/RAG 응답
# 문자열의 equality를 결정론 테스트 조건으로 쓰지 않는다.
#
# 단, 질문(security_guidance.items[].question)과 요약 프롬프트는 template 기반이라
# deterministic하며 그 사실은 테스트로 고정한다.
DETERMINISTIC_SECTIONS = (
    "report_id",
    "agent_statistics",
    "findings",
    "timeline",
    "correlation",
    "hypotheses",
    "impact",
    "evidence",
    "limitations",
)

NON_DETERMINISTIC_FIELDS = (
    "security_guidance.items[].response",
    "narrative_summary.text",
)

SCHEMA_VERSION = "1.0"

MODE_REAL = "real"
MODE_SCENARIO = "scenario"

# normal/warning/failure를 산출할 수 없는 이유. JSON 소비자가 null의 의미를 알 수 있게
# 보고서에 그대로 담는다.
OPERATIONAL_STATE_POLICY = (
    "이 시스템은 이상 징후만 관측하며 정상 상태를 관측하는 모델이 없다. "
    "또한 Finding.severity의 기준이 detector마다 달라(사용률 95% / 지연 30초 / "
    "에러율 50% 등) 운영상 경고·장애로 환산할 근거가 없다. 그래서 normal/warning/"
    "failure를 산출하지 않고 null로 둔다. severity 원시 집계는 findings.severity_counts를, "
    "Agent 실행 상태는 agent_statistics.agents[].execution_status를 참고할 것."
)


class AmbiguousIncidentError(ValueError):
    """focused incident가 여러 개인데 incident_id를 지정하지 않았다.

    첫 번째 incident를 자동 선택하지 않는다 - 어느 incident의 보고서인지 모호한 채로
    보고서를 만들면 안 된다. incident_id를 명시해 incident마다 한 번씩 호출할 것.
    """


# ---------------------------------------------------------------------------
# 공통: 상한으로 잘린 목록
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TruncatedList:
    """상한 때문에 일부만 담은 목록.

    total_count와 included_count를 함께 제공해, 소비자가 잘린 목록을 전체 데이터로
    오해하지 않게 한다.
    """

    total_count: int
    included_count: int
    truncated: bool
    items: tuple[Any, ...]


def make_truncated_list(items: list, limit: int) -> TruncatedList:
    total = len(items)
    included = items[:limit]
    return TruncatedList(
        total_count=total,
        included_count=len(included),
        truncated=total > len(included),
        items=tuple(included),
    )


# ---------------------------------------------------------------------------
# Agent 통계
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentStatistic:
    """Agent 하나의 실행 통계. AgentResult 값을 그대로 옮긴다."""

    agent_name: str
    # AgentResult.status 그대로. 정상/경고/장애가 아니라 실행·구현 상태다.
    execution_status: str
    input_item_count: int
    findings_count: int
    skills_used: tuple[str, ...]
    detectors_used: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class OperationalStateCounts:
    """운영 상태 집계. 현재 데이터로 산출할 수 없는 값은 None이다(위 docstring 참고)."""

    normal_count: int | None
    warning_count: int | None
    failure_count: int | None
    unknown_count: int
    policy: str


@dataclass(frozen=True)
class AgentStatisticsSection:
    routed_agents: tuple[str, ...]
    # 실제 실행된 Agent만 담는다. 새 Agent를 만들거나 가정하지 않는다.
    agents: tuple[AgentStatistic, ...]
    not_run_agents: tuple[str, ...]
    collected_findings_count: int  # dedup 전 (agent_findings)
    deduplicated_findings_count: int  # dedup 후 (findings)
    duplicate_findings_removed: int
    operational_state: OperationalStateCounts


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingRow:
    finding_id: str
    dataset: str
    category: str
    finding_type: str
    severity: str
    start_time: datetime
    end_time: datetime
    host: str | None
    service: str | None
    detector: str
    summary: str
    metrics: dict[str, Any]
    entities: dict[str, tuple[str, ...]]
    evidence_count: int


@dataclass(frozen=True)
class FindingsSection:
    total_count: int
    finding_type_counts: dict[str, int]
    category_counts: dict[str, int]
    severity_counts: dict[str, int]
    dataset_counts: dict[str, int]
    detector_counts: dict[str, int]
    items: TruncatedList  # FindingRow


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TimelineRow:
    finding_id: str
    dataset: str
    # scenario mode에서만 값이 있다. real mode에서는 None(상대 시간축이 없다).
    relative_start_seconds: float | None
    relative_end_seconds: float | None
    original_start_time: datetime
    original_end_time: datetime
    category: str
    finding_type: str
    severity: str
    host: str | None
    service: str | None
    summary: str
    was_clipped: bool
    is_long_span: bool


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorrelationEdgeRow:
    edge_id: str
    source_finding_id: str
    target_finding_id: str
    relation_types: tuple[str, ...]
    temporal_relation: str | None
    overlap_seconds: float
    time_gap_seconds: float | None
    shared_entities: dict[str, tuple[str, ...]]
    shared_evidence_event_ids: tuple[str, ...]
    weak_temporal: bool
    is_grouping_relation: bool


@dataclass(frozen=True)
class CorrelationSection:
    scenario_id: str | None
    candidate_incident_count: int
    multi_finding_incident_count: int
    single_finding_incident_count: int
    focused_incident_ids: tuple[str, ...]
    unselected_candidate_incident_ids: TruncatedList
    unmatched_anchor_finding_ids: tuple[str, ...]
    incident_finding_ids: tuple[str, ...]
    grouping_basis: tuple[str, ...]
    edge_count: int
    grouping_edge_count: int
    edges: TruncatedList  # CorrelationEdgeRow


# ---------------------------------------------------------------------------
# Hypothesis / Impact
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HypothesisRow:
    hypothesis_id: str
    rule_name: str
    statement: str
    supporting_finding_ids: tuple[str, ...]
    supporting_edge_ids: tuple[str, ...]
    shared_identity: dict[str, tuple[str, ...]]
    caveats: tuple[str, ...]


@dataclass(frozen=True)
class ImpactSection:
    affected_hosts: tuple[str, ...]
    affected_services: tuple[str, ...]
    affected_ips: tuple[str, ...]
    affected_users: tuple[str, ...]
    datasets: tuple[str, ...]
    categories: tuple[str, ...]
    finding_type_counts: dict[str, int]
    severity_counts: dict[str, int]
    relative_start_seconds: float | None
    relative_end_seconds: float | None


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceRow:
    source_type: str
    source_file: str
    line_number: int
    timestamp: datetime | None
    event_id: str


@dataclass(frozen=True)
class EvidenceGroup:
    finding_id: str
    evidence_count: int
    included_evidence_count: int
    truncated: bool
    items: tuple[EvidenceRow, ...]


@dataclass(frozen=True)
class EvidenceSection:
    total_evidence_count: int
    included_evidence_count: int
    truncated: bool
    total_finding_count: int
    included_finding_count: int
    groups: tuple[EvidenceGroup, ...]


# ---------------------------------------------------------------------------
# Security Guidance
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GuidanceRow:
    incident_id: str
    question: str
    response: str  # RAG 응답 원문. 요약·재작성하지 않는다([Page N] 보존)
    provider_name: str
    model: str | None


@dataclass(frozen=True)
class GuidanceSection:
    focused_incident_ids: tuple[str, ...]
    failed_incident_ids: tuple[str, ...]
    items: tuple[GuidanceRow, ...]
    notes: tuple[str, ...]
    source_note: str


# 근거 문서의 성격을 과장하지 않기 위한 고정 문구.
GUIDANCE_SOURCE_NOTE = (
    "근거 문서는 AWS Security Incident Response User Guide다. 법적·컴플라이언스 규정이 "
    "아니며, 문서가 권고한 내용을 의무 규정으로 해석하지 않는다."
)


# ---------------------------------------------------------------------------
# Limitations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LimitationsSection:
    """조사의 한계를 모은 섹션.

    ID 목록은 TruncatedList다. 좁은 분석 Window에서는 제외된 Finding이 수천 건이 되어
    (실측: GAIA 20분 Window에서 7,272건) 전부 담으면 JSON이 그 목록으로 가득 찬다.
    total_count로 전체 규모를 알리고 items에는 일부만 담는다.
    """

    errors: dict[str, str]
    not_implemented_agents: tuple[str, ...]
    partially_implemented_agents: tuple[str, ...]
    long_span_finding_ids: TruncatedList
    clipped_finding_ids: TruncatedList
    excluded_from_window_finding_ids: TruncatedList
    skipped_missing_window_finding_ids: TruncatedList
    unmatched_anchor_finding_ids: TruncatedList
    unselected_candidate_incident_ids: TruncatedList
    truncated_sections: tuple[str, ...]
    # 무한/NaN이어서 JSON에 null로 담은 metric. 'finding_id.metric_key' 형태.
    non_finite_metric_fields: TruncatedList
    notes: tuple[str, ...]


# ---------------------------------------------------------------------------
# Narrative summary (LLM)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NarrativeSummary:
    text: str
    provider_name: str
    model: str | None
    prompt: str  # 재현·검증용


# ---------------------------------------------------------------------------
# 최상위
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IncidentReport:
    schema_version: str
    report_id: str
    investigation_id: str
    generated_from: str  # "real" | "scenario"
    scenario_id: str | None
    incident_id: str | None

    agent_statistics: AgentStatisticsSection
    findings: FindingsSection
    timeline: TruncatedList  # TimelineRow
    correlation: CorrelationSection | None
    hypotheses: tuple[HypothesisRow, ...]
    impact: ImpactSection | None
    evidence: EvidenceSection
    security_guidance: GuidanceSection | None
    limitations: LimitationsSection

    # LLM 요약. provider를 주지 않으면 None이며, 결정론적 섹션은 영향받지 않는다.
    narrative_summary: NarrativeSummary | None = field(default=None)
