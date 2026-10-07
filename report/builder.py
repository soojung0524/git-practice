"""IncidentReport를 만드는 결정론적 builder.

LLM을 호출하지 않는다. Finding을 수정하지 않는다. 파일을 읽지 않는다.
같은 입력이면 항상 같은 보고서가 나온다.

InvestigationState를 받지 않는다 - report 패키지는 orchestration을 import하지 않는다.
호출자가 State를 풀어서 개별 인자로 넘긴다.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from collections.abc import Mapping, Sequence

from correlation import CorrelationResult, IncidentSelectionResult, is_long_span
from guidance import SecurityGuidanceResult
from scenario import ScenarioProjection
from src.models import Finding

from .models import (
    GUIDANCE_SOURCE_NOTE,
    MODE_REAL,
    MODE_SCENARIO,
    OPERATIONAL_STATE_POLICY,
    SCHEMA_VERSION,
    AgentStatistic,
    AgentStatisticsSection,
    AmbiguousIncidentError,
    CorrelationEdgeRow,
    CorrelationSection,
    EvidenceGroup,
    EvidenceRow,
    EvidenceSection,
    FindingRow,
    FindingsSection,
    GuidanceRow,
    GuidanceSection,
    HypothesisRow,
    ImpactSection,
    IncidentReport,
    LimitationsSection,
    OperationalStateCounts,
    TimelineRow,
    TruncatedList,
    make_truncated_list,
)

DEFAULT_MAX_FINDINGS = 50
DEFAULT_MAX_EVIDENCE_PER_FINDING = 5
DEFAULT_MAX_TIMELINE_ROWS = 200
DEFAULT_MAX_EDGES = 100
# limitations의 ID 목록 상한. 전체 규모는 total_count로 알린다.
DEFAULT_MAX_LIMITATION_IDS = 50

# long-span caveat. 특정 detector 이름을 쓰지 않는다 - correlation이 계산한
# long_span_finding_ids만 근거로 쓴다.
LONG_SPAN_CAVEAT = (
    "long-span Finding은 분석 Window의 넓은 구간을 차지하여, 정밀한 시간적 인과관계의 "
    "근거로 해석하지 않는다."
)
CLIPPED_CAVEAT = (
    "일부 Finding은 분석 Window 경계에서 구간이 잘렸다. 원본 관측 구간은 더 길 수 있으며 "
    "원본 시각은 timeline의 original_start_time/original_end_time에 보존돼 있다."
)
EMPTY_RESULT_CAVEAT = (
    "Finding이 0건인 것은 '이상이 없다'는 뜻이 아니다. threshold를 넘은 관측이 없었거나 "
    "해당 분석 기능이 구현되지 않았다는 뜻이다. agent_statistics의 execution_status를 "
    "함께 확인할 것."
)
NON_FINITE_METRIC_CAVEAT = (
    "일부 metric 값이 무한(inf) 또는 NaN이어서 JSON에서는 null로 담았다. 비율 계산의 "
    "분모가 0이면 발생한다. 원본 Finding.metrics에는 값이 그대로 남아 있으며, "
    "limitations.non_finite_metric_fields에 해당 항목을 기록했다."
)
NO_HYPOTHESIS_CAVEAT = (
    "가설 후보가 0건인 것은 시간 근접과 식별자 공유 조건을 동시에 만족하는 Finding 조합이 "
    "없었다는 뜻이다. 근본 원인이 없다는 뜻이 아니다."
)


def _sorted_counter(values) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def _normalize_entities(entities: Mapping[str, Sequence[str]]) -> dict[str, tuple[str, ...]]:
    return {key: tuple(entities[key]) for key in sorted(entities)}


def _sanitize_metrics(
    finding_id: str, metrics: Mapping[str, object]
) -> tuple[dict[str, object], list[str]]:
    """JSON으로 담을 수 없는 float(inf/NaN)을 None으로 바꾸고 그 사실을 기록한다.

    실제 데이터에서 발생한다: 비율 계산의 분모(모집단 median 등)가 0이면 inf가 된다.
    조용히 버리지 않고 limitations.non_finite_metric_fields에 남긴다.
    """
    clean: dict[str, object] = {}
    non_finite: list[str] = []
    for key in sorted(metrics):
        value = metrics[key]
        if isinstance(value, float) and not math.isfinite(value):
            clean[key] = None
            non_finite.append(f"{finding_id}.{key}")
        else:
            clean[key] = value
    return clean, non_finite


def make_report_id(
    *,
    investigation_id: str,
    scenario_id: str | None,
    incident_id: str | None,
    finding_ids: Sequence[str],
) -> str:
    """입력에서 유도하는 안정적인 ID. 랜덤 UUID를 쓰지 않는다."""
    key = "\n".join(
        [
            investigation_id,
            scenario_id or "",
            incident_id or "",
            *sorted(finding_ids),
        ]
    )
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]
    return f"{investigation_id}:report:{digest}"


def _resolve_incident_id(
    incident_selection: IncidentSelectionResult | None, incident_id: str | None
) -> str | None:
    """보고서 대상 incident를 정한다.

    - 명시했으면 그것을 쓴다.
    - focused 1개 + 미지정 -> 그 incident
    - focused 0개 -> None (real/general report)
    - focused 2개 이상 + 미지정 -> AmbiguousIncidentError (자동 선택하지 않는다)
    """
    if incident_id is not None:
        return incident_id
    if incident_selection is None:
        return None
    focused = incident_selection.focused_incident_ids
    if not focused:
        return None
    if len(focused) == 1:
        return focused[0]
    raise AmbiguousIncidentError(
        f"focused incident가 {len(focused)}개다: {list(focused)}. "
        "incident_id를 지정해 incident마다 한 번씩 호출할 것 "
        "(첫 번째를 자동 선택하지 않는다)."
    )


def _build_agent_statistics(
    agent_results: Mapping[str, object],
    *,
    routed_agents: Sequence[str],
    collected_findings_count: int,
    findings: Sequence[Finding],
) -> AgentStatisticsSection:
    """실제 실행된 Agent만 담는다. 새 Agent를 가정하지 않는다."""
    stats: list[AgentStatistic] = []
    not_run: list[str] = []

    for key in sorted(agent_results):
        result = agent_results[key]
        if result is None:
            not_run.append(key)
            continue
        stats.append(
            AgentStatistic(
                agent_name=getattr(result, "agent_name", key),
                execution_status=result.status,
                input_item_count=result.input_item_count,
                findings_count=len(result.findings),
                skills_used=tuple(result.skills_used),
                detectors_used=tuple(result.detectors_used),
                notes=tuple(result.notes),
            )
        )

    return AgentStatisticsSection(
        routed_agents=tuple(routed_agents),
        agents=tuple(sorted(stats, key=lambda s: s.agent_name)),
        not_run_agents=tuple(not_run),
        collected_findings_count=collected_findings_count,
        deduplicated_findings_count=len(findings),
        duplicate_findings_removed=max(0, collected_findings_count - len(findings)),
        operational_state=OperationalStateCounts(
            normal_count=None,
            warning_count=None,
            failure_count=None,
            unknown_count=len(findings),
            policy=OPERATIONAL_STATE_POLICY,
        ),
    )


def _finding_row(finding: Finding) -> tuple[FindingRow, list[str]]:
    metrics, non_finite = _sanitize_metrics(finding.finding_id, finding.metrics)
    return FindingRow(
        finding_id=finding.finding_id,
        dataset=finding.dataset,
        category=finding.category,
        finding_type=finding.finding_type,
        severity=finding.severity,
        start_time=finding.start_time,
        end_time=finding.end_time,
        host=finding.host,
        service=finding.service,
        detector=finding.detector,
        summary=finding.summary,
        metrics=metrics,
        entities=_normalize_entities(finding.entities),
        evidence_count=len(finding.evidence),
    ), non_finite


def _build_findings_section(
    findings: Sequence[Finding], *, max_findings: int
) -> tuple[FindingsSection, list[str]]:
    ordered = sorted(findings, key=lambda f: (f.start_time, f.end_time, f.finding_id))
    rows = []
    non_finite: list[str] = []
    for finding in ordered:
        row, flagged = _finding_row(finding)
        rows.append(row)
        non_finite.extend(flagged)
    return FindingsSection(
        total_count=len(ordered),
        finding_type_counts=_sorted_counter(f.finding_type for f in ordered),
        category_counts=_sorted_counter(f.category for f in ordered),
        severity_counts=_sorted_counter(f.severity for f in ordered),
        dataset_counts=_sorted_counter(f.dataset for f in ordered),
        detector_counts=_sorted_counter(f.detector for f in ordered),
        items=make_truncated_list(rows, max_findings),
    ), non_finite


def _build_timeline(
    findings: Sequence[Finding],
    projection: ScenarioProjection | None,
    incident_finding_ids: frozenset[str] | None,
    *,
    max_rows: int,
) -> TruncatedList:
    """scenario mode면 ScenarioFinding의 상대시간을, real mode면 원본 시각만 쓴다."""
    rows: list[TimelineRow] = []

    if projection is not None:
        items = [
            item
            for item in projection
            if incident_finding_ids is None or item.finding_id in incident_finding_ids
        ]
        items.sort(key=lambda i: i.sort_key())
        for item in items:
            finding = item.finding
            rows.append(
                TimelineRow(
                    finding_id=item.finding_id,
                    dataset=item.dataset,
                    relative_start_seconds=item.relative_effective_start_seconds,
                    relative_end_seconds=item.relative_effective_end_seconds,
                    original_start_time=item.original_start_time,
                    original_end_time=item.original_end_time,
                    category=finding.category,
                    finding_type=finding.finding_type,
                    severity=finding.severity,
                    host=finding.host,
                    service=finding.service,
                    summary=finding.summary,
                    was_clipped=item.was_clipped,
                    is_long_span=is_long_span(item),
                )
            )
    else:
        ordered = sorted(findings, key=lambda f: (f.start_time, f.end_time, f.finding_id))
        for finding in ordered:
            rows.append(
                TimelineRow(
                    finding_id=finding.finding_id,
                    dataset=finding.dataset,
                    relative_start_seconds=None,
                    relative_end_seconds=None,
                    original_start_time=finding.start_time,
                    original_end_time=finding.end_time,
                    category=finding.category,
                    finding_type=finding.finding_type,
                    severity=finding.severity,
                    host=finding.host,
                    service=finding.service,
                    summary=finding.summary,
                    was_clipped=False,
                    is_long_span=False,
                )
            )

    return make_truncated_list(rows, max_rows)


def _build_correlation_section(
    result: CorrelationResult,
    selection: IncidentSelectionResult | None,
    incident_id: str | None,
    *,
    max_edges: int,
    max_limitation_ids: int,
) -> CorrelationSection:
    incident = result.incident_by_id(incident_id) if incident_id else None
    incident_finding_ids = frozenset(incident.finding_ids) if incident else frozenset()

    if incident is not None:
        edges = [
            edge
            for edge in result.edges
            if edge.source_finding_id in incident_finding_ids
            and edge.target_finding_id in incident_finding_ids
        ]
    else:
        edges = list(result.edges)

    rows = [
        CorrelationEdgeRow(
            edge_id=edge.edge_id,
            source_finding_id=edge.source_finding_id,
            target_finding_id=edge.target_finding_id,
            relation_types=tuple(edge.relation_types),
            temporal_relation=edge.temporal_relation,
            overlap_seconds=edge.overlap_seconds,
            time_gap_seconds=edge.time_gap_seconds,
            shared_entities=_normalize_entities(edge.shared_entities),
            shared_evidence_event_ids=tuple(edge.shared_evidence_event_ids),
            weak_temporal=edge.weak_temporal,
            is_grouping_relation=edge.is_grouping_relation,
        )
        for edge in edges
    ]

    focused = selection.focused_incident_ids if selection else ()
    unselected = sorted(
        i.incident_id for i in result.incidents if i.incident_id not in set(focused)
    )

    return CorrelationSection(
        scenario_id=result.scenario_id,
        candidate_incident_count=len(result.incidents),
        multi_finding_incident_count=len(result.multi_finding_incidents),
        single_finding_incident_count=len(result.single_finding_incidents),
        focused_incident_ids=tuple(focused),
        unselected_candidate_incident_ids=make_truncated_list(unselected, max_limitation_ids),
        unmatched_anchor_finding_ids=(
            tuple(selection.unmatched_anchor_finding_ids) if selection else ()
        ),
        incident_finding_ids=tuple(incident.finding_ids) if incident else (),
        grouping_basis=tuple(incident.grouping_basis) if incident else (),
        edge_count=len(rows),
        grouping_edge_count=sum(1 for row in rows if row.is_grouping_relation),
        edges=make_truncated_list(rows, max_edges),
    )


def _build_impact_section(incident) -> ImpactSection:
    impact = incident.impact
    return ImpactSection(
        affected_hosts=tuple(impact.affected_hosts),
        affected_services=tuple(impact.affected_services),
        affected_ips=tuple(impact.affected_ips),
        affected_users=tuple(impact.affected_users),
        datasets=tuple(impact.datasets),
        categories=tuple(impact.categories),
        finding_type_counts=dict(sorted(impact.finding_type_counts.items())),
        severity_counts=dict(sorted(impact.severity_counts.items())),
        relative_start_seconds=impact.relative_start_seconds,
        relative_end_seconds=impact.relative_end_seconds,
    )


def _build_evidence_section(
    findings: Sequence[Finding],
    incident_finding_ids: frozenset[str] | None,
    *,
    max_findings: int,
    max_evidence_per_finding: int,
) -> EvidenceSection:
    selected = [
        f
        for f in findings
        if incident_finding_ids is None or f.finding_id in incident_finding_ids
    ]
    selected.sort(key=lambda f: (f.start_time, f.end_time, f.finding_id))

    total_evidence = sum(len(f.evidence) for f in selected)
    included_findings = selected[:max_findings]

    groups: list[EvidenceGroup] = []
    included_evidence = 0
    for finding in included_findings:
        items = [
            EvidenceRow(
                source_type=ref.source_type,
                source_file=ref.source_file,
                line_number=ref.line_number,
                timestamp=ref.timestamp,
                event_id=ref.event_id,
            )
            for ref in finding.evidence[:max_evidence_per_finding]
        ]
        included_evidence += len(items)
        groups.append(
            EvidenceGroup(
                finding_id=finding.finding_id,
                evidence_count=len(finding.evidence),
                included_evidence_count=len(items),
                truncated=len(finding.evidence) > len(items),
                items=tuple(items),
            )
        )

    return EvidenceSection(
        total_evidence_count=total_evidence,
        included_evidence_count=included_evidence,
        truncated=included_evidence < total_evidence,
        total_finding_count=len(selected),
        included_finding_count=len(included_findings),
        groups=tuple(groups),
    )


def _build_guidance_section(
    guidance: SecurityGuidanceResult, incident_id: str | None
) -> GuidanceSection:
    items = [
        GuidanceRow(
            incident_id=item.incident_id,
            question=item.question,
            response=item.response,
            provider_name=item.provider_name,
            model=item.model,
        )
        for item in guidance.guidance
        if incident_id is None or item.incident_id == incident_id
    ]
    return GuidanceSection(
        focused_incident_ids=tuple(guidance.focused_incident_ids),
        failed_incident_ids=tuple(guidance.failed_incident_ids),
        items=tuple(items),
        notes=tuple(guidance.notes),
        source_note=GUIDANCE_SOURCE_NOTE,
    )


def _build_limitations(
    *,
    errors: Mapping[str, str],
    agent_results: Mapping[str, object],
    projection: ScenarioProjection | None,
    correlation: CorrelationResult | None,
    selection: IncidentSelectionResult | None,
    incident,
    findings_section: FindingsSection,
    timeline: TruncatedList,
    evidence: EvidenceSection,
    correlation_section: CorrelationSection | None,
    hypotheses: Sequence[HypothesisRow],
    guidance: SecurityGuidanceResult | None,
    non_finite_metrics: Sequence[str],
    max_limitation_ids: int,
) -> LimitationsSection:
    not_implemented: list[str] = []
    partially: list[str] = []
    for key in sorted(agent_results):
        result = agent_results[key]
        if result is None:
            continue
        name = getattr(result, "agent_name", key)
        if result.status == "not_implemented":
            not_implemented.append(name)
        elif result.status == "partially_implemented":
            partially.append(name)

    long_span: list[str] = []
    clipped: list[str] = []
    if incident is not None:
        long_span = list(incident.long_span_finding_ids)
        clipped = sorted(
            entry.finding_id for entry in incident.timeline if entry.was_clipped
        )
    elif correlation is not None:
        long_span = list(correlation.long_span_finding_ids)
        clipped = sorted(e.finding_id for e in correlation.timeline if e.was_clipped)

    truncated_sections: list[str] = []
    if findings_section.items.truncated:
        truncated_sections.append("findings.items")
    if timeline.truncated:
        truncated_sections.append("timeline")
    if evidence.truncated:
        truncated_sections.append("evidence")
    if correlation_section is not None and correlation_section.edges.truncated:
        truncated_sections.append("correlation.edges")

    notes: list[str] = []
    if long_span:
        notes.append(LONG_SPAN_CAVEAT)
    if clipped:
        notes.append(CLIPPED_CAVEAT)
    if findings_section.total_count == 0 or not_implemented:
        notes.append(EMPTY_RESULT_CAVEAT)
    if correlation is not None and not hypotheses:
        notes.append(NO_HYPOTHESIS_CAVEAT)
    if guidance is not None:
        notes.append(GUIDANCE_SOURCE_NOTE)
    if non_finite_metrics:
        notes.append(NON_FINITE_METRIC_CAVEAT)

    return LimitationsSection(
        errors=dict(sorted(errors.items())),
        not_implemented_agents=tuple(not_implemented),
        partially_implemented_agents=tuple(partially),
        long_span_finding_ids=make_truncated_list(long_span, max_limitation_ids),
        clipped_finding_ids=make_truncated_list(clipped, max_limitation_ids),
        excluded_from_window_finding_ids=make_truncated_list(
            list(projection.excluded_out_of_window) if projection else [],
            max_limitation_ids,
        ),
        skipped_missing_window_finding_ids=make_truncated_list(
            list(projection.skipped_missing_window) if projection else [],
            max_limitation_ids,
        ),
        unmatched_anchor_finding_ids=make_truncated_list(
            list(selection.unmatched_anchor_finding_ids) if selection else [],
            max_limitation_ids,
        ),
        unselected_candidate_incident_ids=(
            correlation_section.unselected_candidate_incident_ids
            if correlation_section
            else make_truncated_list([], max_limitation_ids)
        ),
        truncated_sections=tuple(truncated_sections),
        non_finite_metric_fields=make_truncated_list(
            sorted(non_finite_metrics), max_limitation_ids
        ),
        notes=tuple(notes),
    )


def build_incident_report(
    *,
    investigation_id: str,
    findings: Sequence[Finding],
    agent_results: Mapping[str, object],
    errors: Mapping[str, str] | None = None,
    routed_agents: Sequence[str] = (),
    collected_findings_count: int | None = None,
    scenario_projection: ScenarioProjection | None = None,
    correlation_result: CorrelationResult | None = None,
    incident_selection: IncidentSelectionResult | None = None,
    security_guidance: SecurityGuidanceResult | None = None,
    incident_id: str | None = None,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    max_evidence_per_finding: int = DEFAULT_MAX_EVIDENCE_PER_FINDING,
    max_timeline_rows: int = DEFAULT_MAX_TIMELINE_ROWS,
    max_edges: int = DEFAULT_MAX_EDGES,
    max_limitation_ids: int = DEFAULT_MAX_LIMITATION_IDS,
) -> IncidentReport:
    """결정론적 IncidentReport를 만든다.

    focused incident 1개당 보고서 1개다. focused incident가 2개 이상인데 incident_id를
    지정하지 않으면 AmbiguousIncidentError를 낸다(첫 번째를 자동 선택하지 않는다).
    focused incident가 0개면 real/general report로 만든다.

    LLM을 호출하지 않는다. narrative_summary는 항상 None이며, 요약은 호출자가
    attach_narrative_summary()로 붙인다.
    """
    errors = errors or {}
    collected = (
        collected_findings_count if collected_findings_count is not None else len(findings)
    )

    resolved_incident_id = _resolve_incident_id(incident_selection, incident_id)
    incident = (
        correlation_result.incident_by_id(resolved_incident_id)
        if correlation_result and resolved_incident_id
        else None
    )
    if resolved_incident_id is not None and correlation_result is not None and incident is None:
        raise ValueError(
            f"incident_id {resolved_incident_id!r}가 correlation 결과에 없다"
        )

    incident_finding_ids = frozenset(incident.finding_ids) if incident else None
    report_findings = (
        [f for f in findings if f.finding_id in incident_finding_ids]
        if incident_finding_ids is not None
        else list(findings)
    )

    findings_section, non_finite_metrics = _build_findings_section(
        report_findings, max_findings=max_findings
    )
    timeline = _build_timeline(
        report_findings,
        scenario_projection,
        incident_finding_ids,
        max_rows=max_timeline_rows,
    )
    correlation_section = (
        _build_correlation_section(
            correlation_result,
            incident_selection,
            resolved_incident_id,
            max_edges=max_edges,
            max_limitation_ids=max_limitation_ids,
        )
        if correlation_result is not None
        else None
    )
    hypotheses = tuple(
        HypothesisRow(
            hypothesis_id=h.hypothesis_id,
            rule_name=h.rule_name,
            statement=h.statement,
            supporting_finding_ids=tuple(h.supporting_finding_ids),
            supporting_edge_ids=tuple(h.supporting_edge_ids),
            shared_identity=_normalize_entities(h.shared_identity),
            caveats=tuple(h.caveats),
        )
        for h in (incident.hypotheses if incident else ())
    )
    impact = _build_impact_section(incident) if incident else None
    evidence = _build_evidence_section(
        report_findings,
        incident_finding_ids,
        max_findings=max_findings,
        max_evidence_per_finding=max_evidence_per_finding,
    )
    guidance_section = (
        _build_guidance_section(security_guidance, resolved_incident_id)
        if security_guidance is not None
        else None
    )

    limitations = _build_limitations(
        errors=errors,
        agent_results=agent_results,
        projection=scenario_projection,
        correlation=correlation_result,
        selection=incident_selection,
        incident=incident,
        findings_section=findings_section,
        timeline=timeline,
        evidence=evidence,
        correlation_section=correlation_section,
        hypotheses=hypotheses,
        guidance=security_guidance,
        non_finite_metrics=non_finite_metrics,
        max_limitation_ids=max_limitation_ids,
    )

    scenario_id = (
        scenario_projection.scenario_id
        if scenario_projection is not None
        else (correlation_result.scenario_id if correlation_result else None)
    )

    return IncidentReport(
        schema_version=SCHEMA_VERSION,
        report_id=make_report_id(
            investigation_id=investigation_id,
            scenario_id=scenario_id,
            incident_id=resolved_incident_id,
            finding_ids=[f.finding_id for f in report_findings],
        ),
        investigation_id=investigation_id,
        generated_from=MODE_SCENARIO if scenario_id is not None else MODE_REAL,
        scenario_id=scenario_id,
        incident_id=resolved_incident_id,
        agent_statistics=_build_agent_statistics(
            agent_results,
            routed_agents=routed_agents,
            collected_findings_count=collected,
            findings=report_findings,
        ),
        findings=findings_section,
        timeline=timeline,
        correlation=correlation_section,
        hypotheses=hypotheses,
        impact=impact,
        evidence=evidence,
        security_guidance=guidance_section,
        limitations=limitations,
        narrative_summary=None,
    )
