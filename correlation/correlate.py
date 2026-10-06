"""ScenarioFinding 사이의 관계를 찾아 incident 후보로 묶는다.

이 계층은 새로운 anomaly를 탐지하지 않는다. 이미 만들어진 Finding을 수정하지 않고,
severity를 바꾸지 않고, 새 Finding을 만들지 않는다.

=== 시간 계산에 쓰는 값 ===

scenario mode에서는 relative_effective_start_seconds / relative_effective_end_seconds
만 사용한다. Finding.start_time, original_start_time, relative_start_seconds는 원본
추적·표시용이며 관계 계산에 쓰지 않는다(상대시간이 음수인 clip 전 값이 섞이면 결과가
달라진다).
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from scenario import ScenarioFinding, ScenarioProjection

from .config import (
    GROUPING_IDENTITY_RELATIONS,
    LONG_SPAN_RATIO,
    NEAR_IN_TIME_SECONDS,
    RELATION_SAME_HOST,
    RELATION_SAME_SERVICE,
    RELATION_SHARED_ENTITY,
    RELATION_SHARED_EVIDENCE,
    RELATION_TEMPORAL_NEAR,
    RELATION_TEMPORAL_OVERLAP,
    RELATION_TEMPORAL_WEAK_LONG_SPAN,
    TEMPORAL_OVERLAPS,
    TEMPORAL_PRECEDES,
)
from .graph import build_evidence_graph
from .models import (
    CorrelatedIncident,
    CorrelationEdge,
    CorrelationResult,
    HypothesisCandidate,
    ImpactScope,
    TimelineEntry,
)


# ---------------------------------------------------------------------------
# long-span 판정
# ---------------------------------------------------------------------------


def is_long_span(item: ScenarioFinding) -> bool:
    """scenario Window 길이 대비 span 비율로 판정한다.

    ScenarioFinding.span_ratio의 분모가 Window 길이이므로, 묶은 dataset 구성에 따라
    기준이 흔들리지 않는다.
    """
    return item.span_ratio >= LONG_SPAN_RATIO


# ---------------------------------------------------------------------------
# 시간 relation
# ---------------------------------------------------------------------------


def _canonical_order(
    a: ScenarioFinding, b: ScenarioFinding
) -> tuple[ScenarioFinding, ScenarioFinding]:
    """(effective start, effective end, finding_id)가 작은 쪽을 source로 고정한다.

    방향을 고정하므로 follows가 필요 없고, 같은 쌍에서 edge가 두 번 생기지 않는다.
    """
    key_a = (
        a.relative_effective_start_seconds,
        a.relative_effective_end_seconds,
        a.finding_id,
    )
    key_b = (
        b.relative_effective_start_seconds,
        b.relative_effective_end_seconds,
        b.finding_id,
    )
    return (a, b) if key_a <= key_b else (b, a)


@dataclass(frozen=True)
class _Temporal:
    relation: str | None
    overlap_seconds: float
    time_gap_seconds: float | None


def _temporal_relation(source: ScenarioFinding, target: ScenarioFinding) -> _Temporal:
    """effective 상대초만 써서 시간 관계를 판정한다."""
    a_start = source.relative_effective_start_seconds
    a_end = source.relative_effective_end_seconds
    b_start = target.relative_effective_start_seconds
    b_end = target.relative_effective_end_seconds

    latest_start = max(a_start, b_start)
    earliest_end = min(a_end, b_end)
    overlap = earliest_end - latest_start

    if overlap > 0:
        return _Temporal(TEMPORAL_OVERLAPS, overlap, None)

    if overlap == 0 and (a_start == a_end or b_start == b_end):
        # 한쪽이 길이 0인 순간이고 그 순간이 상대 구간에 닿아 있다. 실제 데이터에
        # 존재한다(표본 1건으로 끝난 metric episode는 start == end다). overlap 길이를
        # 0보다 크게 요구하면 이런 Finding은 영원히 아무것과도 겹치지 않는다.
        return _Temporal(TEMPORAL_OVERLAPS, 0.0, None)

    gap = b_start - a_end
    if 0 < gap <= NEAR_IN_TIME_SECONDS:
        return _Temporal(TEMPORAL_PRECEDES, 0.0, gap)

    return _Temporal(None, 0.0, None)


# ---------------------------------------------------------------------------
# identity relation
# ---------------------------------------------------------------------------


def _shared_entities(
    source: ScenarioFinding, target: ScenarioFinding
) -> dict[str, tuple[str, ...]]:
    """같은 entity 키에 공통 값이 있는 것만 모은다.

    키가 다르면 값이 같아도 공통으로 보지 않는다 - ip=1.2.3.4와 host=1.2.3.4는 의미가
    다르다.
    """
    shared: dict[str, tuple[str, ...]] = {}
    left = source.finding.entities
    right = target.finding.entities
    for key in sorted(left.keys() & right.keys()):
        common = sorted(set(left[key]) & set(right[key]))
        if common:
            shared[key] = tuple(common)
    return shared


def _shared_evidence(
    source: ScenarioFinding, target: ScenarioFinding
) -> tuple[str, ...]:
    left = {ref.event_id for ref in source.finding.evidence}
    right = {ref.event_id for ref in target.finding.evidence}
    return tuple(sorted(left & right))


# ---------------------------------------------------------------------------
# edge 생성
# ---------------------------------------------------------------------------


def _make_edge_id(scenario_id: str, source_id: str, target_id: str) -> str:
    return f"{scenario_id}:edge:{source_id}|{target_id}"


def _build_edge(
    a: ScenarioFinding, b: ScenarioFinding, scenario_id: str
) -> CorrelationEdge | None:
    """관계가 하나도 없으면 None을 돌려준다(edge를 만들지 않는다)."""
    source, target = _canonical_order(a, b)
    temporal = _temporal_relation(source, target)

    shared_entities = _shared_entities(source, target)
    shared_evidence = _shared_evidence(source, target)
    same_host = (
        source.finding.host is not None
        and target.finding.host is not None
        and source.finding.host == target.finding.host
    )
    same_service = (
        source.finding.service is not None
        and target.finding.service is not None
        and source.finding.service == target.finding.service
    )

    relation_types: list[str] = []
    if temporal.relation == TEMPORAL_OVERLAPS:
        relation_types.append(RELATION_TEMPORAL_OVERLAP)
    elif temporal.relation == TEMPORAL_PRECEDES:
        relation_types.append(RELATION_TEMPORAL_NEAR)
    if same_host:
        relation_types.append(RELATION_SAME_HOST)
    if same_service:
        relation_types.append(RELATION_SAME_SERVICE)
    if shared_entities:
        relation_types.append(RELATION_SHARED_ENTITY)
    if shared_evidence:
        relation_types.append(RELATION_SHARED_EVIDENCE)

    if not relation_types:
        return None

    source_long = is_long_span(source)
    target_long = is_long_span(target)
    weak_temporal = (source_long or target_long) and temporal.relation is not None
    if weak_temporal:
        relation_types.append(RELATION_TEMPORAL_WEAK_LONG_SPAN)

    notes: list[str] = []
    if source_long or target_long:
        notes.append(
            "long-span Finding이 포함돼 시간 관계를 약한 근거로 다룬다 "
            f"(span_ratio source={source.span_ratio:.4f} target={target.span_ratio:.4f})"
        )
    if source.was_clipped or target.was_clipped:
        notes.append(
            "scenario Window 경계로 interval이 잘린 Finding이 포함돼 있다 "
            "(원본 Finding 시간은 변경되지 않았다)"
        )

    is_grouping = _is_grouping_relation(
        temporal_present=temporal.relation is not None,
        same_host=same_host,
        has_shared_entity=bool(shared_entities),
        has_shared_evidence=bool(shared_evidence),
        long_span=source_long or target_long,
    )

    return CorrelationEdge(
        edge_id=_make_edge_id(scenario_id, source.finding_id, target.finding_id),
        scenario_id=scenario_id,
        source_finding_id=source.finding_id,
        target_finding_id=target.finding_id,
        relation_types=tuple(sorted(relation_types)),
        temporal_relation=temporal.relation,
        overlap_seconds=temporal.overlap_seconds,
        time_gap_seconds=temporal.time_gap_seconds,
        shared_entities=shared_entities,
        shared_evidence_event_ids=shared_evidence,
        source_was_clipped=source.was_clipped,
        target_was_clipped=target.was_clipped,
        weak_temporal=weak_temporal,
        is_grouping_relation=is_grouping,
        notes=tuple(notes),
    )


def _is_grouping_relation(
    *,
    temporal_present: bool,
    same_host: bool,
    has_shared_entity: bool,
    has_shared_evidence: bool,
    long_span: bool,
) -> bool:
    """incident grouping에 쓸 strong relation인지 판정한다.

    일반 Finding:
        temporal relation 존재 AND (same_host OR shared_entity OR shared_evidence)

    long-span Finding이 하나라도 포함된 경우:
        A. shared_evidence가 있으면 허용 (같은 원본 로그 줄을 가리키는 직접 증거)
        B. shared_entity는 temporal relation도 있을 때만 허용
        C. same_host만으로는 금지
        D. temporal overlap만으로는 금지

    same_service는 어느 경우에도 grouping 근거가 아니다(config 참고).
    """
    if long_span:
        if has_shared_evidence:
            return True
        return has_shared_entity and temporal_present

    if not temporal_present:
        return False
    return same_host or has_shared_entity or has_shared_evidence


def build_edges(
    findings: Sequence[ScenarioFinding], scenario_id: str
) -> tuple[CorrelationEdge, ...]:
    """모든 쌍을 한 번씩 본다. 같은 쌍에서 edge가 두 번 생기지 않는다."""
    edges: dict[tuple[str, str], CorrelationEdge] = {}
    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            a, b = findings[i], findings[j]
            if a.finding_id == b.finding_id:
                continue  # 같은 Finding이 중복 입력된 경우 자기참조 edge를 만들지 않는다
            edge = _build_edge(a, b, scenario_id)
            if edge is None:
                continue
            edges[(edge.source_finding_id, edge.target_finding_id)] = edge
    return tuple(edges[key] for key in sorted(edges))


# ---------------------------------------------------------------------------
# grouping (connected component)
# ---------------------------------------------------------------------------


def _connected_components(
    finding_ids: Sequence[str], edges: Iterable[CorrelationEdge]
) -> list[tuple[str, ...]]:
    """is_grouping_relation=True인 edge만으로 연결 성분을 만든다.

    연결되지 않은 Finding도 버리지 않고 단독 성분이 된다.
    """
    parent = {finding_id: finding_id for finding_id in finding_ids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        root_x, root_y = find(x), find(y)
        if root_x == root_y:
            return
        # 사전순으로 작은 쪽을 root로 고정해 결정론을 유지한다.
        if root_x < root_y:
            parent[root_y] = root_x
        else:
            parent[root_x] = root_y

    for edge in edges:
        if not edge.is_grouping_relation:
            continue
        if edge.source_finding_id in parent and edge.target_finding_id in parent:
            union(edge.source_finding_id, edge.target_finding_id)

    groups: dict[str, list[str]] = {}
    for finding_id in finding_ids:
        groups.setdefault(find(finding_id), []).append(finding_id)
    return [tuple(sorted(members)) for members in groups.values()]


def _make_incident_id(scenario_id: str, finding_ids: Sequence[str]) -> str:
    digest = hashlib.sha1("\n".join(sorted(finding_ids)).encode("utf-8")).hexdigest()
    return f"{scenario_id}:incident:{digest[:12]}"


# ---------------------------------------------------------------------------
# timeline
# ---------------------------------------------------------------------------


def build_timeline(findings: Iterable[ScenarioFinding]) -> tuple[TimelineEntry, ...]:
    """정렬: relative_effective_start -> relative_effective_end -> finding_id."""
    entries = [
        TimelineEntry(
            finding_id=item.finding_id,
            dataset=item.dataset,
            relative_start_seconds=item.relative_effective_start_seconds,
            relative_end_seconds=item.relative_effective_end_seconds,
            original_start_time=item.original_start_time,
            original_end_time=item.original_end_time,
            category=item.finding.category,
            finding_type=item.finding.finding_type,
            severity=item.finding.severity,
            host=item.finding.host,
            service=item.finding.service,
            summary=item.finding.summary,
            was_clipped=item.was_clipped,
            is_long_span=is_long_span(item),
        )
        for item in findings
    ]
    entries.sort(
        key=lambda e: (e.relative_start_seconds, e.relative_end_seconds, e.finding_id)
    )
    return tuple(entries)


# ---------------------------------------------------------------------------
# impact
# ---------------------------------------------------------------------------


def build_impact(findings: Sequence[ScenarioFinding]) -> ImpactScope:
    """입력에 실제로 등장한 값만 집계한다. severity를 새로 계산하지 않는다."""
    hosts: set[str] = set()
    services: set[str] = set()
    ips: set[str] = set()
    users: set[str] = set()
    datasets: set[str] = set()
    categories: set[str] = set()

    for item in findings:
        finding = item.finding
        if finding.host is not None:
            hosts.add(finding.host)
        if finding.service is not None:
            services.add(finding.service)
        ips.update(finding.entities.get("ip", ()))
        users.update(finding.entities.get("user", ()))
        datasets.add(finding.dataset)
        categories.add(finding.category)

    return ImpactScope(
        affected_hosts=tuple(sorted(hosts)),
        affected_services=tuple(sorted(services)),
        affected_ips=tuple(sorted(ips)),
        affected_users=tuple(sorted(users)),
        datasets=tuple(sorted(datasets)),
        categories=tuple(sorted(categories)),
        finding_type_counts=dict(
            sorted(Counter(item.finding.finding_type for item in findings).items())
        ),
        severity_counts=dict(
            sorted(Counter(item.finding.severity for item in findings).items())
        ),
        relative_start_seconds=min(
            item.relative_effective_start_seconds for item in findings
        ),
        relative_end_seconds=max(
            item.relative_effective_end_seconds for item in findings
        ),
    )


# ---------------------------------------------------------------------------
# hypothesis
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _HypothesisRule:
    name: str
    left_categories: frozenset[str]
    right_categories: frozenset[str]
    # 이 키의 entity를 공유해야 하는 경우(security 규칙). None이면 identity 근거는
    # same_host / shared_entity / shared_evidence 중 아무거나 된다.
    required_entity_keys: frozenset[str] | None
    phrase: str


HYPOTHESIS_RULES: tuple[_HypothesisRule, ...] = (
    _HypothesisRule(
        name="traffic_related_degradation",
        left_categories=frozenset({"availability"}),
        right_categories=frozenset({"performance"}),
        required_entity_keys=None,
        phrase="요청량 이상과 성능 저하가",
    ),
    _HypothesisRule(
        name="resource_related_degradation",
        left_categories=frozenset({"resource"}),
        right_categories=frozenset({"performance", "error"}),
        required_entity_keys=None,
        phrase="자원 이상과 성능/에러 이상이",
    ),
    _HypothesisRule(
        name="network_related_degradation",
        left_categories=frozenset({"network"}),
        right_categories=frozenset({"performance", "error"}),
        required_entity_keys=None,
        phrase="network 이상과 성능/에러 이상이",
    ),
    _HypothesisRule(
        name="security_related_chain",
        left_categories=frozenset({"security"}),
        right_categories=frozenset(),  # 비어 있으면 "security 외의 모든 category"
        required_entity_keys=frozenset({"ip", "user"}),
        phrase="보안 Finding과 다른 이상이",
    ),
)

_CAUSAL_CAVEAT = "인과관계는 확인되지 않았다. 시간적 근접과 식별자 공유만 관측됐다."


def _rule_matches(
    rule: _HypothesisRule,
    left: ScenarioFinding,
    right: ScenarioFinding,
    edge: CorrelationEdge,
) -> dict[str, tuple[str, ...]] | None:
    """조건을 만족하면 공유 식별자를, 아니면 None을 돌려준다."""
    left_cat = left.finding.category
    right_cat = right.finding.category

    if left_cat not in rule.left_categories:
        return None
    if rule.right_categories:
        if right_cat not in rule.right_categories:
            return None
    else:
        # security 규칙: 상대는 security가 아닌 아무 category
        if right_cat in rule.left_categories:
            return None

    if edge.temporal_relation is None:
        return None

    if rule.required_entity_keys is not None:
        shared = {
            key: values
            for key, values in edge.shared_entities.items()
            if key in rule.required_entity_keys
        }
        if not shared:
            return None
        return shared

    identity: dict[str, tuple[str, ...]] = dict(edge.shared_entities)
    if RELATION_SAME_HOST in edge.relation_types and left.finding.host is not None:
        identity.setdefault("host", (left.finding.host,))
    if edge.shared_evidence_event_ids:
        identity.setdefault("evidence_event_id", edge.shared_evidence_event_ids)
    if not identity:
        return None
    return identity


def build_hypotheses(
    findings_by_id: dict[str, ScenarioFinding],
    edges: Sequence[CorrelationEdge],
    incident_id: str,
) -> tuple[HypothesisCandidate, ...]:
    """incident 안의 edge를 rule에 대조해 가설 후보를 만든다.

    조건을 만족하는 쌍이 없으면 0건이 정상이다 - 숫자를 만들기 위해 규칙을 느슨하게
    적용하지 않는다.
    """
    candidates: list[HypothesisCandidate] = []

    for rule in HYPOTHESIS_RULES:
        supporting_findings: set[str] = set()
        supporting_edges: set[str] = set()
        identity: dict[str, set[str]] = {}
        pair_descriptions: list[str] = []

        for edge in edges:
            source = findings_by_id.get(edge.source_finding_id)
            target = findings_by_id.get(edge.target_finding_id)
            if source is None or target is None:
                continue

            for left, right in ((source, target), (target, source)):
                shared = _rule_matches(rule, left, right, edge)
                if shared is None:
                    continue
                supporting_findings.update({left.finding_id, right.finding_id})
                supporting_edges.add(edge.edge_id)
                for key, values in shared.items():
                    identity.setdefault(key, set()).update(values)
                pair_descriptions.append(
                    f"{left.finding.finding_type}({left.finding.category}) + "
                    f"{right.finding.finding_type}({right.finding.category})"
                )
                break

        if not supporting_findings or not supporting_edges:
            continue

        identity_text = ", ".join(
            f"{key}={','.join(sorted(values))}" for key, values in sorted(identity.items())
        )
        unique_pairs = sorted(set(pair_descriptions))
        statement = (
            f"{rule.phrase} 같은 scenario에서 시간적으로 근접해 관측됨 "
            f"({'; '.join(unique_pairs)}). 공유 식별자: {identity_text}. {_CAUSAL_CAVEAT}"
        )

        candidates.append(
            HypothesisCandidate(
                hypothesis_id=f"{incident_id}:hypothesis:{rule.name}",
                rule_name=rule.name,
                statement=statement,
                supporting_finding_ids=tuple(sorted(supporting_findings)),
                supporting_edge_ids=tuple(sorted(supporting_edges)),
                shared_identity={
                    key: tuple(sorted(values)) for key, values in sorted(identity.items())
                },
                caveats=(_CAUSAL_CAVEAT,),
            )
        )

    return tuple(candidates)


# ---------------------------------------------------------------------------
# 최상위
# ---------------------------------------------------------------------------


def correlate_scenario(projection: ScenarioProjection) -> CorrelationResult:
    """ScenarioProjection 하나를 correlation한다.

    입력은 단일 scenario의 projection이므로 scenario_id가 hard boundary로 자동 보장된다
    (서로 다른 scenario의 Finding이 한 projection에 섞일 수 없다).
    """
    findings = list(projection.findings)
    scenario_id = projection.scenario_id

    if not findings:
        return CorrelationResult(
            scenario_id=scenario_id,
            incidents=(),
            edges=(),
            graph=build_evidence_graph([], (), (), scenario_id),
            timeline=(),
            finding_count=0,
            datasets=(),
            long_span_finding_ids=(),
            notes=("입력 Finding이 0건이다.",),
        )

    findings.sort(key=ScenarioFinding.sort_key)
    findings_by_id = {item.finding_id: item for item in findings}
    unique_findings = [findings_by_id[fid] for fid in sorted(findings_by_id)]

    edges = build_edges(findings, scenario_id)
    long_span_ids = tuple(
        sorted(item.finding_id for item in unique_findings if is_long_span(item))
    )

    components = _connected_components([item.finding_id for item in unique_findings], edges)

    incidents: list[CorrelatedIncident] = []
    for member_ids in components:
        members = [findings_by_id[fid] for fid in member_ids]
        incident_edges = tuple(
            edge
            for edge in edges
            if edge.source_finding_id in member_ids and edge.target_finding_id in member_ids
        )
        grouping_edges = tuple(edge for edge in incident_edges if edge.is_grouping_relation)
        incident_id = _make_incident_id(scenario_id, member_ids)

        grouping_basis = tuple(
            sorted(
                {
                    relation
                    for edge in grouping_edges
                    for relation in edge.relation_types
                    if relation in GROUPING_IDENTITY_RELATIONS
                }
            )
        )

        incidents.append(
            CorrelatedIncident(
                incident_id=incident_id,
                scenario_id=scenario_id,
                datasets=tuple(sorted({item.dataset for item in members})),
                finding_ids=member_ids,
                edge_ids=tuple(sorted(edge.edge_id for edge in incident_edges)),
                relative_start_seconds=min(
                    item.relative_effective_start_seconds for item in members
                ),
                relative_end_seconds=max(
                    item.relative_effective_end_seconds for item in members
                ),
                timeline=build_timeline(members),
                hypotheses=build_hypotheses(findings_by_id, grouping_edges, incident_id),
                impact=build_impact(members),
                grouping_basis=grouping_basis,
                long_span_finding_ids=tuple(
                    sorted(item.finding_id for item in members if is_long_span(item))
                ),
            )
        )

    incidents.sort(key=lambda item: (item.relative_start_seconds, item.incident_id))

    notes: list[str] = []
    if long_span_ids:
        notes.append(
            f"long-span Finding {len(long_span_ids)}건(span_ratio >= {LONG_SPAN_RATIO})의 "
            "시간 관계를 약한 근거로 처리했다."
        )
    clipped = [item.finding_id for item in unique_findings if item.was_clipped]
    if clipped:
        notes.append(
            f"scenario Window 경계로 interval이 잘린 Finding {len(clipped)}건이 있다 "
            "(원본 Finding은 변경되지 않았다)."
        )
    weak_only = [
        edge.edge_id
        for edge in edges
        if not edge.is_grouping_relation
    ]
    if weak_only:
        notes.append(
            f"관계는 있지만 grouping 근거가 못 되는 edge {len(weak_only)}건을 보존했다."
        )

    return CorrelationResult(
        scenario_id=scenario_id,
        incidents=tuple(incidents),
        edges=edges,
        graph=build_evidence_graph(unique_findings, edges, incidents, scenario_id),
        timeline=build_timeline(unique_findings),
        finding_count=len(unique_findings),
        datasets=tuple(sorted({item.dataset for item in unique_findings})),
        long_span_finding_ids=long_span_ids,
        notes=tuple(notes),
    )
