"""Evidence Correlation 테스트.

Finding 원본 불변, scenario_id 경계, grouping 규칙(특히 long-span), 결정론을 검증한다.
Ground Truth와 RAG를 쓰지 않는다.
"""

import re
from datetime import timedelta
from pathlib import Path

import pytest

from correlation import (
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
    correlate_scenario,
    is_long_span,
    make_node_id,
)
from scenario import make_scenario, project_findings, utc
from src.models import EvidenceReference, Finding
from tests.test_agent_skills import _fingerprint

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 좁은 분석 Window: 2시간. 두 dataset에 같은 길이를 준다.
W_START = utc(2022, 1, 24, 3, 0)
W_END = utc(2022, 1, 24, 5, 0)
G_START = utc(2021, 7, 31, 18, 0)
G_END = utc(2021, 7, 31, 20, 0)

SCENARIO = make_scenario(
    "incident-001",
    {"russellmitchell": (W_START, W_END), "gaia": (G_START, G_END)},
)
WINDOW_SECONDS = 7200.0


def _evidence(event_id: str) -> EvidenceReference:
    return EvidenceReference(
        source_type="apache_access",
        source_file="gather/x/logs/apache2/access.log",
        line_number=1,
        timestamp=W_START,
        event_id=event_id,
    )


def _finding(
    *,
    finding_id,
    offset_seconds=0,
    duration_seconds=60,
    dataset="russellmitchell",
    category="availability",
    finding_type="request_spike",
    severity="low",
    host="intranet_server",
    service="apache2",
    entities=None,
    evidence=(),
    window_start=None,
) -> Finding:
    base = window_start or (W_START if dataset == "russellmitchell" else G_START)
    start = base + timedelta(seconds=offset_seconds)
    return Finding(
        finding_id=finding_id,
        dataset=dataset,
        category=category,
        finding_type=finding_type,
        start_time=start,
        end_time=start + timedelta(seconds=duration_seconds),
        host=host,
        service=service,
        severity=severity,
        summary=f"{finding_type} summary",
        metrics={"ratio": 2.0},
        evidence=list(evidence),
        entities={} if entities is None else dict(entities),
        detector="find_request_spike",
    )


def _correlate(findings, scenario=SCENARIO):
    return correlate_scenario(project_findings(findings, scenario))


# ---------------------------------------------------------------------------
# 1~2. 빈 입력 / 단일 Finding
# ---------------------------------------------------------------------------


def test_no_findings():
    result = _correlate([])
    assert result.finding_count == 0
    assert result.incidents == ()
    assert result.edges == ()
    assert result.timeline == ()
    assert result.graph.node_count == 0


def test_single_finding_becomes_single_incident():
    result = _correlate([_finding(finding_id="a")])
    assert result.finding_count == 1
    assert len(result.incidents) == 1
    incident = result.incidents[0]
    assert incident.finding_ids == ("a",)
    assert incident.is_single_finding
    assert result.edges == ()
    assert incident.hypotheses == ()


# ---------------------------------------------------------------------------
# 3~5. grouping이 되는 경우
# ---------------------------------------------------------------------------


def test_same_host_within_300_seconds_groups():
    a = _finding(finding_id="a", offset_seconds=0, duration_seconds=60)
    b = _finding(finding_id="b", offset_seconds=200, duration_seconds=60)
    result = _correlate([a, b])
    assert len(result.edges) == 1
    edge = result.edges[0]
    assert RELATION_SAME_HOST in edge.relation_types
    assert edge.temporal_relation == TEMPORAL_PRECEDES
    assert edge.time_gap_seconds == 140.0
    assert edge.is_grouping_relation
    assert len(result.incidents) == 1
    assert result.incidents[0].finding_ids == ("a", "b")


def test_shared_entity_groups():
    a = _finding(finding_id="a", host=None, entities={"service": ["dbservice1"]})
    b = _finding(
        finding_id="b", offset_seconds=30, host=None, entities={"service": ["dbservice1"]}
    )
    result = _correlate([a, b])
    edge = result.edges[0]
    assert RELATION_SHARED_ENTITY in edge.relation_types
    assert edge.shared_entities == {"service": ("dbservice1",)}
    assert edge.is_grouping_relation
    assert len(result.incidents) == 1


def test_shared_evidence_groups():
    shared = _evidence("gather/x:100")
    a = _finding(finding_id="a", host=None, evidence=[shared])
    b = _finding(finding_id="b", offset_seconds=30, host=None, evidence=[shared])
    result = _correlate([a, b])
    edge = result.edges[0]
    assert RELATION_SHARED_EVIDENCE in edge.relation_types
    assert edge.shared_evidence_event_ids == ("gather/x:100",)
    assert edge.is_grouping_relation


def test_gap_exactly_at_window_is_near_in_time():
    a = _finding(finding_id="a", offset_seconds=0, duration_seconds=60)
    b = _finding(finding_id="b", offset_seconds=60 + int(NEAR_IN_TIME_SECONDS))
    edge = _correlate([a, b]).edges[0]
    assert edge.temporal_relation == TEMPORAL_PRECEDES
    assert edge.time_gap_seconds == NEAR_IN_TIME_SECONDS


def test_gap_beyond_window_has_no_temporal_relation():
    a = _finding(finding_id="a", offset_seconds=0, duration_seconds=60)
    b = _finding(finding_id="b", offset_seconds=60 + int(NEAR_IN_TIME_SECONDS) + 1)
    result = _correlate([a, b])
    edge = result.edges[0]  # same_host/same_service 때문에 edge 자체는 있다
    assert edge.temporal_relation is None
    assert not edge.is_grouping_relation
    assert len(result.incidents) == 2  # grouping되지 않는다


def test_zero_duration_finding_inside_other_overlaps():
    # 표본 1건으로 끝난 metric episode는 start == end다(실제 데이터에 존재).
    a = _finding(finding_id="a", offset_seconds=0, duration_seconds=600)
    b = _finding(finding_id="b", offset_seconds=300, duration_seconds=0)
    edge = _correlate([a, b]).edges[0]
    assert edge.temporal_relation == TEMPORAL_OVERLAPS
    assert edge.is_grouping_relation


# ---------------------------------------------------------------------------
# 6~7. scenario 경계
# ---------------------------------------------------------------------------


def test_different_scenarios_are_never_connected():
    # projection은 단일 scenario만 담는다 -> 서로 다른 scenario의 Finding은 한
    # correlation 입력에 섞일 수 없다.
    other = make_scenario("incident-002", {"russellmitchell": (W_START, W_END)})
    a = _finding(finding_id="a")
    b = _finding(finding_id="b", offset_seconds=30)

    first = _correlate([a], SCENARIO)
    second = _correlate([b], other)
    assert first.scenario_id == "incident-001"
    assert second.scenario_id == "incident-002"
    assert first.edges == () and second.edges == ()
    # edge_id에 scenario_id가 들어가 서로 섞일 수 없다
    combined = _correlate([a, b], SCENARIO)
    assert all(edge.edge_id.startswith("incident-001:edge:") for edge in combined.edges)


def test_cross_dataset_correlation_allowed_within_same_scenario():
    # dataset이 달라도 같은 scenario + 공유 entity + 시간 근접이면 연결된다.
    rm = _finding(
        finding_id="rm",
        dataset="russellmitchell",
        offset_seconds=0,
        host=None,
        service=None,
        entities={"service": ["dbservice1"]},
    )
    gaia = _finding(
        finding_id="gaia",
        dataset="gaia",
        offset_seconds=30,
        host=None,
        service=None,
        category="resource",
        finding_type="cpu_usage_anomaly",
        entities={"service": ["dbservice1"]},
    )
    result = _correlate([rm, gaia])
    assert len(result.edges) == 1
    assert result.edges[0].is_grouping_relation
    assert len(result.incidents) == 1
    incident = result.incidents[0]
    # dataset provenance가 유지된다
    assert incident.datasets == ("gaia", "russellmitchell")
    assert incident.impact.datasets == ("gaia", "russellmitchell")


def test_cross_dataset_without_shared_identity_is_not_grouped():
    # 실제 데이터 상황: RM은 entities={"host":...}, GAIA는 {"service":...} -> 교집합 없음
    rm = _finding(finding_id="rm", entities={"host": ["intranet_server"]})
    gaia = _finding(
        finding_id="gaia",
        dataset="gaia",
        offset_seconds=30,
        host=None,
        service="dbservice1",
        category="network",
        finding_type="network_usage_anomaly",
        entities={"service": ["dbservice1"]},
    )
    result = _correlate([rm, gaia])
    assert len(result.incidents) == 2  # 연결되지 않는다


# ---------------------------------------------------------------------------
# 8~9. grouping 금지
# ---------------------------------------------------------------------------


def test_temporal_only_does_not_group():
    a = _finding(finding_id="a", host="host-a", service=None, entities={"host": ["host-a"]})
    b = _finding(
        finding_id="b",
        offset_seconds=30,
        host="host-b",
        service=None,
        entities={"host": ["host-b"]},
    )
    result = _correlate([a, b])
    edge = result.edges[0]
    assert edge.relation_types == (RELATION_TEMPORAL_OVERLAP,)
    assert not edge.is_grouping_relation
    assert len(result.incidents) == 2


def test_same_service_only_does_not_group():
    # russellmitchell의 service="apache2"는 상수 라벨이라 grouping 근거가 아니다.
    a = _finding(finding_id="a", host="cloud_share", entities={"host": ["cloud_share"]})
    b = _finding(
        finding_id="b",
        offset_seconds=30,
        host="webserver",
        entities={"host": ["webserver"]},
    )
    result = _correlate([a, b])
    edge = result.edges[0]
    assert RELATION_SAME_SERVICE in edge.relation_types
    assert RELATION_SAME_HOST not in edge.relation_types
    assert RELATION_SHARED_ENTITY not in edge.relation_types
    assert not edge.is_grouping_relation
    assert len(result.incidents) == 2


# ---------------------------------------------------------------------------
# 10~13. long-span 규칙
# ---------------------------------------------------------------------------


def _long_span_finding(**overrides) -> Finding:
    """Window 2시간 중 1.5시간(span_ratio 0.75)을 덮는 Finding."""
    defaults = dict(
        finding_id="long",
        offset_seconds=0,
        duration_seconds=5400,
        category="security",
        finding_type="repeated_source_ip_scan",
        severity="high",
        host=None,
        entities={"ip": ["172.19.131.174"]},
    )
    defaults.update(overrides)
    return _finding(**defaults)


def test_long_span_is_detected():
    result = _correlate([_long_span_finding()])
    item = project_findings([_long_span_finding()], SCENARIO).findings[0]
    assert item.span_ratio == 5400.0 / WINDOW_SECONDS
    assert item.span_ratio >= LONG_SPAN_RATIO
    assert is_long_span(item)
    assert result.long_span_finding_ids == ("long",)


def test_long_span_with_temporal_overlap_only_does_not_group():
    long_item = _long_span_finding(host=None, entities={})
    short = _finding(finding_id="short", offset_seconds=600, host=None, service=None)
    result = _correlate([long_item, short])
    edge = result.edges[0]
    assert edge.weak_temporal
    assert RELATION_TEMPORAL_WEAK_LONG_SPAN in edge.relation_types
    assert not edge.is_grouping_relation
    assert len(result.incidents) == 2


def test_long_span_with_same_host_only_does_not_group():
    long_item = _long_span_finding(host="intranet_server", entities={})
    short = _finding(finding_id="short", offset_seconds=600, host="intranet_server", entities={})
    result = _correlate([long_item, short])
    edge = result.edges[0]
    assert RELATION_SAME_HOST in edge.relation_types
    assert edge.weak_temporal
    assert not edge.is_grouping_relation  # same_host 단독으로는 금지
    assert len(result.incidents) == 2


def test_long_span_with_shared_entity_and_temporal_groups():
    long_item = _long_span_finding(entities={"ip": ["172.19.131.174"]})
    short = _finding(
        finding_id="short",
        offset_seconds=600,
        host=None,
        entities={"ip": ["172.19.131.174"]},
    )
    result = _correlate([long_item, short])
    edge = result.edges[0]
    assert RELATION_SHARED_ENTITY in edge.relation_types
    assert edge.temporal_relation is not None
    assert edge.is_grouping_relation
    assert len(result.incidents) == 1


def test_long_span_with_shared_entity_but_far_in_time_does_not_group():
    # long-span이라도 시간적으로 멀면 묶지 않는다(승인된 정책 B).
    long_item = _long_span_finding(offset_seconds=0, duration_seconds=3700)
    far = _finding(
        finding_id="far",
        offset_seconds=3700 + int(NEAR_IN_TIME_SECONDS) + 10,
        host=None,
        entities={"ip": ["172.19.131.174"]},
    )
    result = _correlate([long_item, far])
    edge = result.edges[0]
    assert RELATION_SHARED_ENTITY in edge.relation_types
    assert edge.temporal_relation is None
    assert not edge.is_grouping_relation
    assert len(result.incidents) == 2


def test_long_span_with_shared_evidence_groups_even_without_temporal():
    shared = _evidence("gather/x:42")
    long_item = _long_span_finding(
        offset_seconds=0, duration_seconds=3700, entities={}, evidence=[shared]
    )
    far = _finding(
        finding_id="far",
        offset_seconds=3700 + int(NEAR_IN_TIME_SECONDS) + 10,
        host=None,
        entities={},
        evidence=[shared],
    )
    result = _correlate([long_item, far])
    edge = result.edges[0]
    assert edge.temporal_relation is None
    assert RELATION_SHARED_EVIDENCE in edge.relation_types
    assert edge.is_grouping_relation  # 정책 A: evidence는 단독 허용
    assert len(result.incidents) == 1


def test_long_span_does_not_absorb_every_finding():
    """repeated_source_ip_scan이 모든 Finding을 하나의 incident로 빨아들이지 않는다."""
    long_item = _long_span_finding()  # entities={"ip": [...]}, host=None
    shorts = [
        _finding(
            finding_id=f"s{i}",
            offset_seconds=i * 400,
            host=f"host-{i}",
            entities={"host": [f"host-{i}"]},
        )
        for i in range(9)
    ]
    result = _correlate([long_item, *shorts])
    assert result.finding_count == 10
    # long-span과 짧은 Finding은 entity 키가 달라(ip vs host) 연결되지 않는다
    assert len(result.incidents) == 10
    assert all(incident.is_single_finding for incident in result.incidents)
    assert not any(edge.is_grouping_relation for edge in result.edges)


# ---------------------------------------------------------------------------
# 14~15. clip / 음수 상대시간
# ---------------------------------------------------------------------------


def test_clipped_flag_is_preserved_on_edges():
    clipped = _finding(
        finding_id="clipped",
        offset_seconds=-3600,
        duration_seconds=7200,
        host="intranet_server",
        entities={"host": ["intranet_server"]},
    )
    inside = _finding(
        finding_id="inside",
        offset_seconds=600,
        host="intranet_server",
        entities={"host": ["intranet_server"]},
    )
    result = _correlate([clipped, inside])
    edge = result.edges[0]
    assert edge.source_was_clipped or edge.target_was_clipped
    assert any("잘린" in note for note in edge.notes)


def test_negative_pre_clip_relative_time_does_not_affect_correlation():
    """relative_start_seconds가 음수여도 correlation은 effective 값만 쓴다.

    clip 전 값(-3600)을 쓰면 두 Finding의 간격이 300초를 넘어 grouping되지 않는다.
    effective 값(0)을 쓰면 겹친다.
    """
    pre_window = _finding(
        finding_id="pre",
        offset_seconds=-3600,
        duration_seconds=3900,  # Window 시작 이전부터 시작해 300초까지 이어진다
        host="intranet_server",
        entities={"host": ["intranet_server"]},
    )
    inside = _finding(
        finding_id="inside",
        offset_seconds=100,
        host="intranet_server",
        entities={"host": ["intranet_server"]},
    )
    projection = project_findings([pre_window, inside], SCENARIO)
    pre_item = next(i for i in projection if i.finding_id == "pre")
    assert pre_item.relative_start_seconds == -3600.0  # 원본 기준은 음수로 보존
    assert pre_item.relative_effective_start_seconds == 0.0  # clip 후 T+0

    result = correlate_scenario(projection)
    edge = result.edges[0]
    assert edge.temporal_relation == TEMPORAL_OVERLAPS
    assert edge.is_grouping_relation
    assert len(result.incidents) == 1


def test_correlation_source_never_uses_original_or_pre_clip_time():
    source = (PROJECT_ROOT / "correlation" / "correlate.py").read_text(encoding="utf-8")
    # 시간 관계 계산 함수 안에서는 effective 값만 써야 한다.
    temporal_fn = source[source.index("def _temporal_relation") : source.index("def _shared_entities")]
    assert "relative_effective_start_seconds" in temporal_fn
    assert "relative_effective_end_seconds" in temporal_fn
    assert "original_start_time" not in temporal_fn
    assert "relative_start_seconds" not in temporal_fn
    canonical_fn = source[source.index("def _canonical_order") : source.index("class _Temporal")]
    assert "original_" not in canonical_fn
    assert re.search(r"relative_start_seconds", canonical_fn) is None


# ---------------------------------------------------------------------------
# 17~19. 결정론
# ---------------------------------------------------------------------------


def _sample_findings():
    return [
        _finding(
            finding_id=f"f{i}",
            offset_seconds=i * 100,
            host="intranet_server",
            entities={"host": ["intranet_server"]},
        )
        for i in range(5)
    ] + [_long_span_finding()]


def test_reversed_input_order_yields_identical_result():
    findings = _sample_findings()
    forward = _correlate(findings)
    reverse = _correlate(list(reversed(findings)))
    assert forward == reverse


def test_repeated_runs_are_identical():
    findings = _sample_findings()
    assert _correlate(findings) == _correlate(findings)


def test_no_duplicate_edges():
    findings = _sample_findings()
    result = _correlate(findings)
    pairs = [(e.source_finding_id, e.target_finding_id) for e in result.edges]
    assert len(pairs) == len(set(pairs))
    assert len(result.edges) == len(set(e.edge_id for e in result.edges))


def test_duplicate_finding_input_does_not_create_self_edge():
    finding = _finding(finding_id="a")
    result = _correlate([finding, finding])
    assert result.finding_count == 1
    assert not any(
        e.source_finding_id == e.target_finding_id for e in result.edges
    )


def test_timeline_is_deterministic_and_sorted():
    findings = _sample_findings()
    result = _correlate(findings)
    keys = [
        (e.relative_start_seconds, e.relative_end_seconds, e.finding_id)
        for e in result.timeline
    ]
    assert keys == sorted(keys)
    assert len(result.timeline) == result.finding_count
    assert _correlate(list(reversed(findings))).timeline == result.timeline


def test_incident_id_is_stable_hash_not_uuid():
    findings = _sample_findings()
    first = _correlate(findings).incidents
    second = _correlate(list(reversed(findings))).incidents
    assert [i.incident_id for i in first] == [i.incident_id for i in second]
    for incident in first:
        assert incident.incident_id.startswith("incident-001:incident:")
        assert re.fullmatch(r"[0-9a-f]{12}", incident.incident_id.rsplit(":", 1)[1])


# ---------------------------------------------------------------------------
# 20~21. 불변성
# ---------------------------------------------------------------------------


def test_original_findings_are_not_modified():
    findings = _sample_findings()
    before = [_fingerprint(f) for f in findings]
    _correlate(findings)
    assert [_fingerprint(f) for f in findings] == before


def test_scenario_findings_are_frozen_and_referenced():
    findings = [_finding(finding_id="a")]
    projection = project_findings(findings, SCENARIO)
    item = projection.findings[0]
    with pytest.raises(Exception):
        item.relative_start_seconds = 1.0  # type: ignore[misc]
    assert item.finding is findings[0]
    correlate_scenario(projection)
    assert item.finding is findings[0]


def test_correlation_does_not_assign_to_finding_attributes():
    for name in ("correlate.py", "graph.py", "models.py"):
        source = (PROJECT_ROOT / "correlation" / name).read_text(encoding="utf-8")
        assert not re.search(r"\.finding\.\w+\s*=[^=]", source), name
        assert not re.search(r"finding\.(severity|category|start_time|end_time)\s*=[^=]", source), name


# ---------------------------------------------------------------------------
# hypothesis
# ---------------------------------------------------------------------------


def _pair_for_rule(left_category, left_type, right_category, right_type, *, entities):
    left = _finding(
        finding_id="left",
        offset_seconds=0,
        duration_seconds=120,
        category=left_category,
        finding_type=left_type,
        host=None,
        service=None,
        entities=entities,
    )
    right = _finding(
        finding_id="right",
        offset_seconds=60,
        duration_seconds=120,
        category=right_category,
        finding_type=right_type,
        host=None,
        service=None,
        entities=entities,
    )
    return [left, right]


def test_network_related_degradation_is_generated():
    findings = _pair_for_rule(
        "network",
        "network_usage_anomaly",
        "performance",
        "service_latency_spike",
        entities={"service": ["dbservice1"]},
    )
    result = _correlate(findings)
    names = [h.rule_name for h in result.hypotheses]
    assert "network_related_degradation" in names
    hypothesis = next(h for h in result.hypotheses if h.rule_name == "network_related_degradation")
    assert hypothesis.supporting_finding_ids == ("left", "right")
    assert hypothesis.supporting_edge_ids
    assert hypothesis.shared_identity == {"service": ("dbservice1",)}


def test_resource_rule_is_not_generated_for_network_category():
    findings = _pair_for_rule(
        "network",
        "network_usage_anomaly",
        "performance",
        "service_latency_spike",
        entities={"service": ["dbservice1"]},
    )
    names = [h.rule_name for h in _correlate(findings).hypotheses]
    assert "resource_related_degradation" not in names


def test_resource_related_degradation_is_generated():
    findings = _pair_for_rule(
        "resource",
        "cpu_usage_anomaly",
        "performance",
        "service_latency_spike",
        entities={"service": ["redis"]},
    )
    names = [h.rule_name for h in _correlate(findings).hypotheses]
    assert "resource_related_degradation" in names
    assert "network_related_degradation" not in names


def test_traffic_related_degradation_is_generated():
    findings = _pair_for_rule(
        "availability",
        "request_spike",
        "performance",
        "service_latency_spike",
        entities={"service": ["webservice1"]},
    )
    names = [h.rule_name for h in _correlate(findings).hypotheses]
    assert "traffic_related_degradation" in names


def test_security_related_chain_requires_shared_ip_or_user():
    with_ip = _pair_for_rule(
        "security",
        "repeated_source_ip_scan",
        "availability",
        "request_spike",
        entities={"ip": ["172.19.131.174"]},
    )
    names = [h.rule_name for h in _correlate(with_ip).hypotheses]
    assert "security_related_chain" in names

    with_service = _pair_for_rule(
        "security",
        "repeated_source_ip_scan",
        "availability",
        "request_spike",
        entities={"service": ["apache2"]},
    )
    names = [h.rule_name for h in _correlate(with_service).hypotheses]
    assert "security_related_chain" not in names  # ip/user가 아니면 생성하지 않는다


def test_hypothesis_statement_avoids_causal_claims():
    findings = _pair_for_rule(
        "network",
        "network_usage_anomaly",
        "performance",
        "service_latency_spike",
        entities={"service": ["dbservice1"]},
    )
    for hypothesis in _correlate(findings).hypotheses:
        assert "인과관계는 확인되지 않았다" in hypothesis.statement
        for forbidden in ("원인이다", "때문에 발생", "원인으로 밝혀", "때문이다"):
            assert forbidden not in hypothesis.statement
        assert hypothesis.caveats


def test_hypothesis_requires_supporting_references():
    from correlation.models import HypothesisCandidate

    with pytest.raises(ValueError):
        HypothesisCandidate(
            hypothesis_id="x",
            rule_name="r",
            statement="s",
            supporting_finding_ids=(),
            supporting_edge_ids=("e",),
            shared_identity={},
        )
    with pytest.raises(ValueError):
        HypothesisCandidate(
            hypothesis_id="x",
            rule_name="r",
            statement="s",
            supporting_finding_ids=("f",),
            supporting_edge_ids=(),
            shared_identity={},
        )


def test_no_hypothesis_when_conditions_unmet():
    # 같은 category 쌍은 어떤 rule도 만족하지 않는다.
    findings = _pair_for_rule(
        "availability",
        "request_spike",
        "availability",
        "request_spike",
        entities={"host": ["intranet_server"]},
    )
    assert _correlate(findings).hypotheses == ()


# ---------------------------------------------------------------------------
# impact
# ---------------------------------------------------------------------------


def test_impact_contains_only_observed_entities():
    findings = [
        _finding(
            finding_id="a",
            host="intranet_server",
            service="apache2",
            entities={"host": ["intranet_server"]},
        ),
        _finding(
            finding_id="b",
            offset_seconds=100,
            host=None,
            service="dbservice1",
            severity="high",
            entities={"ip": ["10.0.0.9"]},
        ),
    ]
    result = _correlate(findings)
    impacts = [incident.impact for incident in result.incidents]
    hosts = {h for impact in impacts for h in impact.affected_hosts}
    services = {s for impact in impacts for s in impact.affected_services}
    ips = {i for impact in impacts for i in impact.affected_ips}
    users = {u for impact in impacts for u in impact.affected_users}
    assert hosts == {"intranet_server"}
    assert services == {"apache2", "dbservice1"}
    assert ips == {"10.0.0.9"}
    assert users == set()  # user entity를 내보내는 detector가 없다


def test_impact_severity_counts_sum_to_finding_count():
    findings = _sample_findings()
    result = _correlate(findings)
    total = sum(
        sum(incident.impact.severity_counts.values()) for incident in result.incidents
    )
    assert total == result.finding_count


def test_impact_does_not_recompute_severity():
    finding = _finding(finding_id="a", severity="high")
    result = _correlate([finding])
    assert result.incidents[0].impact.severity_counts == {"high": 1}
    assert finding.severity == "high"


# ---------------------------------------------------------------------------
# graph
# ---------------------------------------------------------------------------


def test_graph_nodes_use_scenario_namespace_without_dataset():
    finding = _finding(
        finding_id="a", host="intranet_server", entities={"ip": ["172.19.131.174"]}
    )
    graph = _correlate([finding]).graph
    ids = {node.node_id for node in graph.nodes}
    assert make_node_id("incident-001", "host", "intranet_server") in ids
    assert make_node_id("incident-001", "ip", "172.19.131.174") in ids
    assert all(node.node_id.startswith("incident-001:") for node in graph.nodes)
    # dataset이 node_id에 들어가지 않는다
    assert not any(":russellmitchell:" in node.node_id for node in graph.nodes)


def test_graph_entity_node_records_datasets_provenance():
    rm = _finding(
        finding_id="rm", host=None, service=None, entities={"service": ["shared-svc"]}
    )
    gaia = _finding(
        finding_id="gaia",
        dataset="gaia",
        offset_seconds=30,
        host=None,
        service=None,
        entities={"service": ["shared-svc"]},
    )
    graph = _correlate([rm, gaia]).graph
    node = next(n for n in graph.nodes if n.node_type == "service")
    assert node.datasets == ("gaia", "russellmitchell")


def test_graph_edge_types_are_only_observed_ones():
    findings = _sample_findings()
    graph = _correlate(findings).graph
    types = {edge.edge_type for edge in graph.edges}
    assert types <= {"observed_on", "affects", "involves", "preceded", "correlated_with"}
    assert "triggered" not in types


def test_graph_has_no_event_or_process_nodes():
    graph = _correlate(_sample_findings()).graph
    types = {node.node_type for node in graph.nodes}
    assert types <= {"finding", "host", "service", "ip", "user"}
    assert "event" not in types
    assert "process" not in types


def test_graph_has_no_user_node_without_user_entity():
    graph = _correlate([_finding(finding_id="a", entities={"host": ["h"]})]).graph
    assert graph.nodes_of_type("user") == ()


def test_graph_edges_have_no_duplicates():
    graph = _correlate(_sample_findings()).graph
    keys = [(e.edge_type, e.source_node_id, e.target_node_id) for e in graph.edges]
    assert len(keys) == len(set(keys))


def test_preceded_edge_not_created_for_long_span():
    long_item = _long_span_finding(host="intranet_server", entities={})
    short = _finding(finding_id="short", offset_seconds=6000, host="intranet_server", entities={})
    graph = _correlate([long_item, short]).graph
    assert graph.edges_of_type("preceded") == ()


def test_preceded_edge_created_for_normal_precedes():
    a = _finding(finding_id="a", offset_seconds=0, duration_seconds=60)
    b = _finding(finding_id="b", offset_seconds=200)
    graph = _correlate([a, b]).graph
    preceded = graph.edges_of_type("preceded")
    assert len(preceded) == 1
    assert preceded[0].source_node_id.endswith(":finding:a")


# ---------------------------------------------------------------------------
# 24~25. 계층 분리
# ---------------------------------------------------------------------------


def test_correlation_does_not_use_ground_truth_or_higher_layers():
    offenders = []
    for path in (PROJECT_ROOT / "correlation").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "ground_truth" in text.lower():
            offenders.append(f"{path.name}: ground_truth")
        for module in ("evaluation", "agents", "agent_skills", "orchestration", "llm"):
            if re.search(rf"^\s*(from|import)\s+{module}\b", text, re.MULTILINE):
                offenders.append(f"{path.name}: {module}")
    assert offenders == []


def test_correlation_has_no_rag_or_external_service_imports():
    forbidden = ("supabase", "openai", "chromadb", "pinecone", "faiss", "langchain", "langgraph")
    offenders = []
    for path in (PROJECT_ROOT / "correlation").rglob("*.py"):
        text = path.read_text(encoding="utf-8").lower()
        for token in forbidden:
            if re.search(rf"^\s*(from|import)\s+\S*{token}", text, re.MULTILINE):
                offenders.append(f"{path.name}: {token}")
    assert offenders == []


def test_lower_layers_do_not_import_correlation():
    offenders = []
    for directory in ("src", "scenario", "agents", "agent_skills", "evaluation"):
        for path in (PROJECT_ROOT / directory).rglob("*.py"):
            if re.search(
                r"^\s*(from|import)\s+correlation\b",
                path.read_text(encoding="utf-8"),
                re.MULTILINE,
            ):
                offenders.append(str(path.relative_to(PROJECT_ROOT)))
    assert offenders == []


def test_no_numeric_strength_or_confidence_field():
    from correlation.models import CorrelationEdge, HypothesisCandidate

    for model in (CorrelationEdge, HypothesisCandidate):
        fields = set(model.__dataclass_fields__)
        assert "strength" not in fields
        assert "confidence" not in fields
        assert "score" not in fields
