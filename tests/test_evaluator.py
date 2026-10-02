from datetime import datetime, timedelta, timezone

from evaluation import (
    FINDING_TYPE_GROUND_TRUTH_TYPES,
    UMBRELLA_GROUND_TRUTH_TYPES,
    EvaluationCoverage,
    GroundTruthIncident,
    build_coverage_from_events,
    build_gaia_metric_coverage,
    evaluate_all,
    evaluate_detector,
)
from evaluation.evaluator import _try_match
from src.models import Finding, NormalizedEvent

T0 = datetime(2022, 1, 24, 3, 57, 0, tzinfo=timezone.utc)


def _finding(**overrides) -> Finding:
    defaults = dict(
        finding_id="f1",
        dataset="russellmitchell",
        category="security",
        finding_type="request_spike",
        start_time=T0,
        end_time=T0 + timedelta(minutes=2),
        host="intranet_server",
        service=None,
        severity="high",
        summary="s",
        metrics={},
        evidence=[],
        entities={},
        detector="find_request_spike",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _incident(**overrides) -> GroundTruthIncident:
    defaults = dict(
        dataset="russellmitchell",
        incident_id="gt1",
        anomaly_type="dirb",
        start_time=T0,
        end_time=T0 + timedelta(minutes=2),
        host="intranet_server",
        service=None,
        entities={},
        evidence_event_ids=(),
    )
    defaults.update(overrides)
    return GroundTruthIncident(**defaults)


# ---------------------------------------------------------------------------
# _try_match: 시간 overlap / host-service / entity
# ---------------------------------------------------------------------------


def test_full_overlap_matches():
    finding = _finding()
    incident = _incident()
    match = _try_match(finding, incident)
    assert match is not None
    assert match.overlap_ratio == 1.0
    assert match.overlap_seconds == 120.0


def test_partial_overlap_matches():
    finding = _finding(start_time=T0, end_time=T0 + timedelta(minutes=2))
    incident = _incident(start_time=T0 + timedelta(minutes=1), end_time=T0 + timedelta(minutes=3))
    match = _try_match(finding, incident)
    assert match is not None
    assert match.overlap_seconds == 60.0
    assert match.overlap_ratio == 60.0 / 120.0  # incident 지속시간(120초) 대비 비율


def test_no_overlap_does_not_match():
    finding = _finding(start_time=T0, end_time=T0 + timedelta(minutes=1))
    incident = _incident(start_time=T0 + timedelta(hours=1), end_time=T0 + timedelta(hours=1, minutes=1))
    assert _try_match(finding, incident) is None


def test_adjacent_but_not_overlapping_does_not_match():
    finding = _finding(start_time=T0, end_time=T0 + timedelta(minutes=1))
    incident = _incident(start_time=T0 + timedelta(minutes=1), end_time=T0 + timedelta(minutes=2))
    assert _try_match(finding, incident) is None


def test_instantaneous_finding_inside_incident_matches():
    # metric/latency episode가 표본 1건이면 start == end 인 Finding이 만들어진다.
    instant = T0 + timedelta(seconds=30)
    finding = _finding(start_time=instant, end_time=instant)
    incident = _incident(start_time=T0, end_time=T0 + timedelta(minutes=2))
    match = _try_match(finding, incident)
    assert match is not None
    assert match.overlap_seconds == 0.0
    assert match.overlap_ratio == 0.0


def test_instantaneous_incident_inside_finding_matches():
    # labels/ 의 라벨이 한 시각에만 붙으면 지속시간 0초인 incident가 만들어진다.
    instant = T0 + timedelta(seconds=30)
    finding = _finding(start_time=T0, end_time=T0 + timedelta(minutes=2))
    incident = _incident(start_time=instant, end_time=instant)
    match = _try_match(finding, incident)
    assert match is not None
    assert match.overlap_ratio is None  # incident 지속시간이 0이라 비율은 정의되지 않는다


def test_instantaneous_finding_outside_incident_does_not_match():
    instant = T0 + timedelta(hours=5)
    finding = _finding(start_time=instant, end_time=instant)
    incident = _incident(start_time=T0, end_time=T0 + timedelta(minutes=2))
    assert _try_match(finding, incident) is None


def test_host_mismatch_does_not_match_despite_time_overlap():
    finding = _finding(host="webserver")
    incident = _incident(host="intranet_server")
    assert _try_match(finding, incident) is None


def test_host_none_on_either_side_is_permissive():
    finding = _finding(host=None)
    incident = _incident(host="intranet_server")
    assert _try_match(finding, incident) is not None


def test_service_mismatch_does_not_match():
    finding = _finding(
        dataset="gaia", finding_type="cpu_usage_anomaly", host=None, service="dbservice1"
    )
    incident = _incident(
        dataset="gaia", anomaly_type="cpu_anomalies", host=None, service="webservice2"
    )
    assert _try_match(finding, incident) is None


def test_service_match_succeeds():
    finding = _finding(
        dataset="gaia", finding_type="cpu_usage_anomaly", host=None, service="dbservice1"
    )
    incident = _incident(
        dataset="gaia", anomaly_type="cpu_anomalies", host=None, service="dbservice1"
    )
    assert _try_match(finding, incident) is not None


def test_different_dataset_never_matches():
    finding = _finding(dataset="gaia")
    incident = _incident(dataset="russellmitchell")
    assert _try_match(finding, incident) is None


def test_unmapped_finding_type_does_not_match_anything():
    finding = _finding(finding_type="network_usage_anomaly")
    incident = _incident()
    assert _try_match(finding, incident) is None


def test_anomaly_type_not_in_finding_type_mapping_does_not_match():
    finding = _finding(finding_type="repeated_source_ip_scan")
    incident = _incident(anomaly_type="attacker_vpn")  # 매핑에 없는 유형
    assert _try_match(finding, incident) is None


def test_entities_overlap_is_recorded_but_not_required():
    finding = _finding(entities={"ip": ["172.19.131.174"]})
    incident_matching_ip = _incident(entities={"ip": ["172.19.131.174"]})
    incident_no_entities = _incident(entities={})

    match_with_entities = _try_match(finding, incident_matching_ip)
    assert match_with_entities.entities_overlap is True

    match_without_entities = _try_match(finding, incident_no_entities)
    assert match_without_entities is not None  # entity가 없어도 match는 성립
    assert match_without_entities.entities_overlap is False


# ---------------------------------------------------------------------------
# evaluate_detector: incident/Finding 다대다, precision/recall/f1
# ---------------------------------------------------------------------------


def test_one_incident_matched_by_multiple_findings_counts_once():
    incident = _incident()
    findings = [
        _finding(finding_id="f1", start_time=T0, end_time=T0 + timedelta(minutes=1)),
        _finding(finding_id="f2", start_time=T0 + timedelta(seconds=30), end_time=T0 + timedelta(minutes=2)),
    ]
    result = evaluate_detector(findings, [incident], detector="find_request_spike")
    assert result.total_incidents == 1
    assert result.detected_incidents == 1
    assert result.missed_incidents == 0
    assert result.total_findings == 2
    assert result.true_positive_findings == 2  # 두 finding 모두 매치에 기여했다
    assert result.false_positive_findings == 0
    assert result.precision == 1.0
    assert result.recall == 1.0


def test_one_finding_matching_multiple_incidents_counts_finding_once():
    finding = _finding(start_time=T0, end_time=T0 + timedelta(hours=1))
    incidents = [
        _incident(incident_id="gt1", anomaly_type="dirb", start_time=T0, end_time=T0 + timedelta(minutes=1)),
        _incident(incident_id="gt2", anomaly_type="wpscan", start_time=T0 + timedelta(minutes=10), end_time=T0 + timedelta(minutes=11)),
    ]
    result = evaluate_detector([finding], incidents, detector="find_request_spike")
    assert result.total_incidents == 2
    assert result.detected_incidents == 2
    assert result.total_findings == 1
    assert result.true_positive_findings == 1
    assert result.false_positive_findings == 0
    assert result.recall == 1.0
    assert result.precision == 1.0


def test_finding_without_matching_incident_is_false_positive():
    finding = _finding(start_time=T0 + timedelta(days=10), end_time=T0 + timedelta(days=10, minutes=1))
    incident = _incident()  # 전혀 다른 시각
    result = evaluate_detector([finding], [incident], detector="find_request_spike")
    assert result.total_findings == 1
    assert result.true_positive_findings == 0
    assert result.false_positive_findings == 1
    assert result.false_positive_finding_ids == ["f1"]
    assert result.precision == 0.0
    assert result.missed_incidents == 1  # incident도 매치 못 받았으니 동시에 missed


def test_incident_without_matching_finding_is_missed():
    incident = _incident(incident_id="gt-missed", start_time=T0 + timedelta(days=5))
    result = evaluate_detector([], [incident], detector="find_request_spike")
    assert result.total_incidents == 1
    assert result.detected_incidents == 0
    assert result.missed_incidents == 1
    assert result.missed_incident_ids == ["gt-missed"]
    assert result.recall == 0.0
    assert result.precision is None  # finding이 아예 없으므로 정의되지 않는다


def test_no_incidents_at_all_yields_none_recall():
    finding = _finding()
    result = evaluate_detector([finding], [], detector="find_request_spike")
    assert result.total_incidents == 0
    assert result.recall is None
    assert result.false_positive_findings == 1  # 비교할 incident가 없으니 전부 FP


def test_findings_with_unmapped_finding_type_are_excluded_entirely():
    # network_usage_anomaly는 GT 매핑이 없다 - false positive로도 세면 안 된다.
    finding = _finding(
        detector="find_metric_anomaly", finding_type="network_usage_anomaly", dataset="gaia", host=None, service="dbservice1"
    )
    result = evaluate_detector([finding], [], detector="find_metric_anomaly")
    assert result.total_findings == 0
    assert result.false_positive_findings == 0
    assert result.precision is None


def test_f1_is_harmonic_mean_of_precision_and_recall():
    # incident 2개 중 1개 detect(recall=0.5), finding 2개 중 1개가 TP(precision=0.5)
    incidents = [
        _incident(incident_id="gt1", start_time=T0, end_time=T0 + timedelta(minutes=1)),
        _incident(incident_id="gt2", start_time=T0 + timedelta(days=1), end_time=T0 + timedelta(days=1, minutes=1)),
    ]
    findings = [
        _finding(finding_id="f1", start_time=T0, end_time=T0 + timedelta(minutes=1)),
        _finding(finding_id="f2", start_time=T0 + timedelta(days=2), end_time=T0 + timedelta(days=2, minutes=1)),
    ]
    result = evaluate_detector(findings, incidents, detector="find_request_spike")
    assert result.precision == 0.5
    assert result.recall == 0.5
    assert result.f1 == 0.5  # 2*0.5*0.5/(0.5+0.5) = 0.5


def test_f1_is_zero_not_none_when_precision_and_recall_are_both_zero():
    # 완전히 틀린 것("성능 0")과 평가할 수 없는 것("정의 불가")은 구분돼야 한다.
    incident = _incident(start_time=T0, end_time=T0 + timedelta(minutes=1))
    finding = _finding(start_time=T0 + timedelta(days=3), end_time=T0 + timedelta(days=3, minutes=1))
    result = evaluate_detector([finding], [incident], detector="find_request_spike")
    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.f1 == 0.0


def test_f1_is_none_only_when_a_denominator_is_missing():
    incident = _incident()
    result = evaluate_detector([], [incident], detector="find_request_spike")
    assert result.recall == 0.0
    assert result.precision is None  # finding이 없어 분모 0
    assert result.f1 is None


# ---------------------------------------------------------------------------
# 의미 기준 mapping
# ---------------------------------------------------------------------------


def test_mapping_covers_only_automated_scanner_labels():
    # 같은 access.log에 있다는 이유로 매핑하지 않는다. 경로 1개(webshell_cmd)나
    # 요청 3~12건(webshell_upload, service_scan)은 스캐닝도 급증도 아니다.
    for finding_type in ("request_spike", "repeated_source_ip_scan"):
        assert FINDING_TYPE_GROUND_TRUTH_TYPES[finding_type] == frozenset({"dirb", "wpscan"})


def test_umbrella_labels_are_excluded_from_detector_mapping():
    assert UMBRELLA_GROUND_TRUTH_TYPES == frozenset({"foothold", "attacker_http"})
    for types in FINDING_TYPE_GROUND_TRUTH_TYPES.values():
        assert not (types & UMBRELLA_GROUND_TRUTH_TYPES)


def test_umbrella_incident_does_not_match_any_finding():
    finding = _finding()
    assert _try_match(finding, _incident(anomaly_type="foothold")) is None
    assert _try_match(finding, _incident(anomaly_type="attacker_http")) is None


# ---------------------------------------------------------------------------
# entity 평가 모드 (전체 기간 Finding)
# ---------------------------------------------------------------------------


def _scan_finding(**overrides) -> Finding:
    return _finding(
        finding_type="repeated_source_ip_scan",
        detector="find_scan_pattern",
        host=None,
        service="apache2",
        **overrides,
    )


def test_entity_mode_requires_entity_overlap():
    # 시간이 겹쳐도 IP가 다르면 match로 인정하지 않는다.
    finding = _scan_finding(entities={"ip": ["10.0.0.1"]})
    incident = _incident(entities={"ip": ["172.19.131.174"]})
    assert _try_match(finding, incident, mode="entity") is None
    # 같은 조건이 temporal 모드에서는 (entity 불일치와 무관하게) match가 된다.
    assert _try_match(finding, incident, mode="temporal") is not None


def test_entity_mode_matches_when_ip_agrees():
    finding = _scan_finding(entities={"ip": ["172.19.131.174"]})
    incident = _incident(entities={"ip": ["172.19.131.174"]})
    match = _try_match(finding, incident, mode="entity")
    assert match is not None
    assert match.entities_overlap is True


def test_whole_period_detector_metrics_are_flagged_non_official():
    finding = _scan_finding(
        start_time=T0, end_time=T0 + timedelta(days=3), entities={"ip": ["172.19.131.174"]}
    )
    incident = _incident(entities={"ip": ["172.19.131.174"]})
    coverage = EvaluationCoverage(
        dataset="russellmitchell", start_time=T0, end_time=T0 + timedelta(days=3)
    )
    result = evaluate_detector(
        [finding], [incident], detector="find_scan_pattern", coverage=coverage
    )
    assert result.evaluation_mode == "entity"
    assert result.official_temporal_metrics is False
    assert result.recall == 1.0  # 수치 자체는 계산하지만
    assert result.max_finding_span_ratio == 1.0  # 시간 폭이 관측 기간 전체다
    assert any("판별력" in c for c in result.caveats)


def test_temporal_detector_metrics_are_official():
    result = evaluate_detector([_finding()], [_incident()], detector="find_request_spike")
    assert result.evaluation_mode == "temporal"
    assert result.official_temporal_metrics is True
    assert result.caveats == []


# ---------------------------------------------------------------------------
# Evaluation Coverage
# ---------------------------------------------------------------------------


def test_incident_outside_observed_period_is_excluded_from_recall_denominator():
    incident_in = _incident(incident_id="in", start_time=T0, end_time=T0 + timedelta(minutes=1))
    incident_out = _incident(
        incident_id="out", start_time=T0 + timedelta(days=30), end_time=T0 + timedelta(days=30, minutes=1)
    )
    coverage = EvaluationCoverage(
        dataset="russellmitchell", start_time=T0, end_time=T0 + timedelta(days=1)
    )
    result = evaluate_detector(
        [], [incident_in, incident_out], detector="find_request_spike", coverage=coverage
    )
    assert result.total_incidents == 1  # 관측하지 않은 기간의 incident는 분모에서 빠진다
    assert result.out_of_coverage_incidents == 1
    assert result.out_of_coverage_by_type == {"dirb": 1}


def test_incident_on_unobserved_service_is_excluded():
    observed = _incident(incident_id="ok", dataset="gaia", anomaly_type="cpu_anomalies", host=None, service="dbservice2")
    unobserved = _incident(incident_id="no", dataset="gaia", anomaly_type="cpu_anomalies", host=None, service="webservice1")
    coverage = EvaluationCoverage(
        dataset="gaia",
        start_time=T0 - timedelta(days=1),
        end_time=T0 + timedelta(days=1),
        services=frozenset({"dbservice2"}),
    )
    result = evaluate_detector(
        [], [observed, unobserved], detector="find_metric_anomaly", coverage=coverage
    )
    assert result.total_incidents == 1
    assert result.out_of_coverage_incidents == 1


def test_coverage_none_does_not_shrink_denominator():
    incidents = [_incident(incident_id=f"gt{i}") for i in range(3)]
    result = evaluate_detector([], incidents, detector="find_request_spike", coverage=None)
    assert result.total_incidents == 3
    assert result.out_of_coverage_incidents == 0


def test_coverage_built_from_events_measures_period_and_axes():
    events = [
        NormalizedEvent(
            event_id=f"f:{i}",
            source_type="gaia_metric",
            host=host,
            source_path="f",
            line_number=i,
            timestamp=T0 + timedelta(minutes=i),
            raw="",
            dataset="gaia",
            extra={"metric_name": metric},
        )
        for i, (host, metric) in enumerate([("dbservice2", "mem"), ("redis", "mem"), ("x", "other")])
    ]
    coverage = build_coverage_from_events(
        events,
        dataset="gaia",
        predicate=lambda e: e.extra.get("metric_name") == "mem",  # 지원 metric만
        service_fn=lambda e: e.host,
    )
    assert coverage is not None
    assert coverage.event_count == 2  # 지원하지 않는 metric의 이벤트는 범위에 안 들어간다
    assert coverage.services == frozenset({"dbservice2", "redis"})
    assert coverage.hosts is None  # host_fn을 주지 않았으므로 제약 없음
    assert coverage.start_time == T0
    assert coverage.end_time == T0 + timedelta(minutes=1)


def test_coverage_from_events_returns_none_when_nothing_observed():
    assert build_coverage_from_events([], dataset="gaia") is None


def _metric_event(i, host, metric):
    return NormalizedEvent(
        event_id=f"f:{i}",
        source_type="gaia_metric",
        host=host,
        source_path="f",
        line_number=i,
        timestamp=T0 + timedelta(minutes=i),
        raw="",
        dataset="gaia",
        extra={"metric_name": metric, "value": 0.1},
    )


def test_gaia_coverage_restricts_service_per_resource_kind():
    # dbservice1은 network metric만, dbservice2는 memory metric만 관측된 상황.
    events = [
        _metric_event(0, "dbservice1", "docker_network_in_packets"),
        _metric_event(1, "dbservice2", "docker_memory_stats_active_anon"),
    ]
    coverage = build_gaia_metric_coverage(events)
    assert coverage is not None
    assert coverage.services == frozenset({"dbservice1", "dbservice2"})
    # memory_anomalies를 볼 수 있는 service는 dbservice2 하나뿐이다.
    assert coverage.by_anomaly_type["memory_anomalies"].services == frozenset({"dbservice2"})
    # CPU metric은 아무 service에서도 관측되지 않았다.
    assert coverage.by_anomaly_type["cpu_anomalies"].services == frozenset()

    mem_ok = _incident(dataset="gaia", anomaly_type="memory_anomalies", host=None, service="dbservice2")
    mem_no = _incident(dataset="gaia", anomaly_type="memory_anomalies", host=None, service="dbservice1")
    cpu_no = _incident(dataset="gaia", anomaly_type="cpu_anomalies", host=None, service="dbservice1")
    assert coverage.covers(mem_ok) is True
    assert coverage.covers(mem_no) is False  # service는 관측했지만 memory metric이 없다
    assert coverage.covers(cpu_no) is False  # CPU metric을 관측한 service가 없다


def test_gaia_coverage_period_is_measured_per_resource_kind():
    # memory metric은 뒤쪽 구간에서만 관측됐다. 전체 관측 기간(network 포함)으로 판정하면
    # memory metric이 없던 앞쪽 구간의 incident까지 분모에 들어간다.
    events = [
        _metric_event(0, "dbservice2", "docker_network_in_packets"),
        _metric_event(100, "dbservice2", "docker_memory_stats_active_anon"),
        _metric_event(110, "dbservice2", "docker_memory_stats_active_anon"),
    ]
    coverage = build_gaia_metric_coverage(events)
    memory = coverage.by_anomaly_type["memory_anomalies"]
    assert memory.start_time == T0 + timedelta(minutes=100)
    assert memory.end_time == T0 + timedelta(minutes=110)
    assert coverage.start_time == T0  # 전체 범위는 network metric까지 포함해 더 넓다

    early = _incident(
        dataset="gaia",
        anomaly_type="memory_anomalies",
        host=None,
        service="dbservice2",
        start_time=T0 + timedelta(minutes=1),
        end_time=T0 + timedelta(minutes=2),
    )
    late = _incident(
        dataset="gaia",
        anomaly_type="memory_anomalies",
        host=None,
        service="dbservice2",
        start_time=T0 + timedelta(minutes=105),
        end_time=T0 + timedelta(minutes=106),
    )
    assert coverage.covers(early) is False  # memory metric을 관측하지 않던 시점
    assert coverage.covers(late) is True


def test_evaluate_all_applies_per_detector_coverage():
    incident = _incident(start_time=T0 + timedelta(days=30))
    coverage = EvaluationCoverage(
        dataset="russellmitchell", start_time=T0, end_time=T0 + timedelta(days=1)
    )
    result = evaluate_all([], [incident], coverages={"find_request_spike": coverage})
    assert result["find_request_spike"].total_incidents == 0  # coverage 적용
    assert result["find_scan_pattern"].total_incidents == 1  # coverage 미지정 -> 제한 없음


def test_evaluate_all_returns_every_registered_detector():
    result = evaluate_all([], [])
    assert set(result.keys()) == {
        "find_request_spike",
        "find_scan_pattern",
        "find_metric_anomaly",
        "find_latency_anomaly",
        "find_log_error_spike",
    }
    # 매핑이 비어 있는 detector는 GT 유형 자체가 없다.
    assert result["find_latency_anomaly"].ground_truth_types == frozenset()
    assert result["find_log_error_spike"].ground_truth_types == frozenset()
