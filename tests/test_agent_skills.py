"""Agent Skill wrapper 단독 테스트 (Agent 없이 실행).

검증 초점은 "wrapper가 기존 detector를 그대로 호출하고 결과를 건드리지 않는다"다.
detector 자체의 탐지 정확도는 tests/test_apache_traffic.py 등에서 이미 검증한다.
"""

from datetime import datetime, timedelta, timezone

from agent_skills.application_analysis.scripts.run_application_analysis import (
    DETECTORS as APPLICATION_DETECTORS,
)
from agent_skills.application_analysis.scripts.run_application_analysis import (
    SOURCE_TYPES as APPLICATION_SOURCE_TYPES,
)
from agent_skills.application_analysis.scripts.run_application_analysis import (
    run_application_analysis,
)
from agent_skills.authentication_analysis.scripts.run_authentication_analysis import (
    DETECTORS as AUTHENTICATION_DETECTORS,
)
from agent_skills.authentication_analysis.scripts.run_authentication_analysis import (
    IMPLEMENTED,
    run_authentication_analysis,
)
from agent_skills.network_analysis.scripts.run_network_analysis import (
    run_network_analysis,
    select_network_findings,
)
from agent_skills.security_analysis.scripts.run_security_analysis import (
    DETECTORS as SECURITY_DETECTORS,
)
from agent_skills.security_analysis.scripts.run_security_analysis import (
    run_security_analysis,
    select_security_findings,
)
from agent_skills.server_analysis.scripts.run_server_analysis import run_server_analysis
from src.models import Finding, NormalizedEvent
from src.skills import find_metric_anomaly, find_request_spike, find_scan_pattern

RM_T0 = datetime(2022, 1, 21, 0, 0, 0, tzinfo=timezone.utc)
GAIA_T0 = datetime(2021, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

_NORMAL_WINDOWS = 150
_NORMAL_PER_WINDOW = 4
_SPIKE_COUNT = 200

_METRIC_INTERVAL = timedelta(seconds=30)
_METRIC_BASELINE_N = 600


# ---------------------------------------------------------------------------
# fixture: 기존 detector 테스트와 같은 모양의 입력을 만든다
# ---------------------------------------------------------------------------


def _access_event(*, event_id, host, timestamp, src_ip, status=200, path="/index.html"):
    return NormalizedEvent(
        event_id=event_id,
        source_type="apache_access",
        host=host,
        source_path=f"gather/{host}/logs/apache2/access.log",
        line_number=1,
        timestamp=timestamp,
        raw="raw",
        src_ip=src_ip,
        event_type="http_request",
        extra={"status": status, "path": path},
    )


def _apache_events_with_spike(host="webserver"):
    """정상 트래픽 + 뚜렷한 요청 급증 + 스캐닝 IP."""
    events = []
    eid = 0
    for w in range(_NORMAL_WINDOWS):
        window_start = RM_T0 + timedelta(seconds=60 * w)
        for i in range(_NORMAL_PER_WINDOW):
            eid += 1
            events.append(
                _access_event(
                    event_id=f"n{eid}",
                    host=host,
                    timestamp=window_start + timedelta(seconds=i),
                    src_ip="10.0.0.1",
                )
            )
    spike_start = RM_T0 + timedelta(seconds=60 * _NORMAL_WINDOWS)
    for i in range(_SPIKE_COUNT):
        eid += 1
        events.append(
            _access_event(
                event_id=f"s{eid}",
                host=host,
                timestamp=spike_start + timedelta(milliseconds=100 * i),
                src_ip="172.19.131.174",
                status=404,
                path=f"/scan-{i}",
            )
        )
    # find_scan_pattern은 비교 대상 IP가 최소 3개 필요하다.
    for extra_ip in ("10.0.0.2", "10.0.0.3"):
        for i in range(12):
            eid += 1
            events.append(
                _access_event(
                    event_id=f"o{eid}",
                    host=host,
                    timestamp=RM_T0 + timedelta(seconds=30 * i),
                    src_ip=extra_ip,
                )
            )
    return events


def _metric_event(*, event_id, host, metric_name, value, timestamp):
    return NormalizedEvent(
        event_id=event_id,
        source_type="gaia_metric",
        host=host,
        source_path=f"metric/{host}_0.0.0.1_{metric_name}_2021-07-01_2021-07-31.csv",
        line_number=1,
        timestamp=timestamp,
        raw="raw",
        dataset="gaia",
        event_type="gaia_metric_sample",
        extra={"value": value, "metric_name": metric_name},
    )


def _metric_events_with_spike(host="system", metric_name="system_cpu_total_norm_pct"):
    events = [
        _metric_event(
            event_id=f"b{i}",
            host=host,
            metric_name=metric_name,
            value=0.05,
            timestamp=GAIA_T0 + i * _METRIC_INTERVAL,
        )
        for i in range(_METRIC_BASELINE_N)
    ]
    spike_start = GAIA_T0 + _METRIC_BASELINE_N * _METRIC_INTERVAL
    events.append(
        _metric_event(
            event_id="spike",
            host=host,
            metric_name=metric_name,
            value=0.99,
            timestamp=spike_start,
        )
    )
    return events


def _network_metric_events(host="dbservice1"):
    events = [
        _metric_event(
            event_id=f"nb{i}",
            host=host,
            metric_name="docker_network_in_packets",
            value=14.0,
            timestamp=GAIA_T0 + i * _METRIC_INTERVAL,
        )
        for i in range(_METRIC_BASELINE_N)
    ]
    spike_start = GAIA_T0 + _METRIC_BASELINE_N * _METRIC_INTERVAL
    events.append(
        _metric_event(
            event_id="nspike",
            host=host,
            metric_name="docker_network_in_packets",
            value=580.0,
            timestamp=spike_start,
        )
    )
    return events


def _auth_event(event_id="a1"):
    return NormalizedEvent(
        event_id=event_id,
        source_type="syslog_auth",
        host="intranet_server",
        source_path="gather/intranet_server/logs/auth.log",
        line_number=1,
        timestamp=RM_T0,
        raw="raw",
        user="jhall",
        src_ip="172.19.131.174",
        event_type="dovecot_auth_failure",
    )


# ---------------------------------------------------------------------------
# 1. 기존 detector가 정상 호출되는지
# ---------------------------------------------------------------------------


def test_application_analysis_invokes_apache_detectors():
    findings = run_application_analysis(_apache_events_with_spike())
    types = {f.finding_type for f in findings}
    assert "request_spike" in types
    assert "repeated_source_ip_scan" in types
    detectors = {f.detector for f in findings}
    assert detectors <= set(APPLICATION_DETECTORS)


def test_server_analysis_invokes_metric_detector():
    findings = run_server_analysis(_metric_events_with_spike())
    assert findings
    assert all(f.detector == "find_metric_anomaly" for f in findings)
    assert {f.finding_type for f in findings} == {"cpu_usage_anomaly"}


def test_empty_input_returns_empty_list_without_calling_detectors():
    assert run_application_analysis([]) == []
    assert run_server_analysis([]) == []
    assert run_network_analysis([]) == []


# ---------------------------------------------------------------------------
# 2. source_type filtering
# ---------------------------------------------------------------------------


def test_application_ignores_source_types_it_does_not_use():
    # metric / auth 이벤트를 섞어도 apache 결과만 나와야 한다.
    events = _apache_events_with_spike() + _metric_events_with_spike() + [_auth_event()]
    findings = run_application_analysis(events)
    assert findings
    assert all(f.detector in ("find_request_spike", "find_scan_pattern") for f in findings)


def test_server_ignores_apache_events():
    events = _apache_events_with_spike() + _metric_events_with_spike()
    findings = run_server_analysis(events)
    assert findings
    assert all(f.detector == "find_metric_anomaly" for f in findings)


def test_source_types_argument_narrows_which_detectors_run():
    events = _apache_events_with_spike()
    # apache_access를 제외하면 이 Skill이 쓸 이벤트가 없어 결과가 비어야 한다.
    assert run_application_analysis(events, source_types=["gaia_trace"]) == []
    # 지정해도 Skill이 쓰지 않는 source_type이면 아무 영향이 없다.
    assert run_application_analysis(events, source_types=["apache_access"])


def test_source_types_argument_does_not_add_unsupported_types():
    # SOURCE_TYPES에 없는 값을 요청해도 새로 분석되지 않는다.
    events = _metric_events_with_spike()
    assert run_application_analysis(events, source_types=["gaia_metric"]) == []
    assert "gaia_metric" not in APPLICATION_SOURCE_TYPES


# ---------------------------------------------------------------------------
# 3. 반환값이 Finding인지
# ---------------------------------------------------------------------------


def test_all_returned_values_are_findings_with_required_fields():
    findings = run_application_analysis(_apache_events_with_spike())
    assert findings
    for finding in findings:
        assert isinstance(finding, Finding)
        assert finding.finding_id
        assert finding.dataset
        assert finding.category
        assert finding.finding_type
        assert finding.start_time is not None
        assert finding.end_time is not None
        assert finding.severity in ("low", "medium", "high", "critical")
        assert finding.summary
        assert finding.detector
        assert isinstance(finding.metrics, dict)
        assert isinstance(finding.evidence, list)
        assert isinstance(finding.entities, dict)


# ---------------------------------------------------------------------------
# 4. dataset provenance
# ---------------------------------------------------------------------------


def test_dataset_argument_filters_input_and_does_not_overwrite_provenance():
    # dataset 인자는 입력 이벤트를 고르는 용도다. Finding.dataset은 detector가 정한 값.
    findings = run_server_analysis(_metric_events_with_spike(), dataset="gaia")
    assert findings
    assert all(f.dataset == "gaia" for f in findings)

    # 입력 이벤트의 dataset과 다른 값을 주면 아무 이벤트도 남지 않는다.
    assert run_server_analysis(_metric_events_with_spike(), dataset="russellmitchell") == []


def test_mixed_dataset_events_do_not_mix_finding_provenance():
    events = _apache_events_with_spike() + _metric_events_with_spike()
    app_findings = run_application_analysis(events)
    server_findings = run_server_analysis(events)
    assert all(f.dataset == "russellmitchell" for f in app_findings)
    assert all(f.dataset == "gaia" for f in server_findings)


# ---------------------------------------------------------------------------
# 5. wrapper가 detector 결과를 임의로 변경하지 않는지
# ---------------------------------------------------------------------------


def _fingerprint(finding: Finding):
    return (
        finding.finding_id,
        finding.dataset,
        finding.category,
        finding.finding_type,
        finding.start_time,
        finding.end_time,
        finding.host,
        finding.service,
        finding.severity,
        finding.summary,
        tuple(sorted(finding.metrics.items(), key=lambda kv: kv[0])),
        tuple((e.event_id, e.line_number) for e in finding.evidence),
        tuple(sorted((k, tuple(v)) for k, v in finding.entities.items())),
        finding.detector,
    )


def test_application_wrapper_result_is_identical_to_direct_detector_calls():
    events = _apache_events_with_spike()
    direct = find_request_spike(events) + find_scan_pattern(events)
    through_wrapper = run_application_analysis(events)
    assert [_fingerprint(f) for f in through_wrapper] == [_fingerprint(f) for f in direct]


def test_server_wrapper_result_is_identical_to_direct_detector_call():
    events = _metric_events_with_spike()
    direct = find_metric_anomaly(events)
    through_wrapper = run_server_analysis(events)
    assert [_fingerprint(f) for f in through_wrapper] == [_fingerprint(f) for f in direct]


def test_network_wrapper_result_is_a_subset_of_direct_detector_call():
    events = _network_metric_events()
    direct = find_metric_anomaly(events)
    through_wrapper = run_network_analysis(events)
    assert through_wrapper  # network Finding이 실제로 나온다
    direct_prints = [_fingerprint(f) for f in direct]
    for finding in through_wrapper:
        assert _fingerprint(finding) in direct_prints  # 변경 없이 골라낸 것


# ---------------------------------------------------------------------------
# 6. 입력 순서가 달라도 deterministic
# ---------------------------------------------------------------------------


def test_reversed_input_order_yields_same_findings():
    events = _apache_events_with_spike()
    forward = run_application_analysis(events)
    reverse = run_application_analysis(list(reversed(events)))
    assert sorted(_fingerprint(f) for f in forward) == sorted(_fingerprint(f) for f in reverse)


def test_repeated_calls_yield_identical_results():
    events = _metric_events_with_spike()
    first = run_server_analysis(events)
    second = run_server_analysis(events)
    assert [_fingerprint(f) for f in first] == [_fingerprint(f) for f in second]


# ---------------------------------------------------------------------------
# 7. detector가 없는 Skill이 가짜 Finding을 반환하지 않는지
# ---------------------------------------------------------------------------


def test_authentication_skill_returns_no_findings_even_with_auth_events():
    assert IMPLEMENTED is False
    assert AUTHENTICATION_DETECTORS == ()
    assert run_authentication_analysis([_auth_event()]) == []
    # 다른 Skill과 같은 signature를 유지하지만 결과는 여전히 비어 있다.
    assert (
        run_authentication_analysis(
            [_auth_event()], dataset="russellmitchell", host="intranet_server"
        )
        == []
    )


def test_security_skill_declares_no_detectors():
    assert SECURITY_DETECTORS == ()


# ---------------------------------------------------------------------------
# Security Skill: selector 동작
# ---------------------------------------------------------------------------


def test_security_skill_selects_only_security_category_findings():
    findings = run_application_analysis(_apache_events_with_spike())
    security = run_security_analysis(findings)
    assert security
    assert all(f.category == "security" for f in security)
    assert {f.finding_type for f in security} == {"repeated_source_ip_scan"}
    # availability Finding은 제외됐다
    assert any(f.category == "availability" for f in findings)


def test_security_skill_returns_findings_unmodified_and_in_order():
    findings = run_application_analysis(_apache_events_with_spike())
    security = run_security_analysis(findings)
    expected = [f for f in findings if f.category == "security"]
    # 같은 객체를 그대로 돌려준다(복사·수정하지 않는다).
    assert [id(f) for f in security] == [id(f) for f in expected]
    assert [_fingerprint(f) for f in security] == [_fingerprint(f) for f in expected]


def test_security_skill_on_empty_and_non_security_input():
    assert run_security_analysis([]) == []
    non_security = [f for f in run_server_analysis(_metric_events_with_spike())]
    assert non_security  # resource Finding은 있지만
    assert run_security_analysis(non_security) == []  # 보안 Finding은 없다


def test_select_security_findings_matches_run_security_analysis():
    findings = run_application_analysis(_apache_events_with_spike())
    assert select_security_findings(findings) == run_security_analysis(findings)


# ---------------------------------------------------------------------------
# Network Skill: category 선별 동작
# ---------------------------------------------------------------------------


def test_network_skill_returns_only_network_category():
    events = _network_metric_events() + _metric_events_with_spike()
    findings = run_network_analysis(events)
    assert findings
    assert all(f.category == "network" for f in findings)
    assert {f.finding_type for f in findings} == {"network_usage_anomaly"}


def test_network_skill_excludes_cpu_findings():
    # CPU metric만 주면 network Finding이 없어야 한다.
    assert run_network_analysis(_metric_events_with_spike()) == []


def test_select_network_findings_reuses_existing_findings():
    events = _network_metric_events() + _metric_events_with_spike()
    metric_findings = run_server_analysis(events)
    # detector를 다시 돌린 결과와 이미 만든 Finding을 선별한 결과가 같아야 한다.
    assert [_fingerprint(f) for f in select_network_findings(metric_findings)] == [
        _fingerprint(f) for f in run_network_analysis(events)
    ]


# ---------------------------------------------------------------------------
# 입력 범위 지정 (host / service / 기간)
# ---------------------------------------------------------------------------


def test_host_filter_limits_analysis_input():
    events = _apache_events_with_spike(host="webserver") + _apache_events_with_spike(
        host="intranet_server"
    )
    findings = run_application_analysis(events, host="webserver")
    assert findings
    hosts = {f.host for f in findings if f.host is not None}
    assert hosts == {"webserver"}


def test_service_filter_matches_gaia_service_name():
    events = _metric_events_with_spike(host="system") + _network_metric_events(host="dbservice1")
    findings = run_server_analysis(events, service="dbservice1")
    assert findings
    assert {f.service for f in findings} == {"dbservice1"}


def test_time_range_narrows_input_and_recomputes_baseline():
    events = _apache_events_with_spike()
    full = run_application_analysis(events)
    assert any(f.finding_type == "request_spike" for f in full)

    # 급증 구간을 잘라내면 그 Finding은 만들어지지 않는다(입력 범위 지정의 결과).
    cutoff = RM_T0 + timedelta(seconds=60 * (_NORMAL_WINDOWS - 1))
    narrowed = run_application_analysis(events, end_time=cutoff)
    assert not any(f.finding_type == "request_spike" for f in narrowed)


def test_time_range_excludes_events_without_timestamp():
    events = _apache_events_with_spike()
    no_timestamp = _access_event(
        event_id="nots", host="webserver", timestamp=None, src_ip="10.0.0.9"
    )
    with_none = events + [no_timestamp]
    # 기간을 지정하면 timestamp 없는 이벤트는 제외되므로 결과가 달라지지 않는다.
    bounded = run_application_analysis(
        with_none, start_time=RM_T0, end_time=RM_T0 + timedelta(days=1)
    )
    baseline = run_application_analysis(events, start_time=RM_T0, end_time=RM_T0 + timedelta(days=1))
    assert [_fingerprint(f) for f in bounded] == [_fingerprint(f) for f in baseline]
