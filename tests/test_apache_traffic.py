from datetime import datetime, timedelta, timezone

from src.models import NormalizedEvent
from src.skills.apache_traffic import find_request_spike, find_scan_pattern

T0 = datetime(2022, 1, 21, 0, 0, 0, tzinfo=timezone.utc)

_NORMAL_WINDOWS = 150
_NORMAL_PER_WINDOW = 4


def _access_event(*, event_id, host, timestamp, src_ip, status=200, path="/index.html") -> NormalizedEvent:
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


def _baseline_traffic(host="webserver") -> list[NormalizedEvent]:
    events = []
    eid = 0
    for w in range(_NORMAL_WINDOWS):
        window_start = T0 + timedelta(seconds=60 * w)
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
    return events


# ---------------------------------------------------------------------------
# find_request_spike
# ---------------------------------------------------------------------------


def test_find_request_spike_no_finding_on_normal_traffic():
    events = _baseline_traffic()
    findings = find_request_spike(events)
    assert findings == []


def test_find_request_spike_detects_clear_spike_with_low_severity_when_no_errors():
    events = _baseline_traffic()
    spike_window_start = T0 + timedelta(seconds=60 * _NORMAL_WINDOWS)
    events += [
        _access_event(
            event_id=f"s{i}", host="webserver", timestamp=spike_window_start + timedelta(seconds=i), src_ip="10.0.0.1"
        )
        for i in range(40)
    ]

    findings = find_request_spike(events)
    assert len(findings) == 1
    finding = findings[0]

    # --- schema ---
    assert finding.dataset == "russellmitchell"
    assert finding.category == "availability"
    assert finding.finding_type == "request_spike"
    assert finding.host == "webserver"
    assert finding.detector == "find_request_spike"
    assert finding.severity in ("low", "medium", "high", "critical")

    # --- metrics: 정상 트래픽 없이 스파이크만 있었으므로 error 비율이 0 -> low ---
    assert finding.severity == "low"
    assert finding.metrics["request_count"] == 40
    assert finding.metrics["baseline_p99"] == _NORMAL_PER_WINDOW
    assert finding.metrics["ratio"] == 40 / _NORMAL_PER_WINDOW
    assert finding.metrics["error_status_fraction"] == 0.0

    # --- evidence traceability ---
    assert 1 <= len(finding.evidence) <= 5
    for ev in finding.evidence:
        assert ev.source_type == "apache_access"
        assert ev.event_id.startswith("s")


def test_find_request_spike_severity_rises_with_error_fraction_not_just_ratio():
    events = _baseline_traffic()
    spike_window_start = T0 + timedelta(seconds=60 * _NORMAL_WINDOWS)
    # 같은 ratio(40/4=10배)라도 이번엔 절반이 4xx/5xx.
    events += [
        _access_event(
            event_id=f"s{i}",
            host="webserver",
            timestamp=spike_window_start + timedelta(seconds=i),
            src_ip="10.0.0.1",
            status=500 if i % 2 == 0 else 200,
        )
        for i in range(40)
    ]

    findings = find_request_spike(events)
    assert len(findings) == 1
    assert findings[0].metrics["ratio"] == findings[0].metrics["request_count"] / findings[0].metrics["baseline_p99"]
    assert findings[0].metrics["error_status_fraction"] == 0.5
    assert findings[0].severity == "high"  # >= 0.5 -> high


def test_find_request_spike_boundary_just_below_ratio_threshold_is_not_flagged():
    events = _baseline_traffic()
    spike_window_start = T0 + timedelta(seconds=60 * _NORMAL_WINDOWS)
    # ratio = 7/4 = 1.75 < MIN_RATIO(2.0) -> Finding이 생기면 안 된다.
    events += [
        _access_event(
            event_id=f"s{i}", host="webserver", timestamp=spike_window_start + timedelta(seconds=i), src_ip="10.0.0.1"
        )
        for i in range(7)
    ]
    assert find_request_spike(events) == []


def test_find_request_spike_preserves_dataset_provenance():
    events = _baseline_traffic()
    for e in events:
        e.dataset = "russellmitchell"
    spike_window_start = T0 + timedelta(seconds=60 * _NORMAL_WINDOWS)
    events += [
        _access_event(
            event_id=f"s{i}", host="webserver", timestamp=spike_window_start + timedelta(seconds=i), src_ip="10.0.0.1"
        )
        for i in range(40)
    ]
    findings = find_request_spike(events, dataset="russellmitchell")
    assert all(f.dataset == "russellmitchell" for f in findings)


def test_find_request_spike_is_deterministic():
    events = _baseline_traffic()
    spike_window_start = T0 + timedelta(seconds=60 * _NORMAL_WINDOWS)
    events += [
        _access_event(
            event_id=f"s{i}", host="webserver", timestamp=spike_window_start + timedelta(seconds=i), src_ip="10.0.0.1"
        )
        for i in range(40)
    ]
    first = find_request_spike(events)
    second = find_request_spike(list(reversed(events)))
    assert [f.finding_id for f in first] == [f.finding_id for f in second]
    assert [[e.event_id for e in f.evidence] for f in first] == [[e.event_id for e in f.evidence] for f in second]


# ---------------------------------------------------------------------------
# find_scan_pattern
# ---------------------------------------------------------------------------


def _ip_traffic(ip: str, *, total: int, distinct_paths: int, error_count: int, start_offset: int) -> list[NormalizedEvent]:
    events = []
    for i in range(total):
        is_404 = i < error_count
        path = f"/p{i % distinct_paths}.html"
        events.append(
            _access_event(
                event_id=f"{ip}-{i}",
                host="webserver",
                timestamp=T0 + timedelta(seconds=start_offset + i),
                src_ip=ip,
                status=404 if is_404 else 200,
                path=path,
            )
        )
    return events


def test_find_scan_pattern_no_finding_when_ips_look_similar():
    events = []
    for idx, ip in enumerate(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]):
        events += _ip_traffic(ip, total=20, distinct_paths=5, error_count=0, start_offset=idx * 1000)
    assert find_scan_pattern(events) == []


def test_find_scan_pattern_flags_outlier_ip_with_high_fanout_and_errors():
    events = []
    events += _ip_traffic("10.0.0.1", total=20, distinct_paths=5, error_count=0, start_offset=0)
    events += _ip_traffic("10.0.0.2", total=20, distinct_paths=6, error_count=0, start_offset=1000)
    events += _ip_traffic("10.0.0.3", total=20, distinct_paths=4, error_count=1, start_offset=2000)
    # median_distinct=6, median_error_rate=0.05
    events += _ip_traffic("9.9.9.9", total=20, distinct_paths=20, error_count=10, start_offset=3000)

    findings = find_scan_pattern(events)
    assert len(findings) == 1
    finding = findings[0]

    assert finding.category == "security"
    assert finding.finding_type == "repeated_source_ip_scan"
    assert finding.detector == "find_scan_pattern"
    assert finding.entities == {"ip": ["9.9.9.9"]}
    assert finding.metrics["distinct_paths"] == 20
    assert finding.metrics["median_distinct_paths"] == 6
    assert finding.metrics["error_404_count"] == 10
    assert finding.severity in ("medium", "high")
    for ev in finding.evidence:
        assert ev.source_type == "apache_access"


def test_find_scan_pattern_requires_minimum_ip_count():
    events = []
    events += _ip_traffic("10.0.0.1", total=20, distinct_paths=5, error_count=0, start_offset=0)
    events += _ip_traffic("9.9.9.9", total=20, distinct_paths=20, error_count=10, start_offset=1000)
    # IP가 2개뿐 -> MIN_IPS(3) 미만이라 population median을 신뢰할 수 없어 빈 리스트.
    assert find_scan_pattern(events) == []


def test_find_scan_pattern_ignores_low_volume_ips():
    events = []
    events += _ip_traffic("10.0.0.1", total=20, distinct_paths=5, error_count=0, start_offset=0)
    events += _ip_traffic("10.0.0.2", total=20, distinct_paths=6, error_count=0, start_offset=1000)
    events += _ip_traffic("10.0.0.3", total=20, distinct_paths=4, error_count=0, start_offset=2000)
    # 요청 2건짜리 IP는 distinct_paths=2라 median 대비 비율이 크게 보일 수 있지만
    # MIN_REQUESTS(10) 미만이라 애초에 평가 대상에서 빠져야 한다.
    events += _ip_traffic("1.2.3.4", total=2, distinct_paths=2, error_count=0, start_offset=3000)

    findings = find_scan_pattern(events)
    assert all(f.entities["ip"] != ["1.2.3.4"] for f in findings)


def test_find_scan_pattern_is_deterministic():
    events = []
    events += _ip_traffic("10.0.0.1", total=20, distinct_paths=5, error_count=0, start_offset=0)
    events += _ip_traffic("10.0.0.2", total=20, distinct_paths=6, error_count=0, start_offset=1000)
    events += _ip_traffic("10.0.0.3", total=20, distinct_paths=4, error_count=1, start_offset=2000)
    events += _ip_traffic("9.9.9.9", total=20, distinct_paths=20, error_count=10, start_offset=3000)

    first = find_scan_pattern(events)
    second = find_scan_pattern(list(reversed(events)))
    assert [f.finding_id for f in first] == [f.finding_id for f in second]
