from datetime import datetime, timedelta, timezone

from src.models import NormalizedEvent
from src.skills.gaia_trace_anomaly import find_latency_anomaly

T0 = datetime(2021, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
_SAMPLE_INTERVAL = timedelta(seconds=1)
_MIN_SAMPLES = 100
# find_metric_anomaly 테스트와 같은 이유로(자기 자신의 p99 baseline이 스파이크 표본에
# 오염되지 않도록) baseline 표본 수를 넉넉히 둔다.
_BASELINE_N = 600


def _trace_event(*, event_id, host, duration_seconds, timestamp) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        source_type="gaia_trace",
        host=host,
        source_path=f"trace/trace_table_{host}_2021-07.csv",
        line_number=1,
        timestamp=timestamp,
        raw="raw",
        dataset="gaia",
        event_type="gaia_trace_span",
        extra={"duration_seconds": duration_seconds, "status_code": 200},
    )


def _baseline_spans(host, duration_seconds, n=_BASELINE_N):
    return [
        _trace_event(event_id=f"b{i}", host=host, duration_seconds=duration_seconds, timestamp=T0 + i * _SAMPLE_INTERVAL)
        for i in range(n)
    ]


def test_find_latency_anomaly_no_finding_on_stable_latency():
    events = _baseline_spans("dbservice1", 0.2)
    assert find_latency_anomaly(events) == []


def test_find_latency_anomaly_medium_severity_for_moderate_absolute_duration():
    host = "dbservice1"
    events = _baseline_spans(host, 0.2)
    spike_start = T0 + _BASELINE_N * _SAMPLE_INTERVAL
    events += [
        _trace_event(event_id=f"s{i}", host=host, duration_seconds=10.0, timestamp=spike_start + i * _SAMPLE_INTERVAL)
        for i in range(3)
    ]

    findings = find_latency_anomaly(events)
    assert len(findings) == 1
    finding = findings[0]

    assert finding.dataset == "gaia"
    assert finding.category == "performance"
    assert finding.finding_type == "service_latency_spike"
    assert finding.service == host
    assert finding.host is None
    assert finding.detector == "find_latency_anomaly"
    assert finding.entities == {"service": [host]}
    assert finding.metrics["baseline_p99_seconds"] == 0.2
    assert finding.metrics["duration_seconds_peak"] == 10.0
    assert finding.metrics["ratio"] == 10.0 / 0.2
    # 절대 지속시간 5~30초 -> medium (ratio가 아니라 절대값 기준).
    assert finding.severity == "medium"


def test_find_latency_anomaly_high_severity_for_long_absolute_duration():
    host = "dbservice1"
    events = _baseline_spans(host, 0.2)
    spike_start = T0 + _BASELINE_N * _SAMPLE_INTERVAL
    events += [
        _trace_event(event_id=f"s{i}", host=host, duration_seconds=60.0, timestamp=spike_start + i * _SAMPLE_INTERVAL)
        for i in range(3)
    ]
    findings = find_latency_anomaly(events)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_find_latency_anomaly_boundary_ratio_below_threshold_is_not_flagged():
    host = "dbservice1"
    events = _baseline_spans(host, 1.0)
    # ratio = 1.5/1.0 = 1.5 < MIN_RATIO(2.0)
    events.append(
        _trace_event(event_id="s0", host=host, duration_seconds=1.5, timestamp=T0 + _BASELINE_N * _SAMPLE_INTERVAL)
    )
    assert find_latency_anomaly(events) == []


def test_find_latency_anomaly_requires_minimum_sample_count():
    host = "dbservice1"
    events = _baseline_spans(host, 0.2, n=_MIN_SAMPLES - 10)
    events.append(
        _trace_event(event_id="s0", host=host, duration_seconds=50.0, timestamp=T0 + (_MIN_SAMPLES - 10) * _SAMPLE_INTERVAL)
    )
    assert find_latency_anomaly(events) == []


def test_find_latency_anomaly_evidence_traceable_and_deterministic():
    host = "dbservice1"
    events = _baseline_spans(host, 0.2)
    spike_start = T0 + _BASELINE_N * _SAMPLE_INTERVAL
    events += [
        _trace_event(event_id=f"s{i}", host=host, duration_seconds=45.0, timestamp=spike_start + i * _SAMPLE_INTERVAL)
        for i in range(3)
    ]

    first = find_latency_anomaly(events)
    second = find_latency_anomaly(list(reversed(events)))
    assert [f.finding_id for f in first] == [f.finding_id for f in second]
    assert 1 <= len(first[0].evidence) <= 5
    for ev in first[0].evidence:
        assert ev.source_type == "gaia_trace"
        assert ev.event_id.startswith("s")
