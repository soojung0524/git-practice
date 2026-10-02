from datetime import datetime, timedelta, timezone

from src.models import NormalizedEvent
from src.skills.gaia_metric_anomaly import SUPPORTED_METRICS, find_metric_anomaly

T0 = datetime(2021, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
_SAMPLE_INTERVAL = timedelta(seconds=30)
_MIN_SAMPLES = 30
# p99 baseline이 스파이크 표본 자신에게 오염되지 않으려면(가장 큰 값 몇 개가 상위
# 1%에 들어가지 않으려면) baseline 표본 수가 충분히 커야 한다. 스파이크 3건을 섞어도
# 상위 1%(n_total*0.01) 안에 스파이크가 들어가지 않도록 넉넉히 600건을 쓴다.
_BASELINE_N = 600


def _metric_event(*, event_id, host, metric_name, value, timestamp) -> NormalizedEvent:
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
        extra={"value": value, "metric_name": metric_name, "metric_category": metric_name.split("_")[0]},
    )


def _baseline_samples(host, metric_name, value, n=_BASELINE_N):
    return [
        _metric_event(event_id=f"b{i}", host=host, metric_name=metric_name, value=value, timestamp=T0 + i * _SAMPLE_INTERVAL)
        for i in range(n)
    ]


def test_find_metric_anomaly_no_finding_on_flat_normal_series():
    events = _baseline_samples("system", "system_cpu_total_norm_pct", 0.5)
    assert find_metric_anomaly(events) == []


def test_find_metric_anomaly_ignores_unsupported_metric_even_with_huge_spike():
    host, metric = "dbservice1", "docker_cpu_core_5_norm_pct"  # 실제로 100% 0이라 제외한 metric
    events = _baseline_samples(host, metric, 0.0)
    spike_start = T0 + _BASELINE_N * _SAMPLE_INTERVAL
    events += [
        _metric_event(event_id=f"s{i}", host=host, metric_name=metric, value=1.0, timestamp=spike_start + i * _SAMPLE_INTERVAL)
        for i in range(3)
    ]
    assert metric not in SUPPORTED_METRICS
    assert find_metric_anomaly(events) == []


def test_find_metric_anomaly_detects_spike_with_utilization_ceiling_severity():
    host, metric = "system", "system_cpu_total_norm_pct"
    events = _baseline_samples(host, metric, 0.4)
    spike_start = T0 + _BASELINE_N * _SAMPLE_INTERVAL
    events += [
        _metric_event(event_id=f"s{i}", host=host, metric_name=metric, value=0.90, timestamp=spike_start + i * _SAMPLE_INTERVAL)
        for i in range(3)
    ]

    findings = find_metric_anomaly(events)
    assert len(findings) == 1
    finding = findings[0]

    assert finding.dataset == "gaia"
    assert finding.category == "resource"
    assert finding.finding_type == "cpu_usage_anomaly"
    assert finding.service == host
    assert finding.host is None
    assert finding.detector == "find_metric_anomaly"
    assert finding.entities == {"service": [host]}
    assert finding.metrics["metric_name"] == metric
    assert finding.metrics["baseline_p99"] == 0.4
    assert finding.metrics["peak_value"] == 0.90
    assert finding.metrics["ratio"] == 0.90 / 0.4
    # utilization ceiling 지표: 0.80<=peak<0.95 -> medium (ratio가 아니라 절대값 기준).
    assert finding.severity == "medium"


def test_find_metric_anomaly_high_severity_when_near_full_utilization():
    host, metric = "system", "system_filesystem_used_pct"
    events = _baseline_samples(host, metric, 0.04)
    spike_start = T0 + _BASELINE_N * _SAMPLE_INTERVAL
    events += [
        _metric_event(event_id=f"s{i}", host=host, metric_name=metric, value=0.97, timestamp=spike_start + i * _SAMPLE_INTERVAL)
        for i in range(3)
    ]
    findings = find_metric_anomaly(events)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_find_metric_anomaly_stays_conservative_without_capacity_reference():
    # docker_memory_stats_active_anon은 절대 상한(총 메모리 용량)을 데이터에서 알 수
    # 없으므로, ratio가 아무리 커도 severity는 low로 보수적으로 유지되어야 한다.
    host, metric = "dbservice2", "docker_memory_stats_active_anon"
    events = _baseline_samples(host, metric, 1_000_000.0)
    spike_start = T0 + _BASELINE_N * _SAMPLE_INTERVAL
    events += [
        _metric_event(
            event_id=f"s{i}", host=host, metric_name=metric, value=100_000_000.0, timestamp=spike_start + i * _SAMPLE_INTERVAL
        )
        for i in range(3)
    ]
    findings = find_metric_anomaly(events)
    assert len(findings) == 1
    assert findings[0].metrics["ratio"] == 100.0
    assert findings[0].severity == "low"


def test_find_metric_anomaly_requires_minimum_sample_count():
    host, metric = "system", "system_cpu_total_norm_pct"
    events = _baseline_samples(host, metric, 0.4, n=_MIN_SAMPLES - 5)
    events += [
        _metric_event(
            event_id="s0", host=host, metric_name=metric, value=0.99, timestamp=T0 + (_MIN_SAMPLES - 5) * _SAMPLE_INTERVAL
        )
    ]
    assert find_metric_anomaly(events) == []


def test_find_metric_anomaly_evidence_traceable_and_deterministic():
    host, metric = "system", "system_cpu_total_norm_pct"
    events = _baseline_samples(host, metric, 0.4)
    spike_start = T0 + _BASELINE_N * _SAMPLE_INTERVAL
    events += [
        _metric_event(event_id=f"s{i}", host=host, metric_name=metric, value=0.90, timestamp=spike_start + i * _SAMPLE_INTERVAL)
        for i in range(3)
    ]

    first = find_metric_anomaly(events)
    second = find_metric_anomaly(list(reversed(events)))
    assert [f.finding_id for f in first] == [f.finding_id for f in second]
    assert len(first[0].evidence) == first[0].metrics["evidence_count"] or len(first[0].evidence) <= 5
    for ev in first[0].evidence:
        assert ev.source_type == "gaia_metric"
        assert ev.event_id.startswith("s")
