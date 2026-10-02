from datetime import datetime, timedelta, timezone

from src.models import NormalizedEvent
from src.skills.gaia_log_anomaly import find_log_error_spike

T0 = datetime(2021, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
_WINDOW_SECONDS = 60
_MIN_WINDOWS = 100
# baseline p99가 스파이크 창 자신에게 오염되지 않도록(자세한 이유는
# test_gaia_metric_anomaly.py 참고) 충분히 많은 정상 창을 쓴다.
_BASELINE_WINDOWS = 300
_EVENTS_PER_WINDOW = 10
_ERRORS_PER_NORMAL_WINDOW = 1  # 정상 창의 error rate = 0.1


def _log_event(*, event_id, host, timestamp, level) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        source_type="gaia_log",
        host=host,
        source_path=f"business/business_table_{host}_2021-07.csv",
        line_number=1,
        timestamp=timestamp,
        raw="raw",
        dataset="gaia",
        event_type="gaia_log_entry",
        extra={"level": level},
    )


def _window(host, window_index, *, error_count, total=_EVENTS_PER_WINDOW, prefix="w"):
    window_start = T0 + timedelta(seconds=_WINDOW_SECONDS * window_index)
    events = []
    for i in range(total):
        level = "ERROR" if i < error_count else "INFO"
        events.append(
            _log_event(
                event_id=f"{prefix}{window_index}-{i}",
                host=host,
                timestamp=window_start + timedelta(seconds=i * 5),
                level=level,
            )
        )
    return events


def _baseline_windows(host, n=_BASELINE_WINDOWS):
    events = []
    for w in range(n):
        events += _window(host, w, error_count=_ERRORS_PER_NORMAL_WINDOW, prefix="b")
    return events


def test_find_log_error_spike_no_finding_on_stable_error_rate():
    events = _baseline_windows("webservice1")
    assert find_log_error_spike(events) == []


def test_find_log_error_spike_detects_elevated_error_rate_with_medium_severity():
    host = "webservice1"
    events = _baseline_windows(host)
    # 정상 창 error_rate=0.1 (baseline p99=0.1). 스파이크 창은 error_rate=0.3 -> ratio=3.
    events += _window(host, _BASELINE_WINDOWS, error_count=3, prefix="s")

    findings = find_log_error_spike(events)
    assert len(findings) == 1
    finding = findings[0]

    assert finding.dataset == "gaia"
    assert finding.category == "error"
    assert finding.finding_type == "log_error_rate_spike"
    assert finding.service == host
    assert finding.host is None
    assert finding.detector == "find_log_error_spike"
    assert finding.entities == {"service": [host]}
    assert finding.metrics["baseline_p99_error_rate"] == _ERRORS_PER_NORMAL_WINDOW / _EVENTS_PER_WINDOW
    assert abs(finding.metrics["error_rate_peak"] - 0.3) < 1e-9
    assert finding.metrics["error_count"] == 3
    assert finding.metrics["total_log_count"] == _EVENTS_PER_WINDOW
    # 절대 error rate 0.2~0.5 -> medium (ratio가 아니라 절대값 기준).
    assert finding.severity == "medium"


def test_find_log_error_spike_high_severity_when_majority_of_logs_are_errors():
    host = "webservice1"
    events = _baseline_windows(host)
    events += _window(host, _BASELINE_WINDOWS, error_count=8, prefix="s")  # error_rate=0.8

    findings = find_log_error_spike(events)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_find_log_error_spike_boundary_ratio_below_threshold_is_not_flagged():
    host = "webservice1"
    events = _baseline_windows(host)
    # ratio = 0.19/0.1 < 2.0 (MIN_RATIO) -> Finding이 생기면 안 된다. 정수 error_count로
    # 정확히 0.19를 만들 수 없으니 그보다 더 확실히 낮은 0.1(=baseline과 동일)로 둔다.
    events += _window(host, _BASELINE_WINDOWS, error_count=1, prefix="s")
    assert find_log_error_spike(events) == []


def test_find_log_error_spike_requires_minimum_window_count():
    host = "webservice1"
    events = _baseline_windows(host, n=_MIN_WINDOWS - 10)
    events += _window(host, _MIN_WINDOWS - 10, error_count=8, prefix="s")
    assert find_log_error_spike(events) == []


def test_find_log_error_spike_ignores_unstructured_entries():
    host = "webservice1"
    events = _baseline_windows(host)
    # level 정보가 없는 gaia_log_unstructured 이벤트는 대상에서 제외되어야 한다.
    events.append(
        NormalizedEvent(
            event_id="u1",
            source_type="gaia_log",
            host=host,
            source_path="business/business_table_webservice1_2021-07.csv",
            line_number=999999,
            timestamp=T0 + timedelta(seconds=_WINDOW_SECONDS * _BASELINE_WINDOWS),
            raw="raw",
            dataset="gaia",
            event_type="gaia_log_unstructured",
            extra={},
        )
    )
    assert find_log_error_spike(events) == []


def test_find_log_error_spike_evidence_traceable_and_deterministic():
    host = "webservice1"
    events = _baseline_windows(host)
    events += _window(host, _BASELINE_WINDOWS, error_count=8, prefix="s")

    first = find_log_error_spike(events)
    second = find_log_error_spike(list(reversed(events)))
    assert [f.finding_id for f in first] == [f.finding_id for f in second]
    assert 1 <= len(first[0].evidence) <= 5
    for ev in first[0].evidence:
        assert ev.source_type == "gaia_log"
        assert ev.event_id.startswith("s")
