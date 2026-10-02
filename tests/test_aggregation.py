from datetime import datetime, timedelta, timezone

from src.models import NormalizedEvent
from src.skills.aggregation import (
    ValueSample,
    cluster_by_time_gap,
    collect_values_by_group,
    compute_count_baseline,
    count_by_window,
    evidence_from_event,
    percentile,
    select_representative_evidence,
)

T0 = datetime(2022, 1, 21, 0, 0, 0, tzinfo=timezone.utc)


def _event(**overrides) -> NormalizedEvent:
    defaults = dict(
        event_id="ev:1",
        source_type="apache_access",
        host="webserver",
        source_path="gather/webserver/logs/apache2/access.log",
        line_number=1,
        timestamp=T0,
        raw="raw",
        event_type="http_request",
        extra={},
    )
    defaults.update(overrides)
    return NormalizedEvent(**defaults)


# ---------------------------------------------------------------------------
# percentile
# ---------------------------------------------------------------------------


def test_percentile_matches_rank_based_method():
    values = list(range(1, 101))  # 1..100
    assert percentile(values, 0.5) == 51  # idx = int(100*0.5) = 50 -> values[50] == 51
    assert percentile(values, 0.99) == 100  # idx = 99 -> values[99] == 100
    assert percentile(values, 0.0) == 1


def test_percentile_empty_raises():
    try:
        percentile([], 0.5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


# ---------------------------------------------------------------------------
# count_by_window
# ---------------------------------------------------------------------------


def test_count_by_window_groups_by_key_and_window():
    events = [
        _event(event_id="1", host="a", timestamp=T0),
        _event(event_id="2", host="a", timestamp=T0 + timedelta(seconds=10)),
        _event(event_id="3", host="a", timestamp=T0 + timedelta(seconds=65)),  # next window
        _event(event_id="4", host="b", timestamp=T0),
    ]
    buckets = count_by_window(events, window_seconds=60, group_key=lambda e: e.host)

    assert len(buckets) == 3
    a_window0 = buckets[("a", T0)]
    assert a_window0.count == 2
    assert a_window0.window_end == T0 + timedelta(seconds=60)
    b_window0 = buckets[("b", T0)]
    assert b_window0.count == 1


def test_count_by_window_respects_predicate_and_ignores_missing_timestamp():
    events = [
        _event(event_id="1", source_type="apache_access", timestamp=T0),
        _event(event_id="2", source_type="apache_error", timestamp=T0),
        _event(event_id="3", source_type="apache_access", timestamp=None),
    ]
    buckets = count_by_window(
        events,
        window_seconds=60,
        group_key=lambda e: e.host,
        predicate=lambda e: e.source_type == "apache_access",
    )
    assert len(buckets) == 1
    only = next(iter(buckets.values()))
    assert only.count == 1


def test_count_by_window_value_fn_is_carried_through_untouched():
    events = [
        _event(event_id="1", timestamp=T0, extra={"status": 200}),
        _event(event_id="2", timestamp=T0, extra={"status": 500}),
    ]
    buckets = count_by_window(
        events,
        window_seconds=60,
        group_key=lambda e: e.host,
        value_fn=lambda e: 1.0 if e.extra.get("status") == 500 else 0.0,
    )
    bucket = next(iter(buckets.values()))
    error_fraction = sum(s.value for s in bucket.samples) / bucket.count
    assert error_fraction == 0.5


def test_count_by_window_value_sum_matches_all_matched_events_even_when_evidence_is_filtered():
    events = [
        _event(event_id=f"info{i}", timestamp=T0, extra={"status": 200}) for i in range(50)
    ] + [
        _event(event_id="err1", timestamp=T0, extra={"status": 500}),
    ]
    buckets = count_by_window(
        events,
        window_seconds=60,
        group_key=lambda e: e.host,
        value_fn=lambda e: 1.0 if e.extra.get("status") == 500 else 0.0,
        collect_evidence_for=lambda e: e.extra.get("status") == 500,
    )
    bucket = next(iter(buckets.values()))
    # count/value_sum은 evidence 필터와 무관하게 매칭된 이벤트 51건 전체를 반영해야 한다.
    assert bucket.count == 51
    assert bucket.value_sum == 1.0
    # samples는 evidence 후보(500만) 딱 1건만 담겨야 한다 - 나머지 50건은 메모리에 안 남는다.
    assert len(bucket.samples) == 1
    assert bucket.samples[0].evidence.event_id == "err1"


# ---------------------------------------------------------------------------
# compute_count_baseline
# ---------------------------------------------------------------------------


def test_compute_count_baseline_pads_implicit_zero_windows():
    # 관측된(0건 초과) 창은 딱 1개(count=100)뿐이고, 나머지 99개 창은 0건이라고 가정.
    baseline = compute_count_baseline([100], total_windows=100, percentile_value=0.99, min_observations=10)
    # idx = int(100*0.99) = 99 -> 마지막 위치. n_zero = 99이므로 idx(99) == n_zero(99)는
    # False(99>=99 아님 99==99) -> idx(99) < n_zero(99) 는 거짓 -> ordered[99-99]=ordered[0]=100
    assert baseline == 100.0


def test_compute_count_baseline_returns_none_when_insufficient_observations():
    assert compute_count_baseline([5, 6, 7], total_windows=5, percentile_value=0.99, min_observations=30) is None


def test_compute_count_baseline_rejects_invalid_total_windows():
    try:
        compute_count_baseline([1, 2, 3], total_windows=1, min_observations=1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


# ---------------------------------------------------------------------------
# collect_values_by_group
# ---------------------------------------------------------------------------


def test_collect_values_by_group_skips_none_values_and_missing_timestamp():
    events = [
        _event(event_id="1", host="dbservice1", timestamp=T0, extra={"value": 1.0}),
        _event(event_id="2", host="dbservice1", timestamp=T0, extra={}),  # value_fn -> None
        _event(event_id="3", host="dbservice1", timestamp=None, extra={"value": 2.0}),
        _event(event_id="4", host="dbservice2", timestamp=T0, extra={"value": 3.0}),
    ]
    groups = collect_values_by_group(
        events, group_key=lambda e: e.host, value_fn=lambda e: e.extra.get("value")
    )
    assert list(groups.keys()) == ["dbservice1", "dbservice2"]
    # values는 percentile 계산용으로 매칭된 값 전체를 정확히 담는다.
    assert list(groups["dbservice1"].values) == [1.0]
    assert list(groups["dbservice2"].values) == [3.0]
    # 표본이 max_candidates_per_group보다 훨씬 적으므로 evidence_candidates에도
    # 그대로 전부 담긴다.
    assert len(groups["dbservice1"].evidence_candidates) == 1
    assert groups["dbservice1"].evidence_candidates[0].value == 1.0


def test_collect_values_by_group_caps_evidence_candidates_but_keeps_all_values():
    # max_candidates_per_group(2)보다 많은 값(5개)을 넣어도 values에는 전부 담기고,
    # evidence_candidates에는 값이 큰 순으로 딱 2개만 남아야 한다.
    events = [
        _event(event_id=f"e{i}", host="h", timestamp=T0 + timedelta(seconds=i), extra={"value": float(i)})
        for i in range(5)  # values: 0.0, 1.0, 2.0, 3.0, 4.0
    ]
    groups = collect_values_by_group(
        events,
        group_key=lambda e: e.host,
        value_fn=lambda e: e.extra.get("value"),
        max_candidates_per_group=2,
    )
    group = groups["h"]
    assert sorted(group.values) == [0.0, 1.0, 2.0, 3.0, 4.0]
    assert len(group.evidence_candidates) == 2
    assert sorted(s.value for s in group.evidence_candidates) == [3.0, 4.0]


def test_collect_values_by_group_evidence_candidates_are_deterministic_regardless_of_order():
    events = [
        _event(event_id=f"e{i}", host="h", timestamp=T0 + timedelta(seconds=i), extra={"value": float(i)})
        for i in range(20)
    ]
    forward = collect_values_by_group(
        events, group_key=lambda e: e.host, value_fn=lambda e: e.extra.get("value"), max_candidates_per_group=5
    )
    backward = collect_values_by_group(
        list(reversed(events)),
        group_key=lambda e: e.host,
        value_fn=lambda e: e.extra.get("value"),
        max_candidates_per_group=5,
    )
    forward_ids = sorted(s.evidence.event_id for s in forward["h"].evidence_candidates)
    backward_ids = sorted(s.evidence.event_id for s in backward["h"].evidence_candidates)
    assert forward_ids == backward_ids == ["e15", "e16", "e17", "e18", "e19"]


# ---------------------------------------------------------------------------
# cluster_by_time_gap
# ---------------------------------------------------------------------------


def _sample(value: float, offset_seconds: float, event_id: str = "e") -> ValueSample:
    ev = _event(event_id=event_id, timestamp=T0 + timedelta(seconds=offset_seconds))
    return ValueSample(value=value, timestamp=ev.timestamp, evidence=evidence_from_event(ev))


def test_cluster_by_time_gap_splits_on_large_gap():
    samples = [
        _sample(1, 0, "a"),
        _sample(1, 10, "b"),  # gap=10 <= 30 -> same episode
        _sample(1, 500, "c"),  # gap=490 > 30 -> new episode
    ]
    episodes = cluster_by_time_gap(samples, max_gap_seconds=30)
    assert len(episodes) == 2
    assert [s.evidence.event_id for s in episodes[0]] == ["a", "b"]
    assert [s.evidence.event_id for s in episodes[1]] == ["c"]


def test_cluster_by_time_gap_empty_input():
    assert cluster_by_time_gap([], max_gap_seconds=30) == []


# ---------------------------------------------------------------------------
# select_representative_evidence
# ---------------------------------------------------------------------------


def test_select_representative_evidence_includes_first_peak_last_and_is_capped():
    samples = [_sample(value=i, offset_seconds=i, event_id=f"e{i}") for i in range(20)]
    picked = select_representative_evidence(samples, max_count=5)
    assert len(picked) == 5
    ids = [e.event_id for e in picked]
    assert "e0" in ids  # first
    assert "e19" in ids  # last (and also peak, value increases with offset)
    # 시간순으로 정렬되어 있어야 한다.
    assert [e.timestamp for e in picked] == sorted(e.timestamp for e in picked)


def test_select_representative_evidence_is_deterministic():
    samples = [_sample(value=i % 3, offset_seconds=i, event_id=f"e{i}") for i in range(10)]
    picked1 = select_representative_evidence(samples, max_count=4)
    picked2 = select_representative_evidence(list(reversed(samples)), max_count=4)
    assert [e.event_id for e in picked1] == [e.event_id for e in picked2]


def test_select_representative_evidence_empty_input():
    assert select_representative_evidence([]) == []
