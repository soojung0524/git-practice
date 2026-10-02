"""상대시간 정렬 테스트.

원본 timestamp 불변, 상대초 보존, scenario/real mode 경계 규칙을 검증한다.
"""

import re
from datetime import timedelta
from pathlib import Path

import pytest

from scenario import (
    MODE_REAL,
    MODE_SCENARIO,
    RELATIVE_SECONDS_KEY,
    SCENARIO_ID_KEY,
    WINDOW_START_KEY,
    AlignmentError,
    AnalysisWindow,
    align_event,
    align_events,
    correlation_boundary_key,
    get_relative_seconds,
    get_scenario_id,
    is_aligned,
    long_span_basis_seconds,
    utc,
)
from src.models import NormalizedEvent

PROJECT_ROOT = Path(__file__).resolve().parent.parent

T0 = utc(2022, 1, 20)
WINDOW_END = utc(2022, 1, 26)


def _event(*, event_id="e1", timestamp=None, dataset="russellmitchell", extra=None):
    return NormalizedEvent(
        event_id=event_id,
        source_type="apache_access",
        host="webserver",
        source_path="gather/webserver/logs/apache2/access.log",
        line_number=1,
        timestamp=timestamp,
        raw="raw",
        dataset=dataset,
        extra={} if extra is None else dict(extra),
    )


REAL_WINDOW = AnalysisWindow(window_start=T0, window_end=WINDOW_END)
SCENARIO_WINDOW = AnalysisWindow(
    window_start=T0, window_end=WINDOW_END, scenario_id="scenario-001"
)


# ---------------------------------------------------------------------------
# AnalysisWindow
# ---------------------------------------------------------------------------


def test_mode_is_real_without_scenario_id():
    assert REAL_WINDOW.mode == MODE_REAL
    assert REAL_WINDOW.scenario_id is None


def test_mode_is_scenario_with_scenario_id():
    assert SCENARIO_WINDOW.mode == MODE_SCENARIO


def test_window_requires_timezone():
    from datetime import datetime

    with pytest.raises(AlignmentError):
        AnalysisWindow(window_start=datetime(2022, 1, 20))


def test_window_end_must_not_precede_start():
    with pytest.raises(AlignmentError):
        AnalysisWindow(window_start=WINDOW_END, window_end=T0)


def test_empty_scenario_id_is_rejected():
    # 묶지 않으려면 None을 써야 한다. 빈 문자열로 모호하게 두지 않는다.
    with pytest.raises(AlignmentError):
        AnalysisWindow(window_start=T0, scenario_id="  ")


def test_duration_seconds():
    assert SCENARIO_WINDOW.duration_seconds == 6 * 86400
    assert AnalysisWindow(window_start=T0).duration_seconds is None


# ---------------------------------------------------------------------------
# 상대시간 계산
# ---------------------------------------------------------------------------


def test_relative_seconds_is_zero_at_window_start():
    assert REAL_WINDOW.relative_seconds(T0) == 0.0


def test_relative_seconds_counts_from_window_start():
    assert REAL_WINDOW.relative_seconds(T0 + timedelta(seconds=300)) == 300.0
    assert REAL_WINDOW.relative_seconds(T0 + timedelta(days=1)) == 86400.0


def test_relative_seconds_is_negative_before_window_start():
    # T+0 이전 이벤트를 버리지 않고 음수로 보존한다.
    assert REAL_WINDOW.relative_seconds(T0 - timedelta(seconds=10)) == -10.0


def test_relative_seconds_is_none_without_timestamp():
    assert REAL_WINDOW.relative_seconds(None) is None


# ---------------------------------------------------------------------------
# align_event: 원본 불변 + 양쪽 보존
# ---------------------------------------------------------------------------


def test_original_timestamp_is_preserved_unchanged():
    moment = T0 + timedelta(hours=5)
    event = _event(timestamp=moment)
    aligned = align_event(event, REAL_WINDOW)
    assert aligned.timestamp == moment  # 원본시간 보존
    assert get_relative_seconds(aligned) == 5 * 3600  # 상대시간도 보존


def test_align_event_does_not_mutate_input():
    event = _event(timestamp=T0, extra={"status": 200})
    before_extra = dict(event.extra)
    aligned = align_event(event, REAL_WINDOW)
    assert event.extra == before_extra  # 입력 이벤트는 그대로
    assert RELATIVE_SECONDS_KEY not in event.extra
    assert aligned is not event


def test_existing_extra_is_kept():
    event = _event(timestamp=T0, extra={"status": 404, "path": "/x"})
    aligned = align_event(event, REAL_WINDOW)
    assert aligned.extra["status"] == 404
    assert aligned.extra["path"] == "/x"
    assert aligned.extra[RELATIVE_SECONDS_KEY] == 0.0


def test_all_other_fields_are_copied_unchanged():
    event = _event(timestamp=T0)
    aligned = align_event(event, REAL_WINDOW)
    for field in (
        "event_id",
        "source_type",
        "host",
        "source_path",
        "line_number",
        "raw",
        "dataset",
        "process",
        "pid",
        "user",
        "src_ip",
        "dst_ip",
        "event_type",
        "message",
    ):
        assert getattr(aligned, field) == getattr(event, field), field


def test_window_start_is_recorded_for_traceability():
    aligned = align_event(_event(timestamp=T0), REAL_WINDOW)
    assert aligned.extra[WINDOW_START_KEY] == T0.isoformat()


def test_scenario_id_recorded_only_in_scenario_mode():
    real = align_event(_event(timestamp=T0), REAL_WINDOW)
    scenario = align_event(_event(timestamp=T0), SCENARIO_WINDOW)
    assert SCENARIO_ID_KEY not in real.extra
    assert scenario.extra[SCENARIO_ID_KEY] == "scenario-001"
    assert get_scenario_id(real) is None
    assert get_scenario_id(scenario) == "scenario-001"


def test_event_without_timestamp_keeps_none_relative():
    aligned = align_event(_event(timestamp=None), REAL_WINDOW)
    assert aligned.timestamp is None
    assert get_relative_seconds(aligned) is None
    assert is_aligned(aligned)  # 정렬은 됐고, 값이 없다는 사실이 보존된다


def test_is_aligned_false_for_raw_event():
    assert not is_aligned(_event(timestamp=T0))


# ---------------------------------------------------------------------------
# align_events 스트리밍
# ---------------------------------------------------------------------------


def test_align_events_streams_and_preserves_order():
    events = [_event(event_id=f"e{i}", timestamp=T0 + timedelta(seconds=i)) for i in range(5)]
    aligned = list(align_events(events, REAL_WINDOW))
    assert [e.event_id for e in aligned] == [f"e{i}" for i in range(5)]
    assert [get_relative_seconds(e) for e in aligned] == [0.0, 1.0, 2.0, 3.0, 4.0]


def test_align_events_is_lazy():
    import types

    result = align_events(iter([_event(timestamp=T0)]), REAL_WINDOW)
    assert isinstance(result, types.GeneratorType)


# ---------------------------------------------------------------------------
# dataset boundary: real vs scenario
# ---------------------------------------------------------------------------


def test_real_mode_keeps_dataset_boundary():
    rm = align_event(_event(timestamp=T0, dataset="russellmitchell"), REAL_WINDOW)
    gaia = align_event(_event(timestamp=T0, dataset="gaia"), REAL_WINDOW)
    assert correlation_boundary_key(rm) == "russellmitchell"
    assert correlation_boundary_key(gaia) == "gaia"
    # 서로 다른 경계 -> correlation 금지
    assert correlation_boundary_key(rm) != correlation_boundary_key(gaia)


def test_scenario_mode_allows_cross_dataset_within_same_scenario():
    rm = align_event(_event(timestamp=T0, dataset="russellmitchell"), SCENARIO_WINDOW)
    gaia = align_event(_event(timestamp=T0, dataset="gaia"), SCENARIO_WINDOW)
    assert correlation_boundary_key(rm) == correlation_boundary_key(gaia) == "scenario-001"
    # dataset 자체는 그대로 보존된다(출처를 잃지 않는다)
    assert rm.dataset == "russellmitchell"
    assert gaia.dataset == "gaia"


def test_different_scenario_ids_are_separate_boundaries():
    a = align_event(
        _event(timestamp=T0, dataset="gaia"),
        AnalysisWindow(window_start=T0, scenario_id="s-a"),
    )
    b = align_event(
        _event(timestamp=T0, dataset="gaia"),
        AnalysisWindow(window_start=T0, scenario_id="s-b"),
    )
    assert correlation_boundary_key(a) != correlation_boundary_key(b)


def test_unaligned_event_falls_back_to_dataset_boundary():
    assert correlation_boundary_key(_event(dataset="gaia")) == "gaia"


# ---------------------------------------------------------------------------
# 서로 다른 dataset을 같은 T+0에 맞추면 상대초가 비교 가능해진다
# ---------------------------------------------------------------------------


def test_two_datasets_aligned_to_own_window_become_comparable():
    # 러셀미첼 2022-01-20 기준, GAIA 2021-07-01 기준으로 각각 정렬하면
    # 두 이벤트의 상대초가 같은 눈금 위에 놓인다(scenario mode의 목적).
    rm_window = AnalysisWindow(
        window_start=utc(2022, 1, 20), window_end=utc(2022, 1, 26), scenario_id="scenario-001"
    )
    gaia_window = AnalysisWindow(
        window_start=utc(2021, 7, 1), window_end=utc(2021, 9, 1), scenario_id="scenario-001"
    )
    rm = align_event(
        _event(timestamp=utc(2022, 1, 20, 0, 5), dataset="russellmitchell"), rm_window
    )
    gaia = align_event(_event(timestamp=utc(2021, 7, 1, 0, 5), dataset="gaia"), gaia_window)

    assert get_relative_seconds(rm) == get_relative_seconds(gaia) == 300.0
    assert correlation_boundary_key(rm) == correlation_boundary_key(gaia)
    # 원본 timestamp는 서로 다른 해에 그대로 남아 있다
    assert rm.timestamp.year == 2022
    assert gaia.timestamp.year == 2021


def test_relative_300_second_window_works_in_scenario_mode():
    # correlation의 300초 window를 상대초 기준으로 그대로 쓸 수 있다.
    a = align_event(_event(event_id="a", timestamp=utc(2022, 1, 20, 1, 0)), SCENARIO_WINDOW)
    b = align_event(_event(event_id="b", timestamp=utc(2022, 1, 20, 1, 4)), SCENARIO_WINDOW)
    c = align_event(_event(event_id="c", timestamp=utc(2022, 1, 20, 1, 10)), SCENARIO_WINDOW)
    gap_ab = get_relative_seconds(b) - get_relative_seconds(a)
    gap_ac = get_relative_seconds(c) - get_relative_seconds(a)
    assert gap_ab == 240.0 and gap_ab <= 300.0
    assert gap_ac == 600.0 and gap_ac > 300.0


# ---------------------------------------------------------------------------
# long-span 분모
# ---------------------------------------------------------------------------


def test_long_span_basis_uses_window_length_in_scenario_mode():
    assert long_span_basis_seconds(SCENARIO_WINDOW, 1000.0) == 6 * 86400


def test_long_span_basis_uses_observed_span_in_real_mode():
    assert long_span_basis_seconds(REAL_WINDOW, 1000.0) == 1000.0


def test_long_span_basis_falls_back_without_window_end():
    window = AnalysisWindow(window_start=T0, scenario_id="s1")
    assert long_span_basis_seconds(window, 1000.0) == 1000.0


def test_long_span_basis_without_window():
    assert long_span_basis_seconds(None, 1000.0) == 1000.0


# ---------------------------------------------------------------------------
# 결정론 / 계층 분리
# ---------------------------------------------------------------------------


def test_alignment_is_deterministic():
    event = _event(timestamp=T0 + timedelta(seconds=42))
    first = align_event(event, SCENARIO_WINDOW)
    second = align_event(event, SCENARIO_WINDOW)
    assert first.extra == second.extra


def test_scenario_layer_does_not_use_ground_truth_or_higher_layers():
    offenders = []
    for path in (PROJECT_ROOT / "scenario").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "ground_truth" in text.lower():
            offenders.append(f"{path.name}: ground_truth")
        for module in ("evaluation", "agents", "agent_skills", "orchestration", "llm"):
            if re.search(rf"^\s*(from|import)\s+{module}\b", text, re.MULTILINE):
                offenders.append(f"{path.name}: {module}")
    assert offenders == []


def test_lower_layers_do_not_import_scenario():
    offenders = []
    for directory in ("src", "agents", "agent_skills"):
        for path in (PROJECT_ROOT / directory).rglob("*.py"):
            if re.search(
                r"^\s*(from|import)\s+scenario\b", path.read_text(encoding="utf-8"), re.MULTILINE
            ):
                offenders.append(str(path.relative_to(PROJECT_ROOT)))
    assert offenders == []
