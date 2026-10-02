"""Scenario Finding Projection 테스트.

원본 Finding 불변, 상대시간 계산, clip, 제외/누락 기록, 결정론을 검증한다.
Event pkl을 읽지 않고 Ground Truth도 쓰지 않는다.
"""

import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from scenario import (
    ON_MISSING_SKIP,
    MissingDatasetWindowError,
    NaiveDatetimeError,
    ScenarioDatasetWindow,
    ScenarioDefinition,
    ScenarioProjection,
    aligned_source_scenario,
    make_analysis_scenario,
    make_scenario,
    project_findings,
    utc,
)
from src.models import Finding
from tests.test_agent_skills import _fingerprint

PROJECT_ROOT = Path(__file__).resolve().parent.parent

RM_T0 = utc(2022, 1, 20)
RM_END = utc(2022, 1, 26)
GAIA_T0 = utc(2021, 7, 1)
GAIA_END = utc(2021, 9, 1)

SCENARIO = aligned_source_scenario()


def _finding(
    *,
    finding_id="f1",
    dataset="russellmitchell",
    start=None,
    end=None,
    category="availability",
    finding_type="request_spike",
    severity="low",
) -> Finding:
    start = RM_T0 if start is None else start
    end = start if end is None else end
    return Finding(
        finding_id=finding_id,
        dataset=dataset,
        category=category,
        finding_type=finding_type,
        start_time=start,
        end_time=end,
        host="webserver",
        service="apache2",
        severity=severity,
        summary="s",
        metrics={"ratio": 2.0},
        evidence=[],
        entities={"host": ["webserver"]},
        detector="find_request_spike",
    )


# ---------------------------------------------------------------------------
# 1~2. dataset별 상대시간 계산
# ---------------------------------------------------------------------------


def test_rm_finding_relative_time():
    # 실제 Finding과 같은 시각: 2022-01-24 03:57 ~ 03:59
    finding = _finding(start=utc(2022, 1, 24, 3, 57), end=utc(2022, 1, 24, 3, 59))
    result = project_findings([finding], SCENARIO)
    item = result.findings[0]
    expected = (utc(2022, 1, 24, 3, 57) - RM_T0).total_seconds()
    assert item.relative_start_seconds == expected == 359_820.0
    assert item.relative_end_seconds == expected + 120.0


def test_gaia_finding_relative_time():
    # 실제 Finding과 같은 시각: 2021-07-20 09:34:55 (span 0)
    moment = utc(2021, 7, 20, 9, 34, 55)
    finding = _finding(
        finding_id="g1",
        dataset="gaia",
        start=moment,
        end=moment,
        category="resource",
        finding_type="cpu_usage_anomaly",
    )
    result = project_findings([finding], SCENARIO)
    item = result.findings[0]
    expected = (moment - GAIA_T0).total_seconds()
    assert item.relative_start_seconds == expected == 1_676_095.0
    assert item.relative_start_seconds == item.relative_end_seconds
    assert item.effective_span_seconds == 0.0
    assert item.window_length_seconds == (GAIA_END - GAIA_T0).total_seconds()


# ---------------------------------------------------------------------------
# 3. 서로 다른 원본 연도가 같은 상대 시간축에
# ---------------------------------------------------------------------------


def test_different_original_years_land_on_same_relative_axis():
    rm = _finding(
        finding_id="rm",
        dataset="russellmitchell",
        start=RM_T0 + timedelta(seconds=300),
        end=RM_T0 + timedelta(seconds=360),
    )
    gaia = _finding(
        finding_id="gaia",
        dataset="gaia",
        start=GAIA_T0 + timedelta(seconds=300),
        end=GAIA_T0 + timedelta(seconds=360),
    )
    result = project_findings([rm, gaia], SCENARIO)
    assert len(result) == 2
    by_id = {item.finding_id: item for item in result}
    assert by_id["rm"].relative_start_seconds == by_id["gaia"].relative_start_seconds == 300.0
    assert by_id["rm"].relative_end_seconds == by_id["gaia"].relative_end_seconds == 360.0
    # 원본 timestamp는 서로 다른 해에 그대로 남아 있다
    assert by_id["rm"].original_start_time.year == 2022
    assert by_id["gaia"].original_start_time.year == 2021
    # dataset provenance도 유지된다
    assert by_id["rm"].dataset == "russellmitchell"
    assert by_id["gaia"].dataset == "gaia"


# ---------------------------------------------------------------------------
# 4. 원본 Finding 불변
# ---------------------------------------------------------------------------


def test_original_finding_is_not_modified():
    finding = _finding(start=utc(2022, 1, 22), end=utc(2022, 1, 22, 0, 1))
    before = _fingerprint(finding)
    result = project_findings([finding], SCENARIO)
    assert _fingerprint(finding) == before
    # 참조로 들고 있다(복사하지 않는다)
    assert result.findings[0].finding is finding


def test_clipping_does_not_modify_original_finding():
    # Window 경계를 걸친 Finding을 clip해도 원본 시간은 그대로다.
    finding = _finding(start=RM_T0 - timedelta(hours=2), end=RM_T0 + timedelta(hours=2))
    before_start, before_end = finding.start_time, finding.end_time
    item = project_findings([finding], SCENARIO).findings[0]
    assert finding.start_time == before_start
    assert finding.end_time == before_end
    assert item.was_clipped is True
    assert item.effective_start_time == RM_T0  # clip된 값은 별도 필드에만


def test_projection_layer_never_writes_to_finding_fields():
    """projection 코드가 Finding 속성에 대입하지 않는지 소스로 확인한다."""
    source = (PROJECT_ROOT / "scenario" / "finding_projection.py").read_text(encoding="utf-8")
    assert not re.search(r"finding\.\w+\s*=", source)
    source_models = (PROJECT_ROOT / "scenario" / "models.py").read_text(encoding="utf-8")
    assert not re.search(r"\.finding\.\w+\s*=[^=]", source_models)


# ---------------------------------------------------------------------------
# 5~6. T+0 / T+300
# ---------------------------------------------------------------------------


def test_finding_at_window_start_is_t_plus_zero():
    finding = _finding(start=RM_T0, end=RM_T0)
    item = project_findings([finding], SCENARIO).findings[0]
    assert item.relative_start_seconds == 0.0
    assert item.relative_effective_start_seconds == 0.0
    assert item.was_clipped is False


def test_finding_300_seconds_after_window_start():
    finding = _finding(start=RM_T0 + timedelta(seconds=300), end=RM_T0 + timedelta(seconds=300))
    item = project_findings([finding], SCENARIO).findings[0]
    assert item.relative_start_seconds == 300.0


# ---------------------------------------------------------------------------
# 7. Window 밖 Finding 제외
# ---------------------------------------------------------------------------


def test_finding_entirely_before_window_is_excluded():
    finding = _finding(
        start=RM_T0 - timedelta(days=5), end=RM_T0 - timedelta(days=5, seconds=-60)
    )
    result = project_findings([finding], SCENARIO)
    assert result.findings == ()
    assert result.excluded_out_of_window == ("f1",)
    assert any("겹치지 않아" in note for note in result.notes)


def test_finding_entirely_after_window_is_excluded():
    finding = _finding(start=RM_END + timedelta(days=1), end=RM_END + timedelta(days=1, minutes=1))
    result = project_findings([finding], SCENARIO)
    assert result.findings == ()
    assert result.excluded_out_of_window == ("f1",)


def test_finding_touching_window_start_boundary_is_included():
    # 경계는 포함으로 본다: end == window_start
    finding = _finding(start=RM_T0 - timedelta(minutes=1), end=RM_T0)
    result = project_findings([finding], SCENARIO)
    assert len(result) == 1
    assert result.findings[0].relative_start_seconds == -60.0  # 원본은 음수로 보존
    assert result.findings[0].relative_effective_start_seconds == 0.0  # clip 후 T+0


def test_finding_touching_window_end_boundary_is_included():
    finding = _finding(start=RM_END, end=RM_END + timedelta(minutes=1))
    result = project_findings([finding], SCENARIO)
    assert len(result) == 1
    item = result.findings[0]
    assert item.relative_effective_end_seconds == item.window_length_seconds


# ---------------------------------------------------------------------------
# 8. 부분 overlap clip
# ---------------------------------------------------------------------------


def test_partial_overlap_is_clipped_at_both_ends():
    finding = _finding(start=RM_T0 - timedelta(days=1), end=RM_END + timedelta(days=1))
    result = project_findings([finding], SCENARIO)
    item = result.findings[0]
    assert item.was_clipped is True
    assert item.effective_start_time == RM_T0
    assert item.effective_end_time == RM_END
    assert item.effective_span_seconds == item.window_length_seconds
    assert item.span_ratio == 1.0
    # clip 전 원본 기준 상대초는 그대로 남는다
    assert item.relative_start_seconds == -86400.0
    assert item.relative_end_seconds == item.window_length_seconds + 86400.0
    assert result.clipped_count == 1


def test_fully_contained_finding_is_not_clipped():
    finding = _finding(start=utc(2022, 1, 22), end=utc(2022, 1, 22, 0, 1))
    item = project_findings([finding], SCENARIO).findings[0]
    assert item.was_clipped is False
    assert item.effective_start_time == finding.start_time
    assert item.effective_end_time == finding.end_time
    assert project_findings([finding], SCENARIO).clipped_count == 0


# ---------------------------------------------------------------------------
# 9. dataset Window 누락
# ---------------------------------------------------------------------------


def test_missing_dataset_window_raises_by_default():
    finding = _finding(dataset="unknown_dataset")
    with pytest.raises(MissingDatasetWindowError) as excinfo:
        project_findings([finding], SCENARIO)
    message = str(excinfo.value)
    assert "unknown_dataset" in message
    assert "f1" in message
    assert "gaia" in message  # 정의된 dataset을 알려 준다


def test_missing_dataset_window_can_be_skipped_explicitly():
    ok = _finding(finding_id="ok", start=utc(2022, 1, 22))
    unknown = _finding(finding_id="bad", dataset="unknown_dataset", start=utc(2022, 1, 22))
    result = project_findings([ok, unknown], SCENARIO, on_missing_window=ON_MISSING_SKIP)
    assert result.finding_ids == ("ok",)
    assert result.skipped_missing_window == ("bad",)
    assert any("Window가 없어" in note for note in result.notes)


def test_invalid_on_missing_window_value_is_rejected():
    with pytest.raises(ValueError):
        project_findings([], SCENARIO, on_missing_window="ignore")


def test_naive_datetime_raises_clear_error():
    finding = _finding(start=datetime(2022, 1, 22), end=datetime(2022, 1, 22))
    with pytest.raises(NaiveDatetimeError):
        project_findings([finding], SCENARIO)


# ---------------------------------------------------------------------------
# 10~11. scenario_id 보존 / 결정론
# ---------------------------------------------------------------------------


def test_scenario_id_is_preserved_on_every_item():
    findings = [
        _finding(finding_id="a", start=utc(2022, 1, 21)),
        _finding(finding_id="b", dataset="gaia", start=utc(2021, 7, 2)),
    ]
    result = project_findings(findings, SCENARIO)
    assert result.scenario_id == "scenario-001"
    assert all(item.scenario_id == "scenario-001" for item in result)


def test_reversed_input_order_yields_identical_projection():
    findings = [
        _finding(finding_id=f"f{i}", start=RM_T0 + timedelta(hours=i)) for i in range(5)
    ]
    forward = project_findings(findings, SCENARIO)
    reverse = project_findings(list(reversed(findings)), SCENARIO)
    assert forward == reverse


def test_sort_order_is_relative_start_then_end_then_id():
    a = _finding(finding_id="zzz", start=RM_T0 + timedelta(seconds=10), end=RM_T0 + timedelta(seconds=20))
    b = _finding(finding_id="aaa", start=RM_T0 + timedelta(seconds=10), end=RM_T0 + timedelta(seconds=20))
    c = _finding(finding_id="mmm", start=RM_T0 + timedelta(seconds=10), end=RM_T0 + timedelta(seconds=15))
    d = _finding(finding_id="bbb", start=RM_T0 + timedelta(seconds=5), end=RM_T0 + timedelta(seconds=99))
    result = project_findings([a, b, c, d], SCENARIO)
    # start 5초가 먼저, 그 다음 start 10초 중 end 짧은 것, 같은 end는 finding_id 순
    assert result.finding_ids == ("bbb", "mmm", "aaa", "zzz")


def test_duplicate_findings_are_projected_as_given():
    # projection은 dedup을 하지 않는다(collect_findings가 이미 했다).
    finding = _finding(start=utc(2022, 1, 22))
    result = project_findings([finding, finding], SCENARIO)
    assert len(result) == 2


def test_empty_input_returns_empty_projection():
    result = project_findings([], SCENARIO)
    assert isinstance(result, ScenarioProjection)
    assert len(result) == 0
    assert result.notes == ()


# ---------------------------------------------------------------------------
# span_ratio (long-span 지원)
# ---------------------------------------------------------------------------


def test_span_ratio_uses_window_length_not_observed_span():
    # 실제 repeated_source_ip_scan과 같은 폭: 301,389초
    finding = _finding(
        finding_id="scan",
        start=utc(2022, 1, 21, 6, 30, 14),
        end=utc(2022, 1, 24, 18, 13, 23),
        category="security",
        finding_type="repeated_source_ip_scan",
        severity="high",
    )
    item = project_findings([finding], SCENARIO).findings[0]
    assert item.effective_span_seconds == 301_389.0
    assert item.window_length_seconds == 518_400.0
    assert item.span_ratio == pytest.approx(301_389.0 / 518_400.0)
    assert 0.58 < item.span_ratio < 0.59


def test_span_ratio_of_instantaneous_finding_is_zero():
    moment = utc(2022, 1, 22)
    item = project_findings([_finding(start=moment, end=moment)], SCENARIO).findings[0]
    assert item.span_ratio == 0.0


def test_original_span_and_effective_span_differ_when_clipped():
    finding = _finding(start=RM_T0 - timedelta(days=1), end=RM_T0 + timedelta(days=1))
    item = project_findings([finding], SCENARIO).findings[0]
    assert item.original_span_seconds == 2 * 86400
    assert item.effective_span_seconds == 86400


# ---------------------------------------------------------------------------
# 모델 검증
# ---------------------------------------------------------------------------


def test_window_requires_timezone_aware_bounds():
    with pytest.raises(ValueError):
        ScenarioDatasetWindow("x", datetime(2022, 1, 20), utc(2022, 1, 26))


def test_window_end_must_be_after_start():
    with pytest.raises(ValueError):
        ScenarioDatasetWindow("x", RM_T0, RM_T0)


def test_duplicate_dataset_windows_are_rejected():
    with pytest.raises(ValueError, match="중복"):
        ScenarioDefinition(
            scenario_id="s",
            windows=(
                ScenarioDatasetWindow("gaia", GAIA_T0, GAIA_END),
                ScenarioDatasetWindow("gaia", RM_T0, RM_END),
            ),
        )


def test_empty_scenario_id_is_rejected():
    with pytest.raises(ValueError):
        ScenarioDefinition(scenario_id=" ", windows=())


def test_window_for_returns_none_for_unknown_dataset():
    assert SCENARIO.window_for("nope") is None


# ---------------------------------------------------------------------------
# definitions: aligned source 범위 vs incident 분석 Window
# ---------------------------------------------------------------------------


def test_aligned_source_scenario_matches_generated_pkl_windows():
    scenario = aligned_source_scenario()
    assert scenario.scenario_id == "scenario-001"
    rm = scenario.window_for("russellmitchell")
    gaia = scenario.window_for("gaia")
    assert (rm.window_start, rm.window_end) == (utc(2022, 1, 20), utc(2022, 1, 26))
    assert (gaia.window_start, gaia.window_end) == (utc(2021, 7, 1), utc(2021, 9, 1))


def test_aligned_source_windows_have_different_lengths():
    # 이것이 aligned source 범위를 correlation에 그대로 쓰면 안 되는 이유다.
    scenario = aligned_source_scenario()
    lengths = {w.dataset: w.window_length_seconds for w in scenario.windows}
    assert lengths["russellmitchell"] != lengths["gaia"]


def test_make_analysis_scenario_gives_every_dataset_the_same_window_length():
    scenario = make_analysis_scenario(
        "incident-001",
        anchors={
            "russellmitchell": utc(2022, 1, 24, 3, 57),
            "gaia": utc(2021, 7, 20, 9, 34, 55),
        },
        duration=timedelta(hours=2),
        lead=timedelta(minutes=30),
    )
    lengths = {w.window_length_seconds for w in scenario.windows}
    assert lengths == {7200.0}  # 모든 dataset이 같은 길이 -> 상대초가 같은 눈금


def test_make_analysis_scenario_anchor_lands_at_lead_offset():
    anchor = utc(2022, 1, 24, 3, 57)
    scenario = make_analysis_scenario(
        "incident-002",
        anchors={"russellmitchell": anchor},
        duration=timedelta(hours=1),
        lead=timedelta(minutes=10),
    )
    window = scenario.window_for("russellmitchell")
    assert window.window_start == anchor - timedelta(minutes=10)
    assert window.relative_seconds(anchor) == 600.0


def test_make_analysis_scenario_rejects_bad_duration():
    with pytest.raises(ValueError):
        make_analysis_scenario("x", anchors={}, duration=timedelta(0))
    with pytest.raises(ValueError):
        make_analysis_scenario(
            "x", anchors={}, duration=timedelta(hours=1), lead=timedelta(seconds=-1)
        )


def test_narrow_analysis_scenario_excludes_findings_outside_it():
    # 좁은 분석 Window를 쓰면 그 밖의 Finding은 제외된다(aligned source 범위와 다르다).
    scenario = make_scenario(
        "narrow-001",
        {"russellmitchell": (utc(2022, 1, 24, 3, 0), utc(2022, 1, 24, 5, 0))},
    )
    inside = _finding(finding_id="in", start=utc(2022, 1, 24, 3, 57))
    outside = _finding(finding_id="out", start=utc(2022, 1, 21, 12, 2))
    result = project_findings([inside, outside], scenario)
    assert result.finding_ids == ("in",)
    assert result.excluded_out_of_window == ("out",)
    assert result.findings[0].relative_start_seconds == 3420.0  # 03:00 -> 03:57


# ---------------------------------------------------------------------------
# 12~13. Ground Truth / Event pkl 재스캔 금지
# ---------------------------------------------------------------------------


def test_projection_does_not_reference_ground_truth_or_events():
    for name in ("models.py", "finding_projection.py", "definitions.py"):
        text = (PROJECT_ROOT / "scenario" / name).read_text(encoding="utf-8")
        assert "ground_truth" not in text.lower(), name
        for module in ("evaluation", "agents", "agent_skills", "orchestration", "llm"):
            assert not re.search(rf"^\s*(from|import)\s+{module}\b", text, re.MULTILINE), name


def test_projection_does_not_import_event_store_or_loader():
    text = (PROJECT_ROOT / "scenario" / "finding_projection.py").read_text(encoding="utf-8")
    for forbidden in ("event_store", "src.loader", "load_events", "NormalizedEvent"):
        assert forbidden not in text, forbidden


def test_projection_performs_no_filesystem_access(monkeypatch):
    import builtins

    def explode(*args, **kwargs):
        raise AssertionError("projection은 파일을 열지 않아야 한다")

    monkeypatch.setattr(builtins, "open", explode)
    result = project_findings([_finding(start=utc(2022, 1, 22))], SCENARIO)
    assert len(result) == 1
