"""Investigation Focus / incident selection 단독 테스트 (orchestration 없이)."""

import re
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from correlation import (
    IncidentSelectionResult,
    InconsistentCorrelationError,
    InvestigationFocus,
    correlate_scenario,
    focus_on,
    select_incidents,
)
from scenario import make_scenario, project_findings, utc
from src.models import Finding

PROJECT_ROOT = Path(__file__).resolve().parent.parent

W_START = utc(2022, 1, 24, 3, 0)
W_END = utc(2022, 1, 24, 5, 0)
SCENARIO = make_scenario("incident-001", {"russellmitchell": (W_START, W_END)})


def _finding(*, finding_id, offset_seconds=0, duration_seconds=60, host=None, entities=None):
    start = W_START + timedelta(seconds=offset_seconds)
    return Finding(
        finding_id=finding_id,
        dataset="russellmitchell",
        category="availability",
        finding_type="request_spike",
        start_time=start,
        end_time=start + timedelta(seconds=duration_seconds),
        host=host,
        service="apache2",
        severity="low",
        summary="s",
        metrics={},
        evidence=[],
        entities={} if entities is None else dict(entities),
        detector="find_request_spike",
    )


def _correlate(findings):
    return correlate_scenario(project_findings(findings, SCENARIO))


# ---------------------------------------------------------------------------
# InvestigationFocus
# ---------------------------------------------------------------------------


def test_anchor_order_does_not_change_focus():
    a = InvestigationFocus(anchor_finding_ids=("A", "B"))
    b = InvestigationFocus(anchor_finding_ids=("B", "A"))
    assert a == b
    assert hash(a) == hash(b)
    assert a.anchor_finding_ids == ("A", "B")  # canonical 정렬


def test_anchor_ids_are_normalized_to_sorted_tuple():
    focus = InvestigationFocus(anchor_finding_ids=["z", "m", "a"])
    assert focus.anchor_finding_ids == ("a", "m", "z")
    assert isinstance(focus.anchor_finding_ids, tuple)


def test_empty_anchor_tuple_is_value_error():
    with pytest.raises(ValueError, match="비어 있다"):
        InvestigationFocus(anchor_finding_ids=())


def test_duplicate_anchor_is_value_error():
    with pytest.raises(ValueError, match="중복"):
        InvestigationFocus(anchor_finding_ids=("a", "b", "a"))


def test_focus_on_builds_from_finding_objects():
    findings = [_finding(finding_id="f2"), _finding(finding_id="f1")]
    focus = focus_on(findings)
    assert focus.anchor_finding_ids == ("f1", "f2")
    assert focus == InvestigationFocus(anchor_finding_ids=("f1", "f2"))


def test_focus_on_rejects_duplicate_findings():
    finding = _finding(finding_id="f1")
    with pytest.raises(ValueError):
        focus_on([finding, finding])


# ---------------------------------------------------------------------------
# selection
# ---------------------------------------------------------------------------


def test_anchor_in_single_finding_incident_is_selected():
    findings = [_finding(finding_id="a"), _finding(finding_id="b", offset_seconds=3000)]
    result = _correlate(findings)
    assert len(result.incidents) == 2
    selection = select_incidents(result, focus_on([findings[0]]))
    assert isinstance(selection, IncidentSelectionResult)
    assert len(selection.focused_incident_ids) == 1
    incident = result.incident_by_id(selection.focused_incident_ids[0])
    assert incident.finding_ids == ("a",)
    assert incident.is_single_finding
    assert selection.unmatched_anchor_finding_ids == ()
    assert selection.candidate_incident_count == 2


def test_multiple_anchors_in_same_incident_select_one():
    findings = [
        _finding(finding_id="a", host="h1", entities={"host": ["h1"]}),
        _finding(finding_id="b", offset_seconds=30, host="h1", entities={"host": ["h1"]}),
    ]
    result = _correlate(findings)
    assert len(result.incidents) == 1  # 둘이 묶였다
    selection = select_incidents(result, InvestigationFocus(anchor_finding_ids=("a", "b")))
    assert len(selection.focused_incident_ids) == 1
    assert selection.anchor_to_incident["a"] == selection.anchor_to_incident["b"]


def test_anchors_in_different_incidents_select_several():
    findings = [
        _finding(finding_id="a"),
        _finding(finding_id="b", offset_seconds=2000),
        _finding(finding_id="c", offset_seconds=4000),
    ]
    result = _correlate(findings)
    assert len(result.incidents) == 3
    selection = select_incidents(result, InvestigationFocus(anchor_finding_ids=("a", "c")))
    assert len(selection.focused_incident_ids) == 2
    selected_findings = {
        fid
        for incident_id in selection.focused_incident_ids
        for fid in result.incident_by_id(incident_id).finding_ids
    }
    assert selected_findings == {"a", "c"}


def test_unknown_anchor_is_reported_not_raised():
    findings = [_finding(finding_id="a")]
    result = _correlate(findings)
    selection = select_incidents(result, InvestigationFocus(anchor_finding_ids=("nope",)))
    assert selection.focused_incident_ids == ()
    assert selection.unmatched_anchor_finding_ids == ("nope",)
    assert selection.has_unmatched_anchors
    assert selection.is_empty
    assert any("매칭되지 않아" in note for note in selection.notes)


def test_partially_matched_anchors():
    findings = [_finding(finding_id="a")]
    result = _correlate(findings)
    selection = select_incidents(
        result, InvestigationFocus(anchor_finding_ids=("a", "missing"))
    )
    assert len(selection.focused_incident_ids) == 1
    assert selection.unmatched_anchor_finding_ids == ("missing",)
    assert "a" in selection.anchor_to_incident


def test_anchor_excluded_by_window_is_unmatched():
    inside = _finding(finding_id="in", offset_seconds=60)
    outside = _finding(finding_id="out", offset_seconds=-100_000)
    projection = project_findings([inside, outside], SCENARIO)
    assert projection.excluded_out_of_window == ("out",)
    result = correlate_scenario(projection)
    selection = select_incidents(result, focus_on([outside]))
    assert selection.unmatched_anchor_finding_ids == ("out",)
    assert any("Window 밖" in note for note in selection.notes)


def test_selection_does_not_prefer_multi_finding_incidents():
    """anchor가 single-Finding incident에 있으면 multi가 있어도 single을 고른다."""
    multi_a = _finding(finding_id="m1", host="h1", entities={"host": ["h1"]})
    multi_b = _finding(finding_id="m2", offset_seconds=30, host="h1", entities={"host": ["h1"]})
    lone = _finding(finding_id="lone", offset_seconds=4000, host="h2", entities={"host": ["h2"]})

    result = _correlate([multi_a, multi_b, lone])
    assert len(result.multi_finding_incidents) == 1
    assert len(result.single_finding_incidents) == 1

    selection = select_incidents(result, focus_on([lone]))
    assert len(selection.focused_incident_ids) == 1
    incident = result.incident_by_id(selection.focused_incident_ids[0])
    assert incident.finding_ids == ("lone",)
    assert incident.is_single_finding
    # multi incident는 선택되지 않았다
    multi_id = result.multi_finding_incidents[0].incident_id
    assert multi_id not in selection.focused_incident_ids


def test_unrelated_multi_incident_in_same_window_is_not_selected():
    """핵심: 같은 Window 안의 무관한 multi incident를 선택하지 않는다.

    실제 GAIA 상황을 재현한다 - dbservice1 network anomaly를 anchor로 했을 때 같은
    Window 안에 있던 webservice2 latency 2건 incident를 고르지 않아야 한다.
    """
    anchor = _finding(
        finding_id="network", offset_seconds=600, host=None, entities={"service": ["dbservice1"]}
    )
    unrelated_a = _finding(
        finding_id="lat1", offset_seconds=610, host=None, entities={"service": ["webservice2"]}
    )
    unrelated_b = _finding(
        finding_id="lat2", offset_seconds=640, host=None, entities={"service": ["webservice2"]}
    )

    result = _correlate([anchor, unrelated_a, unrelated_b])
    assert len(result.incidents) == 2
    assert len(result.multi_finding_incidents) == 1

    selection = select_incidents(result, focus_on([anchor]))
    assert len(selection.focused_incident_ids) == 1
    chosen = result.incident_by_id(selection.focused_incident_ids[0])
    assert chosen.finding_ids == ("network",)
    assert chosen.impact.affected_services == ("apache2",)
    assert "lat1" not in chosen.finding_ids and "lat2" not in chosen.finding_ids
    assert selection.candidate_incident_count == 2
    assert any("조사 대상이 아니다" in note for note in selection.notes)


def test_candidate_incident_count_matches_total():
    findings = [_finding(finding_id=f"f{i}", offset_seconds=i * 1500) for i in range(4)]
    result = _correlate(findings)
    selection = select_incidents(result, focus_on([findings[0]]))
    assert selection.candidate_incident_count == len(result.incidents) == 4


def test_selection_is_deterministic_regardless_of_anchor_order():
    findings = [_finding(finding_id=f"f{i}", offset_seconds=i * 2000) for i in range(3)]
    result = _correlate(findings)
    first = select_incidents(result, InvestigationFocus(anchor_finding_ids=("f0", "f2")))
    second = select_incidents(result, InvestigationFocus(anchor_finding_ids=("f2", "f0")))
    assert first == second


def test_selection_holds_ids_not_incident_copies():
    findings = [_finding(finding_id="a")]
    result = _correlate(findings)
    selection = select_incidents(result, focus_on(findings))
    assert all(isinstance(i, str) for i in selection.focused_incident_ids)
    fields = set(IncidentSelectionResult.__dataclass_fields__)
    assert "incidents" not in fields
    assert "focused_incidents" not in fields


def test_scenario_id_is_carried_into_selection():
    result = _correlate([_finding(finding_id="a")])
    selection = select_incidents(result, focus_on([_finding(finding_id="a")]))
    assert selection.scenario_id == "incident-001"


# ---------------------------------------------------------------------------
# correlation invariant 위반 검출
# ---------------------------------------------------------------------------


def test_finding_in_two_incidents_fails_immediately():
    findings = [_finding(finding_id="a"), _finding(finding_id="b", offset_seconds=2000)]
    result = _correlate(findings)
    assert len(result.incidents) == 2

    # 비정상 CorrelationResult를 인공으로 만든다: "a"가 두 incident에 들어가 있다.
    broken_incident = replace(result.incidents[1], finding_ids=("a", "b"))
    broken = replace(result, incidents=(result.incidents[0], broken_incident))

    with pytest.raises(InconsistentCorrelationError):
        select_incidents(broken, focus_on([findings[0]]))


def test_inconsistent_correlation_error_is_assertion_error():
    # orchestration의 error policy에서 programming error로 다시 raise되려면
    # AssertionError 계열이어야 한다.
    assert issubclass(InconsistentCorrelationError, AssertionError)


def test_same_finding_listed_twice_in_one_incident_does_not_raise():
    # 같은 incident 안에서 같은 finding_id가 반복되는 것은 invariant 위반이 아니다.
    findings = [_finding(finding_id="a")]
    result = _correlate(findings)
    weird = replace(result.incidents[0], finding_ids=("a", "a"))
    patched = replace(result, incidents=(weird,))
    selection = select_incidents(patched, focus_on(findings))
    assert len(selection.focused_incident_ids) == 1


# ---------------------------------------------------------------------------
# 계층 분리
# ---------------------------------------------------------------------------


def test_focus_module_does_not_import_orchestration():
    text = (PROJECT_ROOT / "correlation" / "focus.py").read_text(encoding="utf-8")
    for module in ("orchestration", "agents", "agent_skills", "evaluation", "llm"):
        assert not re.search(rf"^\s*(from|import)\s+{module}\b", text, re.MULTILINE), module
    assert "ground_truth" not in text.lower()
