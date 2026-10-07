"""scenario mode workflow 연결 테스트.

기존 real mode workflow를 깨지 않는지, scenario node 3개가 State를 올바르게 채우는지,
error policy가 기존과 일관된지 검증한다.
"""

import re
from datetime import timedelta
from pathlib import Path

import pytest

from correlation import (
    CorrelationResult,
    IncidentSelectionResult,
    InvestigationFocus,
    focus_on,
)
from orchestration import (
    NODE_EVIDENCE_CORRELATION,
    NODE_INTERPRET,
    NODE_SCENARIO_PROJECTION,
    NODE_SECURITY,
    NODE_SELECT_INCIDENT,
    build_graph,
    run_investigation,
)
from scenario import ScenarioProjection, make_scenario, utc
from tests.test_agent_skills import (
    _apache_events_with_spike,
    _fingerprint,
    _metric_events_with_spike,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# tests.test_agent_skills의 apache fixture는 2022-01-21 00:00부터 시작한다.
RM_T0 = utc(2022, 1, 21)
RM_WINDOW = (RM_T0, RM_T0 + timedelta(hours=6))
SCENARIO = make_scenario("incident-001", {"russellmitchell": RM_WINDOW})

GAIA_T0 = utc(2021, 7, 1)
BOTH_SCENARIO = make_scenario(
    "incident-both",
    {
        "russellmitchell": RM_WINDOW,
        "gaia": (GAIA_T0, GAIA_T0 + timedelta(hours=12)),
    },
)


# ---------------------------------------------------------------------------
# 1. 기존 real mode 호환성
# ---------------------------------------------------------------------------


def test_real_mode_node_set_is_unchanged():
    nodes = {n for n in build_graph().get_graph().nodes if not n.startswith("__")}
    assert NODE_SCENARIO_PROJECTION not in nodes
    assert NODE_EVIDENCE_CORRELATION not in nodes
    assert NODE_SELECT_INCIDENT not in nodes
    assert NODE_INTERPRET not in nodes


def test_run_investigation_without_scenario_behaves_as_before():
    events = _apache_events_with_spike()
    state = run_investigation(events=events)
    assert state["scenario_definition"] is None
    assert state["investigation_focus"] is None
    assert state["scenario_projection"] is None
    assert state["correlation_result"] is None
    assert state["incident_selection"] is None
    assert state["findings"]
    assert state["errors"] == {}


def test_scenario_fields_do_not_change_detection_results():
    events = _apache_events_with_spike()
    without = run_investigation(events=events)
    with_scenario = run_investigation(events=events, scenario_definition=SCENARIO)
    assert [_fingerprint(f) for f in with_scenario["findings"]] == [
        _fingerprint(f) for f in without["findings"]
    ]
    assert with_scenario["security_result"].findings == without["security_result"].findings


def test_focus_without_scenario_definition_is_rejected():
    with pytest.raises(ValueError, match="scenario_definition"):
        run_investigation(
            events=[], investigation_focus=InvestigationFocus(anchor_finding_ids=("x",))
        )


# ---------------------------------------------------------------------------
# 3가지 graph topology + 순서
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario,interpret,expected",
    [
        (False, False, set()),
        (False, True, {NODE_INTERPRET}),
        (True, False, {NODE_SCENARIO_PROJECTION, NODE_EVIDENCE_CORRELATION, NODE_SELECT_INCIDENT}),
        (
            True,
            True,
            {
                NODE_SCENARIO_PROJECTION,
                NODE_EVIDENCE_CORRELATION,
                NODE_SELECT_INCIDENT,
                NODE_INTERPRET,
            },
        ),
    ],
)
def test_graph_topologies(scenario, interpret, expected):
    graph = build_graph(scenario=scenario, interpret=interpret)
    nodes = {n for n in graph.get_graph().nodes if not n.startswith("__")}
    optional = {
        NODE_SCENARIO_PROJECTION,
        NODE_EVIDENCE_CORRELATION,
        NODE_SELECT_INCIDENT,
        NODE_INTERPRET,
    }
    assert nodes & optional == expected


def test_scenario_and_interpret_order_is_projection_correlation_selection_interpretation():
    graph = build_graph(scenario=True, interpret=True)
    edges = {(e.source, e.target) for e in graph.get_graph().edges}
    assert (NODE_SECURITY, NODE_SCENARIO_PROJECTION) in edges
    assert (NODE_SCENARIO_PROJECTION, NODE_EVIDENCE_CORRELATION) in edges
    assert (NODE_EVIDENCE_CORRELATION, NODE_SELECT_INCIDENT) in edges
    assert (NODE_SELECT_INCIDENT, NODE_INTERPRET) in edges
    assert (NODE_INTERPRET, "__end__") in edges
    # END와 interpret로 동시에 fan-out하지 않는다
    assert (NODE_SELECT_INCIDENT, "__end__") not in edges
    assert (NODE_SECURITY, "__end__") not in edges


def test_scenario_only_tail_goes_to_end():
    graph = build_graph(scenario=True, interpret=False)
    edges = {(e.source, e.target) for e in graph.get_graph().edges}
    assert (NODE_SELECT_INCIDENT, "__end__") in edges
    assert (NODE_SECURITY, "__end__") not in edges


# ---------------------------------------------------------------------------
# 2~4. scenario mode 실행
# ---------------------------------------------------------------------------


def test_scenario_mode_stores_projection():
    state = run_investigation(
        events=_apache_events_with_spike(), scenario_definition=SCENARIO
    )
    projection = state["scenario_projection"]
    assert isinstance(projection, ScenarioProjection)
    assert projection.scenario_id == "incident-001"
    assert len(projection) > 0


def test_scenario_mode_stores_correlation_result():
    state = run_investigation(
        events=_apache_events_with_spike(), scenario_definition=SCENARIO
    )
    result = state["correlation_result"]
    assert isinstance(result, CorrelationResult)
    assert result.scenario_id == "incident-001"
    assert result.finding_count == len(state["scenario_projection"])


def test_scenario_mode_stores_incident_selection():
    events = _apache_events_with_spike()
    findings = run_investigation(events=events)["findings"]
    anchor = findings[0]
    state = run_investigation(
        events=events,
        scenario_definition=SCENARIO,
        investigation_focus=focus_on([anchor]),
    )
    selection = state["incident_selection"]
    assert isinstance(selection, IncidentSelectionResult)
    assert len(selection.focused_incident_ids) == 1
    incident = state["correlation_result"].incident_by_id(selection.focused_incident_ids[0])
    assert anchor.finding_id in incident.finding_ids


def test_focus_none_leaves_incident_selection_none():
    state = run_investigation(
        events=_apache_events_with_spike(), scenario_definition=SCENARIO
    )
    assert state["correlation_result"] is not None
    assert state["incident_selection"] is None  # 빈 결과를 만들지 않는다


def test_anchor_outside_window_is_unmatched_not_error():
    events = _apache_events_with_spike()
    findings = run_investigation(events=events)["findings"]
    # Window를 아주 좁게 잡아 anchor가 제외되게 한다.
    narrow = make_scenario(
        "narrow", {"russellmitchell": (RM_T0, RM_T0 + timedelta(minutes=1))}
    )
    anchor = max(findings, key=lambda f: f.start_time)
    state = run_investigation(
        events=events, scenario_definition=narrow, investigation_focus=focus_on([anchor])
    )
    assert state["errors"] == {}  # Window 밖은 오류가 아니다
    projection = state["scenario_projection"]
    assert anchor.finding_id in projection.excluded_out_of_window
    assert state["incident_selection"].unmatched_anchor_finding_ids == (anchor.finding_id,)


# ---------------------------------------------------------------------------
# 10. correlation 입력이 findings 하나뿐
# ---------------------------------------------------------------------------


def test_security_findings_are_not_added_to_projection_input():
    events = _apache_events_with_spike()
    state = run_investigation(events=events, scenario_definition=SCENARIO)
    security_count = len(state["security_result"].findings)
    assert security_count > 0  # security Finding이 실제로 있다
    # projection에 들어간 Finding 수가 findings 수와 같다(security가 중복되지 않았다).
    projection = state["scenario_projection"]
    expected = len(state["findings"]) - len(projection.excluded_out_of_window)
    assert len(projection) == expected
    ids = [item.finding_id for item in projection]
    assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# 11~13. 불변성
# ---------------------------------------------------------------------------


def test_original_findings_are_not_modified_by_scenario_stage():
    events = _apache_events_with_spike()
    state = run_investigation(
        events=events,
        scenario_definition=SCENARIO,
        investigation_focus=None,
    )
    findings = state["findings"]
    before = [_fingerprint(f) for f in findings]
    # projection이 참조로 들고 있는 Finding이 원본과 같은 객체이고 바뀌지 않았다
    for item in state["scenario_projection"]:
        assert any(item.finding is f for f in findings)
    assert [_fingerprint(f) for f in findings] == before


def test_scenario_findings_are_frozen():
    state = run_investigation(
        events=_apache_events_with_spike(), scenario_definition=SCENARIO
    )
    item = state["scenario_projection"].findings[0]
    with pytest.raises(Exception):
        item.relative_start_seconds = 0.0  # type: ignore[misc]


def test_agent_results_are_unchanged_in_scenario_mode():
    events = _apache_events_with_spike()
    without = run_investigation(events=events)
    with_scenario = run_investigation(events=events, scenario_definition=SCENARIO)
    for key in (
        "application_result",
        "server_result",
        "network_result",
        "authentication_result",
        "security_result",
    ):
        a, b = without[key], with_scenario[key]
        if a is None:
            assert b is None
            continue
        assert a.status == b.status
        assert a.input_item_count == b.input_item_count
        assert a.skills_used == b.skills_used
        assert a.detectors_used == b.detectors_used
        assert a.notes == b.notes


# ---------------------------------------------------------------------------
# 14. 결정론
# ---------------------------------------------------------------------------


def test_scenario_mode_is_deterministic():
    events = _apache_events_with_spike()
    findings = run_investigation(events=events)["findings"]
    focus = focus_on([findings[0]])

    def run(ev):
        return run_investigation(
            events=ev, scenario_definition=SCENARIO, investigation_focus=focus
        )

    first = run(events)
    second = run(events)
    reversed_run = run(list(reversed(events)))

    for other in (second, reversed_run):
        assert first["scenario_projection"] == other["scenario_projection"]
        assert first["correlation_result"] == other["correlation_result"]
        assert first["incident_selection"] == other["incident_selection"]


# ---------------------------------------------------------------------------
# 9. error handling
# ---------------------------------------------------------------------------


def test_missing_dataset_window_is_recorded_as_error():
    """dataset Window 누락은 Window 밖 제외와 다르게 오류로 처리한다."""
    events = _apache_events_with_spike()  # russellmitchell 이벤트
    gaia_only = make_scenario("gaia-only", {"gaia": (GAIA_T0, GAIA_T0 + timedelta(hours=1))})
    state = run_investigation(events=events, scenario_definition=gaia_only)

    assert NODE_SCENARIO_PROJECTION in state["errors"]
    assert "MissingDatasetWindowError" in state["errors"][NODE_SCENARIO_PROJECTION]
    assert "Traceback" in state["errors"][NODE_SCENARIO_PROJECTION]
    assert state["scenario_projection"] is None
    # 앞 단계가 None이어도 뒤 node가 터지지 않는다
    assert state["correlation_result"] is None
    assert state["incident_selection"] is None
    # 탐지 결과는 그대로 남는다
    assert state["findings"]


def test_correlation_failure_is_recorded(monkeypatch):
    import orchestration.nodes as nodes

    def boom(projection):
        raise RuntimeError("correlation blew up")

    monkeypatch.setattr(nodes, "correlate_scenario", boom)
    state = run_investigation(
        events=_apache_events_with_spike(), scenario_definition=SCENARIO
    )
    assert NODE_EVIDENCE_CORRELATION in state["errors"]
    assert "correlation blew up" in state["errors"][NODE_EVIDENCE_CORRELATION]
    assert state["correlation_result"] is None
    assert state["scenario_projection"] is not None  # 앞 단계는 성공했다


def test_selection_failure_is_recorded(monkeypatch):
    import orchestration.nodes as nodes

    def boom(result, focus):
        raise RuntimeError("selection blew up")

    monkeypatch.setattr(nodes, "select_incidents", boom)
    events = _apache_events_with_spike()
    findings = run_investigation(events=events)["findings"]
    state = run_investigation(
        events=events,
        scenario_definition=SCENARIO,
        investigation_focus=focus_on([findings[0]]),
    )
    assert NODE_SELECT_INCIDENT in state["errors"]
    assert state["incident_selection"] is None


def test_programming_error_in_scenario_node_is_reraised(monkeypatch):
    import orchestration.nodes as nodes

    def boom(findings, scenario, **kwargs):
        raise AttributeError("typo")

    monkeypatch.setattr(nodes, "project_findings", boom)
    with pytest.raises(AttributeError):
        run_investigation(
            events=_apache_events_with_spike(), scenario_definition=SCENARIO
        )


def test_inconsistent_correlation_is_reraised(monkeypatch):
    """correlation invariant 위반(AssertionError 계열)은 errors에 숨기지 않는다."""
    import orchestration.nodes as nodes
    from correlation import InconsistentCorrelationError

    def boom(result, focus):
        raise InconsistentCorrelationError("finding in two incidents")

    monkeypatch.setattr(nodes, "select_incidents", boom)
    events = _apache_events_with_spike()
    findings = run_investigation(events=events)["findings"]
    with pytest.raises(InconsistentCorrelationError):
        run_investigation(
            events=events,
            scenario_definition=SCENARIO,
            investigation_focus=focus_on([findings[0]]),
        )


# ---------------------------------------------------------------------------
# cross-dataset
# ---------------------------------------------------------------------------


def test_cross_dataset_scenario_projects_both_datasets():
    events = _apache_events_with_spike() + _metric_events_with_spike()
    state = run_investigation(events=events, scenario_definition=BOTH_SCENARIO)
    assert state["errors"] == {}
    projection = state["scenario_projection"]
    datasets = {item.dataset for item in projection}
    assert datasets == {"russellmitchell", "gaia"}
    assert state["correlation_result"].datasets == ("gaia", "russellmitchell")


# ---------------------------------------------------------------------------
# 의존 방향 / public API 사용
# ---------------------------------------------------------------------------


def test_correlation_and_scenario_do_not_import_orchestration():
    offenders = []
    for directory in ("correlation", "scenario"):
        for path in (PROJECT_ROOT / directory).rglob("*.py"):
            if re.search(
                r"^\s*(from|import)\s+orchestration\b",
                path.read_text(encoding="utf-8"),
                re.MULTILINE,
            ):
                offenders.append(str(path.relative_to(PROJECT_ROOT)))
    assert offenders == []


def test_orchestration_uses_only_public_correlation_functions():
    text = (PROJECT_ROOT / "orchestration" / "nodes.py").read_text(encoding="utf-8")
    # correlation/scenario의 내부 함수(_로 시작)를 import하지 않는다
    assert not re.search(r"from (correlation|scenario)[\w.]* import [^\n]*\b_\w", text)
    assert "correlate_scenario" in text
    assert "project_findings" in text
    assert "select_incidents" in text
    # correlation 로직을 복사하지 않았다
    for internal in ("_build_edge", "_connected_components", "_temporal_relation", "_project_one"):
        assert internal not in text, internal
