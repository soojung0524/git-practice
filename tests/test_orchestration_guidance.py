"""Security Guidance의 LangGraph 연결 테스트.

실제 OpenAI/Supabase를 호출하지 않는다. fake provider만 주입한다.
"""

import re
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from correlation import InvestigationFocus, focus_on
from guidance import GuidanceResponse, SecurityGuidanceResult
from orchestration import (
    NODE_INTERPRET,
    NODE_SECURITY_GUIDANCE,
    NODE_SELECT_INCIDENT,
    build_graph,
    run_investigation,
)
from scenario import make_scenario, utc
from tests.test_agent_skills import (
    _apache_events_with_spike,
    _fingerprint,
    _metric_events_with_spike,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

RM_T0 = utc(2022, 1, 21)
SCENARIO = make_scenario(
    "incident-001", {"russellmitchell": (RM_T0, RM_T0 + timedelta(hours=6))}
)

# 서로 다른 incident 2개를 만들려면 dataset이 다른 Finding을 쓴다. 같은 dataset의
# apache Finding들은 같은 로그 줄을 evidence로 공유해(shared_evidence) 한 incident로
# 묶이기 때문이다.
GAIA_T0 = utc(2021, 7, 1)
BOTH_SCENARIO = make_scenario(
    "incident-both",
    {
        "russellmitchell": (RM_T0, RM_T0 + timedelta(hours=6)),
        "gaia": (GAIA_T0, GAIA_T0 + timedelta(hours=12)),
    },
)
BOTH_EVENTS = _apache_events_with_spike() + _metric_events_with_spike()


def _two_incident_anchors():
    """서로 다른 incident에 속하는 anchor 2개와 그 입력 이벤트를 돌려준다."""
    findings = run_investigation(events=BOTH_EVENTS)["findings"]
    rm = next(f for f in findings if f.dataset == "russellmitchell")
    gaia = next(f for f in findings if f.dataset == "gaia")
    return BOTH_EVENTS, [rm, gaia]

_RAG_MODULE_PREFIXES = ("rag", "langchain", "langchain_openai", "supabase")


class FakeProvider:
    """complete한 provider 경계만 만족하는 fake. 네트워크를 쓰지 않는다."""

    def __init__(self, response="## 요약\n확인했습니다. [Page 94]", error=None):
        self.response = response
        self.error = error
        self.questions: list[str] = []

    def generate(self, question: str) -> GuidanceResponse:
        self.questions.append(question)
        if self.error is not None:
            raise self.error
        return GuidanceResponse(
            response=self.response, provider_name="fake", model="fake-model"
        )


class SelectiveFailProvider:
    """특정 호출 순번만 실패시키는 fake (partial failure 검증용)."""

    def __init__(self, fail_on_call_indexes):
        self.fail_on = set(fail_on_call_indexes)
        self.questions: list[str] = []

    def generate(self, question: str) -> GuidanceResponse:
        index = len(self.questions)
        self.questions.append(question)
        if index in self.fail_on:
            raise RuntimeError(f"call {index} 실패")
        return GuidanceResponse(response=f"응답 {index} [Page 1]", provider_name="fake")


def _findings():
    return run_investigation(events=_apache_events_with_spike())["findings"]


def _run(**kwargs):
    return run_investigation(events=_apache_events_with_spike(), **kwargs)


# ---------------------------------------------------------------------------
# provider=None → 기존 workflow 동일 + lazy import 유지
# ---------------------------------------------------------------------------


def test_provider_none_keeps_existing_workflow():
    without = _run()
    assert without["security_guidance"] is None
    assert NODE_SECURITY_GUIDANCE not in {
        n for n in build_graph().get_graph().nodes if not n.startswith("__")
    }


def test_provider_none_does_not_change_findings_or_agent_results():
    baseline = _run()
    scenario_only = _run(scenario_definition=SCENARIO)
    assert [_fingerprint(f) for f in scenario_only["findings"]] == [
        _fingerprint(f) for f in baseline["findings"]
    ]
    for key in (
        "application_result",
        "server_result",
        "network_result",
        "authentication_result",
        "security_result",
    ):
        a, b = baseline[key], scenario_only[key]
        if a is None:
            assert b is None
            continue
        assert (a.status, a.input_item_count, a.skills_used, a.detectors_used, a.notes) == (
            b.status,
            b.input_item_count,
            b.skills_used,
            b.detectors_used,
            b.notes,
        )


def test_rag_modules_are_not_imported_when_guidance_disabled():
    for name in [n for n in sys.modules if n.split(".")[0] in _RAG_MODULE_PREFIXES]:
        del sys.modules[name]
    _run(scenario_definition=SCENARIO)
    leaked = sorted(
        n for n in sys.modules if n.split(".")[0] in _RAG_MODULE_PREFIXES
    )
    assert leaked == [], f"RAG 모듈이 로드됐다: {leaked}"


def test_guidance_disabled_works_without_supabase_url(monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    state = _run(scenario_definition=SCENARIO)
    assert state["errors"] == {}
    assert state["security_guidance"] is None
    assert state["correlation_result"] is not None


# ---------------------------------------------------------------------------
# graph topology
# ---------------------------------------------------------------------------


def test_guidance_node_sits_between_selection_and_interpretation():
    graph = build_graph(
        scenario=True, interpret=True, security_guidance_provider=FakeProvider()
    )
    edges = {(e.source, e.target) for e in graph.get_graph().edges}
    assert (NODE_SELECT_INCIDENT, NODE_SECURITY_GUIDANCE) in edges
    assert (NODE_SECURITY_GUIDANCE, NODE_INTERPRET) in edges
    assert (NODE_INTERPRET, "__end__") in edges
    # fan-out 없음
    assert (NODE_SELECT_INCIDENT, "__end__") not in edges
    assert (NODE_SECURITY_GUIDANCE, "__end__") not in edges


def test_guidance_node_goes_to_end_without_interpret():
    graph = build_graph(scenario=True, security_guidance_provider=FakeProvider())
    edges = {(e.source, e.target) for e in graph.get_graph().edges}
    assert (NODE_SECURITY_GUIDANCE, "__end__") in edges
    assert (NODE_SELECT_INCIDENT, "__end__") not in edges


def test_provider_without_scenario_is_rejected():
    with pytest.raises(ValueError, match="scenario"):
        build_graph(scenario=False, security_guidance_provider=FakeProvider())
    with pytest.raises(ValueError, match="scenario_definition"):
        run_investigation(events=[], security_guidance_provider=FakeProvider())


def test_provider_is_not_stored_in_state():
    provider = FakeProvider()
    findings = _findings()
    state = _run(
        scenario_definition=SCENARIO,
        investigation_focus=focus_on([findings[0]]),
        security_guidance_provider=provider,
    )
    assert "security_guidance_provider" not in state
    for value in state.values():
        assert value is not provider


# ---------------------------------------------------------------------------
# 호출 횟수
# ---------------------------------------------------------------------------


def test_single_focused_incident_calls_provider_once():
    provider = FakeProvider()
    findings = _findings()
    state = _run(
        scenario_definition=SCENARIO,
        investigation_focus=focus_on([findings[0]]),
        security_guidance_provider=provider,
    )
    assert len(provider.questions) == 1
    result = state["security_guidance"]
    assert isinstance(result, SecurityGuidanceResult)
    assert len(result.guidance) == 1
    assert result.failed_incident_ids == ()


def test_two_focused_incidents_call_provider_twice():
    provider = FakeProvider()
    events, anchors = _two_incident_anchors()
    state = run_investigation(
        events=events,
        scenario_definition=BOTH_SCENARIO,
        investigation_focus=focus_on(anchors),
        security_guidance_provider=provider,
    )
    selection = state["incident_selection"]
    assert len(selection.focused_incident_ids) == 2
    assert len(provider.questions) == 2
    assert len(state["security_guidance"].guidance) == 2
    # 각 질문은 incident 하나만 다룬다(여러 incident를 섞지 않는다)
    for question, incident_id in zip(provider.questions, selection.focused_incident_ids):
        assert incident_id in question


def test_focus_none_makes_zero_provider_calls():
    provider = FakeProvider()
    state = _run(scenario_definition=SCENARIO, security_guidance_provider=provider)
    assert state["incident_selection"] is None
    assert provider.questions == []
    assert state["security_guidance"] is None


def test_unmatched_anchors_only_makes_zero_provider_calls():
    provider = FakeProvider()
    state = _run(
        scenario_definition=SCENARIO,
        investigation_focus=InvestigationFocus(anchor_finding_ids=("does-not-exist",)),
        security_guidance_provider=provider,
    )
    selection = state["incident_selection"]
    assert selection.focused_incident_ids == ()
    assert selection.unmatched_anchor_finding_ids == ("does-not-exist",)
    assert provider.questions == []
    assert state["security_guidance"] is None


def test_empty_selection_makes_zero_provider_calls():
    provider = FakeProvider()
    narrow = make_scenario(
        "narrow", {"russellmitchell": (RM_T0, RM_T0 + timedelta(seconds=1))}
    )
    findings = _findings()
    state = _run(
        scenario_definition=narrow,
        investigation_focus=focus_on([findings[0]]),
        security_guidance_provider=provider,
    )
    assert state["incident_selection"].focused_incident_ids == ()
    assert provider.questions == []
    assert state["security_guidance"] is None


# ---------------------------------------------------------------------------
# 질문 내용 / 결과 매핑
# ---------------------------------------------------------------------------


def test_question_passed_to_provider_contains_only_focused_incident():
    provider = FakeProvider()
    findings = _findings()
    anchor = findings[0]
    state = _run(
        scenario_definition=SCENARIO,
        investigation_focus=focus_on([anchor]),
        security_guidance_provider=provider,
    )
    selection = state["incident_selection"]
    focused_id = selection.focused_incident_ids[0]
    focused = state["correlation_result"].incident_by_id(focused_id)

    question = provider.questions[0]
    assert focused_id in question
    # 선택되지 않은 incident의 id가 질문에 없다
    for incident in state["correlation_result"].incidents:
        if incident.incident_id != focused_id:
            assert incident.incident_id not in question


def test_guidance_is_mapped_to_correct_incident_id():
    provider = SelectiveFailProvider(fail_on_call_indexes=())
    events, anchors = _two_incident_anchors()
    state = run_investigation(
        events=events,
        scenario_definition=BOTH_SCENARIO,
        investigation_focus=focus_on(anchors),
        security_guidance_provider=provider,
    )
    selection = state["incident_selection"]
    result = state["security_guidance"]
    # canonical 순서대로 호출되고, 각 guidance가 올바른 incident_id와 연결된다
    assert [g.incident_id for g in result.guidance] == list(selection.focused_incident_ids)
    for guidance in result.guidance:
        assert guidance.incident_id in guidance.question


def test_page_citation_survives_in_state():
    provider = FakeProvider(response="결론.\n\n근거 [Page 94 | 섹션: Containment] 내용")
    findings = _findings()
    state = _run(
        scenario_definition=SCENARIO,
        investigation_focus=focus_on([findings[0]]),
        security_guidance_provider=provider,
    )
    stored = state["security_guidance"].guidance[0].response
    assert stored == provider.response  # 요약·재작성 없음
    assert "[Page 94" in stored


def test_provider_metadata_is_recorded():
    provider = FakeProvider()
    findings = _findings()
    state = _run(
        scenario_definition=SCENARIO,
        investigation_focus=focus_on([findings[0]]),
        security_guidance_provider=provider,
    )
    guidance = state["security_guidance"].guidance[0]
    assert guidance.provider_name == "fake"
    assert guidance.model == "fake-model"


# ---------------------------------------------------------------------------
# error handling
# ---------------------------------------------------------------------------


def test_all_incidents_failing_records_error_and_leaves_guidance_none():
    provider = FakeProvider(error=RuntimeError("supabase down"))
    findings = _findings()
    state = _run(
        scenario_definition=SCENARIO,
        investigation_focus=focus_on([findings[0]]),
        security_guidance_provider=provider,
    )
    assert NODE_SECURITY_GUIDANCE in state["errors"]
    assert "supabase down" in state["errors"][NODE_SECURITY_GUIDANCE]
    assert "Traceback" in state["errors"][NODE_SECURITY_GUIDANCE]
    assert state["security_guidance"] is None
    # 실패한 incident 목록은 selection에서 복구할 수 있다
    assert state["incident_selection"].focused_incident_ids


def test_provider_failure_preserves_earlier_results():
    provider = FakeProvider(error=RuntimeError("openai down"))
    findings = _findings()
    state = _run(
        scenario_definition=SCENARIO,
        investigation_focus=focus_on([findings[0]]),
        security_guidance_provider=provider,
    )
    assert state["findings"]
    assert state["scenario_projection"] is not None
    assert state["correlation_result"] is not None
    assert state["incident_selection"] is not None
    assert state["security_result"] is not None


def test_partial_failure_keeps_successful_guidance():
    provider = SelectiveFailProvider(fail_on_call_indexes=(1,))
    events, anchors = _two_incident_anchors()
    state = run_investigation(
        events=events,
        scenario_definition=BOTH_SCENARIO,
        investigation_focus=focus_on(anchors),
        security_guidance_provider=provider,
    )
    result = state["security_guidance"]
    assert result is not None
    assert len(result.guidance) == 1
    assert len(result.failed_incident_ids) == 1
    assert result.has_failures
    assert NODE_SECURITY_GUIDANCE in state["errors"]
    assert any("실패했다" in note for note in result.notes)


def test_unexpected_rag_response_is_recorded_not_raised():
    from guidance import UnexpectedRagResponseError

    provider = FakeProvider(error=UnexpectedRagResponseError("구조가 다르다"))
    findings = _findings()
    state = _run(
        scenario_definition=SCENARIO,
        investigation_focus=focus_on([findings[0]]),
        security_guidance_provider=provider,
    )
    assert NODE_SECURITY_GUIDANCE in state["errors"]
    assert state["security_guidance"] is None


def test_programming_error_in_provider_is_reraised():
    provider = FakeProvider(error=AttributeError("typo"))
    findings = _findings()
    with pytest.raises(AttributeError):
        _run(
            scenario_definition=SCENARIO,
            investigation_focus=focus_on([findings[0]]),
            security_guidance_provider=provider,
        )


def test_import_error_from_provider_is_reraised():
    provider = FakeProvider(error=ModuleNotFoundError("No module named 'langchain'"))
    findings = _findings()
    with pytest.raises(ModuleNotFoundError):
        _run(
            scenario_definition=SCENARIO,
            investigation_focus=focus_on([findings[0]]),
            security_guidance_provider=provider,
        )


# ---------------------------------------------------------------------------
# determinism (RAG 응답 문자열은 제외)
# ---------------------------------------------------------------------------


def test_questions_are_deterministic_across_runs():
    findings = _findings()
    focus = focus_on([findings[0]])
    first, second = FakeProvider(), FakeProvider()
    _run(
        scenario_definition=SCENARIO,
        investigation_focus=focus,
        security_guidance_provider=first,
    )
    _run(
        scenario_definition=SCENARIO,
        investigation_focus=focus,
        security_guidance_provider=second,
    )
    assert first.questions == second.questions


def test_questions_identical_when_event_order_reversed():
    events = _apache_events_with_spike()
    findings = run_investigation(events=events)["findings"]
    focus = focus_on([findings[0]])
    forward, reverse = FakeProvider(), FakeProvider()
    run_investigation(
        events=events,
        scenario_definition=SCENARIO,
        investigation_focus=focus,
        security_guidance_provider=forward,
    )
    run_investigation(
        events=list(reversed(events)),
        scenario_definition=SCENARIO,
        investigation_focus=focus,
        security_guidance_provider=reverse,
    )
    assert forward.questions == reverse.questions


# ---------------------------------------------------------------------------
# SecurityAgent 역할 유지
# ---------------------------------------------------------------------------


def test_existing_security_agent_behaviour_unchanged():
    provider = FakeProvider()
    findings = _findings()
    baseline = _run()
    with_guidance = _run(
        scenario_definition=SCENARIO,
        investigation_focus=focus_on([findings[0]]),
        security_guidance_provider=provider,
    )
    a, b = baseline["security_result"], with_guidance["security_result"]
    assert a.status == b.status
    assert a.detectors_used == b.detectors_used == ()
    assert [f.finding_id for f in a.findings] == [f.finding_id for f in b.findings]
    assert all(f.category == "security" for f in b.findings)


def test_guidance_does_not_modify_findings():
    provider = FakeProvider()
    events = _apache_events_with_spike()
    findings = run_investigation(events=events)["findings"]
    before = [_fingerprint(f) for f in findings]
    state = _run(
        scenario_definition=SCENARIO,
        investigation_focus=focus_on([findings[0]]),
        security_guidance_provider=provider,
    )
    assert [_fingerprint(f) for f in state["findings"]] == before


# ---------------------------------------------------------------------------
# 계층
# ---------------------------------------------------------------------------


def test_guidance_does_not_import_orchestration():
    offenders = []
    for path in (PROJECT_ROOT / "guidance").rglob("*.py"):
        if re.search(
            r"^\s*(from|import)\s+orchestration\b",
            path.read_text(encoding="utf-8"),
            re.MULTILINE,
        ):
            offenders.append(path.name)
    assert offenders == []


def test_guidance_does_not_use_ground_truth():
    for path in (PROJECT_ROOT / "guidance").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "ground_truth" not in text.lower()
        assert not re.search(r"^\s*(from|import)\s+evaluation\b", text, re.MULTILINE)
