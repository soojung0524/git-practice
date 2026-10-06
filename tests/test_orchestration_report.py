"""incident_report node의 LangGraph 연결 테스트."""

import re
from datetime import timedelta
from pathlib import Path

import pytest

from correlation import focus_on
from orchestration import (
    NODE_INCIDENT_REPORT,
    NODE_INTERPRET,
    NODE_SECURITY,
    NODE_SECURITY_GUIDANCE,
    NODE_SELECT_INCIDENT,
    build_graph,
    run_investigation,
)
from report import IncidentReport, NarrativeSummary, to_json
from scenario import make_scenario, utc
from tests.test_agent_skills import _apache_events_with_spike, _fingerprint

PROJECT_ROOT = Path(__file__).resolve().parent.parent

RM_T0 = utc(2022, 1, 21)
SCENARIO = make_scenario(
    "incident-001", {"russellmitchell": (RM_T0, RM_T0 + timedelta(hours=6))}
)


class FakeGuidanceProvider:
    def generate(self, question):
        from guidance import GuidanceResponse

        return GuidanceResponse(
            response="대응 절차입니다. [Page 94]", provider_name="fake", model="fake-model"
        )


class FakeSummaryProvider:
    def __init__(self, error=None):
        self.error = error
        self.prompts: list[str] = []

    def summarize(self, report_json: str) -> NarrativeSummary:
        self.prompts.append(report_json)
        if self.error is not None:
            raise self.error
        return NarrativeSummary(
            text="## 요약\n요약본", provider_name="fake", model="m", prompt=report_json
        )


def _run(**kwargs):
    return run_investigation(events=_apache_events_with_spike(), **kwargs)


# ---------------------------------------------------------------------------
# opt-in / 기존 호환성
# ---------------------------------------------------------------------------


def test_report_disabled_by_default():
    state = _run()
    assert state["incident_report"] is None
    nodes = {n for n in build_graph().get_graph().nodes if not n.startswith("__")}
    assert NODE_INCIDENT_REPORT not in nodes


def test_report_does_not_change_detection_results():
    baseline = _run()
    with_report = _run(build_report=True)
    assert [_fingerprint(f) for f in with_report["findings"]] == [
        _fingerprint(f) for f in baseline["findings"]
    ]
    for key in ("application_result", "security_result"):
        a, b = baseline[key], with_report[key]
        assert (a.status, a.input_item_count, a.notes) == (
            b.status,
            b.input_item_count,
            b.notes,
        )


def test_narrative_provider_requires_build_report():
    with pytest.raises(ValueError, match="build_report"):
        run_investigation(
            events=[], narrative_summary_provider=FakeSummaryProvider()
        )
    with pytest.raises(ValueError, match="build_report"):
        build_graph(narrative_summary_provider=FakeSummaryProvider())


# ---------------------------------------------------------------------------
# graph topology
# ---------------------------------------------------------------------------


def test_report_node_sits_after_guidance_and_before_interpretation():
    graph = build_graph(
        scenario=True,
        interpret=True,
        security_guidance_provider=FakeGuidanceProvider(),
        build_report=True,
    )
    edges = {(e.source, e.target) for e in graph.get_graph().edges}
    assert (NODE_SELECT_INCIDENT, NODE_SECURITY_GUIDANCE) in edges
    assert (NODE_SECURITY_GUIDANCE, NODE_INCIDENT_REPORT) in edges
    assert (NODE_INCIDENT_REPORT, NODE_INTERPRET) in edges
    assert (NODE_INTERPRET, "__end__") in edges
    # fan-out 없음
    assert (NODE_INCIDENT_REPORT, "__end__") not in edges
    assert (NODE_SECURITY_GUIDANCE, "__end__") not in edges


def test_report_node_goes_to_end_alone():
    graph = build_graph(build_report=True)
    edges = {(e.source, e.target) for e in graph.get_graph().edges}
    assert (NODE_SECURITY, NODE_INCIDENT_REPORT) in edges
    assert (NODE_INCIDENT_REPORT, "__end__") in edges
    assert (NODE_SECURITY, "__end__") not in edges


# ---------------------------------------------------------------------------
# real / scenario mode
# ---------------------------------------------------------------------------


def test_real_mode_report_in_state():
    state = _run(build_report=True)
    report = state["incident_report"]
    assert isinstance(report, IncidentReport)
    assert report.generated_from == "real"
    assert report.investigation_id == state["investigation_id"]
    assert report.correlation is None
    assert report.findings.total_count == len(state["findings"])


def test_scenario_mode_report_in_state():
    findings = _run()["findings"]
    state = _run(
        scenario_definition=SCENARIO,
        investigation_focus=focus_on([findings[0]]),
        build_report=True,
    )
    report = state["incident_report"]
    assert report.generated_from == "scenario"
    assert report.scenario_id == "incident-001"
    assert report.incident_id == state["incident_selection"].focused_incident_ids[0]
    assert report.correlation is not None
    assert report.impact is not None


def test_report_includes_guidance_when_present():
    findings = _run()["findings"]
    state = _run(
        scenario_definition=SCENARIO,
        investigation_focus=focus_on([findings[0]]),
        security_guidance_provider=FakeGuidanceProvider(),
        build_report=True,
    )
    section = state["incident_report"].security_guidance
    assert section is not None
    assert len(section.items) == 1
    assert "[Page 94]" in section.items[0].response


def test_report_dedup_counts_match_state():
    state = _run(build_report=True)
    stats = state["incident_report"].agent_statistics
    assert stats.collected_findings_count == len(state["agent_findings"])
    assert stats.deduplicated_findings_count == len(state["findings"])


def test_report_limitations_include_errors_from_state():
    events = _apache_events_with_spike()
    gaia_only = make_scenario(
        "gaia-only", {"gaia": (utc(2021, 7, 1), utc(2021, 7, 2))}
    )
    state = run_investigation(
        events=events, scenario_definition=gaia_only, build_report=True
    )
    assert "scenario_projection" in state["errors"]
    report = state["incident_report"]
    assert "scenario_projection" in report.limitations.errors
    # 앞 단계 실패에도 결정론적 섹션은 채워진다
    assert report.findings.total_count == len(state["findings"])
    assert report.generated_from == "real"  # projection이 없어 scenario_id가 없다


# ---------------------------------------------------------------------------
# narrative summary
# ---------------------------------------------------------------------------


def test_narrative_summary_attached_when_provider_given():
    provider = FakeSummaryProvider()
    state = _run(build_report=True, narrative_summary_provider=provider)
    report = state["incident_report"]
    assert report.narrative_summary is not None
    assert report.narrative_summary.text == "## 요약\n요약본"
    assert len(provider.prompts) == 1
    assert state["errors"] == {}


def test_summary_failure_preserves_deterministic_report():
    provider = FakeSummaryProvider(error=RuntimeError("openai down"))
    state = _run(build_report=True, narrative_summary_provider=provider)
    report = state["incident_report"]
    assert report is not None  # 결정론적 보고서는 보존된다
    assert report.narrative_summary is None
    assert NODE_INCIDENT_REPORT in state["errors"]
    assert "결정론적 보고서는 보존된다" in state["errors"][NODE_INCIDENT_REPORT]
    assert report.findings.total_count == len(state["findings"])


def test_programming_error_in_summary_is_reraised():
    provider = FakeSummaryProvider(error=AttributeError("typo"))
    with pytest.raises(AttributeError):
        _run(build_report=True, narrative_summary_provider=provider)


def test_report_without_provider_has_no_summary():
    state = _run(build_report=True)
    assert state["incident_report"].narrative_summary is None


# ---------------------------------------------------------------------------
# 결정론
# ---------------------------------------------------------------------------


def test_report_json_is_deterministic_across_runs():
    events = _apache_events_with_spike()
    first = run_investigation(
        events=events, investigation_id="fixed", build_report=True
    )["incident_report"]
    second = run_investigation(
        events=list(reversed(events)), investigation_id="fixed", build_report=True
    )["incident_report"]
    assert to_json(first) == to_json(second)
    assert first.report_id == second.report_id


# ---------------------------------------------------------------------------
# 계층
# ---------------------------------------------------------------------------


def test_report_package_does_not_import_orchestration():
    offenders = []
    for path in (PROJECT_ROOT / "report").rglob("*.py"):
        if re.search(
            r"^\s*(from|import)\s+orchestration\b",
            path.read_text(encoding="utf-8"),
            re.MULTILINE,
        ):
            offenders.append(path.name)
    assert offenders == []


def test_orchestration_passes_individual_arguments_not_state():
    text = (PROJECT_ROOT / "orchestration" / "nodes.py").read_text(encoding="utf-8")
    # build_incident_report에 state를 통째로 넘기지 않는다
    assert "build_incident_report(state" not in text
    assert "investigation_id=state[" in text
    assert "findings=state[" in text
