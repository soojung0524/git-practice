"""Security Guidance 단독 테스트 (question builder / provider 경계).

실제 OpenAI/Supabase를 호출하지 않는다. fake provider만 쓴다.
"""

import re
from datetime import timedelta
from pathlib import Path

import pytest

from correlation import correlate_scenario, focus_on, select_incidents
from guidance import (
    DEFAULT_MAX_TIMELINE_ENTRIES,
    GuidanceResponse,
    IncidentSecurityGuidance,
    RagSecurityGuidanceProvider,
    SecurityGuidanceProvider,
    SecurityGuidanceResult,
    UnexpectedRagResponseError,
    build_security_guidance_question,
    extract_response_text,
)
from scenario import make_scenario, project_findings, utc
from src.models import Finding

PROJECT_ROOT = Path(__file__).resolve().parent.parent

W_START = utc(2021, 7, 31, 19, 0)
W_END = utc(2021, 7, 31, 20, 0)
SCENARIO = make_scenario("net-2021-07-31", {"gaia": (W_START, W_END)})


def _finding(
    *,
    finding_id,
    offset_seconds=0,
    duration_seconds=210,
    category="network",
    finding_type="network_usage_anomaly",
    severity="low",
    host=None,
    service="dbservice1",
    entities=None,
):
    start = W_START + timedelta(seconds=offset_seconds)
    return Finding(
        finding_id=finding_id,
        dataset="gaia",
        category=category,
        finding_type=finding_type,
        start_time=start,
        end_time=start + timedelta(seconds=duration_seconds),
        host=host,
        service=service,
        severity=severity,
        summary=f"{finding_type} 요약",
        metrics={"observed_max": 578.4, "baseline_p99": 20.7},
        evidence=[],
        entities={"service": [service]} if entities is None else dict(entities),
        detector="find_metric_anomaly",
    )


def _incident(findings):
    result = correlate_scenario(project_findings(findings, SCENARIO))
    return result, result.incidents[0]


# ---------------------------------------------------------------------------
# question builder
# ---------------------------------------------------------------------------


def test_question_contains_observed_incident_facts():
    _, incident = _incident([_finding(finding_id="net1", offset_seconds=600)])
    question = build_security_guidance_question(incident)

    assert incident.incident_id in question
    assert "net-2021-07-31" in question
    assert "gaia" in question
    assert "network_usage_anomaly" in question
    assert "dbservice1" in question
    assert "T+600s" in question
    assert "2021-07-31T19:10:00+00:00" in question  # 원본 절대시각
    assert "## 요청" in question


def test_question_is_deterministic():
    findings = [
        _finding(finding_id="a", offset_seconds=600),
        _finding(finding_id="b", offset_seconds=630),
    ]
    _, incident = _incident(findings)
    assert build_security_guidance_question(incident) == build_security_guidance_question(
        incident
    )


def test_question_identical_when_input_finding_order_reversed():
    findings = [
        _finding(finding_id="a", offset_seconds=600),
        _finding(finding_id="b", offset_seconds=630),
    ]
    _, forward = _incident(findings)
    _, reverse = _incident(list(reversed(findings)))
    assert build_security_guidance_question(forward) == build_security_guidance_question(
        reverse
    )


def test_question_excludes_ground_truth_terms():
    _, incident = _incident([_finding(finding_id="net1", offset_seconds=600)])
    question = build_security_guidance_question(incident)
    for forbidden in ("ground_truth", "Ground Truth", "labels/", "run_table", "정답"):
        assert forbidden not in question, forbidden


def test_question_only_contains_observed_entities():
    _, incident = _incident(
        [_finding(finding_id="net1", offset_seconds=600, service="dbservice1")]
    )
    question = build_security_guidance_question(incident)
    assert "dbservice1" in question
    # 입력에 없는 대상이 질문에 등장하지 않는다
    for absent in ("webservice2", "redis", "intranet_server", "172.19.131.174"):
        assert absent not in question, absent
    # user entity를 내보내는 detector가 없으므로 해당 줄 자체가 없다
    assert "관측된 사용자" not in question


def test_question_omits_empty_entity_lines():
    _, incident = _incident([_finding(finding_id="net1", offset_seconds=600, host=None)])
    question = build_security_guidance_question(incident)
    assert "관측된 host" not in question  # host=None이므로 줄이 없다
    assert "관측된 IP" not in question


def test_question_timeline_is_capped_and_reports_omitted_count():
    findings = [
        _finding(finding_id=f"f{i:02d}", offset_seconds=600 + i * 30, duration_seconds=20)
        for i in range(15)
    ]
    _, incident = _incident(findings)
    assert incident.finding_count == 15
    question = build_security_guidance_question(incident, max_timeline_entries=10)
    timeline_lines = re.findall(r"^- T\+", question, re.MULTILINE)
    assert len(timeline_lines) == 10
    assert "나머지 5건은 분량 때문에 생략" in question
    assert "관측된 Finding 수: 15" in question  # 집계는 전체 기준


def test_question_default_timeline_cap():
    assert DEFAULT_MAX_TIMELINE_ENTRIES == 10


def test_question_rejects_invalid_cap():
    _, incident = _incident([_finding(finding_id="a", offset_seconds=600)])
    with pytest.raises(ValueError):
        build_security_guidance_question(incident, max_timeline_entries=0)


def test_question_states_no_hypothesis_when_none():
    _, incident = _incident([_finding(finding_id="net1", offset_seconds=600)])
    assert incident.hypotheses == ()
    question = build_security_guidance_question(incident)
    assert "가설 후보" in question
    assert "없음" in question


def test_question_includes_hypothesis_statement_when_present():
    findings = [
        _finding(finding_id="net", offset_seconds=600),
        _finding(
            finding_id="lat",
            offset_seconds=630,
            category="performance",
            finding_type="service_latency_spike",
        ),
    ]
    _, incident = _incident(findings)
    assert incident.hypotheses
    question = build_security_guidance_question(incident)
    assert "network_related_degradation" in question
    assert "인과관계는 확인되지 않았다" in question


def test_question_includes_long_span_and_clipped_caveats():
    # Window(3600초)의 절반을 넘는 Finding이고, Window 경계를 걸친다.
    long_clipped = _finding(
        finding_id="long", offset_seconds=-600, duration_seconds=3000
    )
    _, incident = _incident([long_clipped])
    question = build_security_guidance_question(incident)
    assert "해석 시 주의" in question
    assert "장기간" in question
    assert "잘렸다" in question


def test_question_does_not_claim_root_cause():
    _, incident = _incident([_finding(finding_id="net1", offset_seconds=600)])
    question = build_security_guidance_question(incident)
    assert "근본 원인은 확정되지 않았습니다" in question
    for forbidden in ("원인이다", "때문에 발생했다", "root cause가 확인"):
        assert forbidden not in question


def test_question_does_not_include_unrelated_incident():
    """같은 Window의 무관한 incident가 질문에 들어가지 않는다."""
    anchor = _finding(finding_id="net", offset_seconds=600, service="dbservice1")
    other_a = _finding(
        finding_id="lat1",
        offset_seconds=1800,
        category="performance",
        finding_type="service_latency_spike",
        service="webservice2",
        entities={"service": ["webservice2"]},
    )
    other_b = _finding(
        finding_id="lat2",
        offset_seconds=1830,
        category="performance",
        finding_type="service_latency_spike",
        service="webservice2",
        entities={"service": ["webservice2"]},
    )
    result = correlate_scenario(project_findings([anchor, other_a, other_b], SCENARIO))
    selection = select_incidents(result, focus_on([anchor]))
    assert len(selection.focused_incident_ids) == 1

    incident = result.incident_by_id(selection.focused_incident_ids[0])
    question = build_security_guidance_question(incident)
    assert "net" in question
    assert "webservice2" not in question
    assert "lat1" not in question and "lat2" not in question


# ---------------------------------------------------------------------------
# provider 경계 / 응답 추출
# ---------------------------------------------------------------------------


class FakeProvider:
    def __init__(self, response="## 요약\n확인 결과입니다. [Page 94]", error=None):
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


def test_fake_provider_satisfies_protocol():
    assert isinstance(FakeProvider(), SecurityGuidanceProvider)
    assert isinstance(RagSecurityGuidanceProvider(), SecurityGuidanceProvider)


def test_extract_response_text_from_string_content():
    class Message:
        content = "답변 [Page 12]"

    assert extract_response_text({"messages": [Message()]}) == "답변 [Page 12]"


def test_extract_response_text_from_content_blocks():
    class Message:
        content = [
            {"type": "text", "text": "앞부분 "},
            {"type": "reasoning", "summary": "무시"},
            {"type": "text", "text": "[Page 7]"},
        ]

    assert extract_response_text({"messages": [Message()]}) == "앞부분 [Page 7]"


def test_extract_response_text_from_dict_message():
    assert extract_response_text({"messages": [{"content": "ok"}]}) == "ok"


@pytest.mark.parametrize(
    "payload",
    [
        "문자열",
        {"messages": []},
        {"other": 1},
        {"messages": [object()]},
        {"messages": [{"content": [{"type": "reasoning"}]}]},
    ],
)
def test_extract_response_text_rejects_unexpected_structures(payload):
    with pytest.raises(UnexpectedRagResponseError):
        extract_response_text(payload)


def test_unexpected_response_error_is_not_programming_error():
    # orchestration이 errors에 기록하고 계속할 수 있어야 한다.
    assert not issubclass(UnexpectedRagResponseError, (AssertionError, TypeError, AttributeError))
    assert issubclass(UnexpectedRagResponseError, RuntimeError)


def test_rag_provider_does_not_import_rag_on_construction():
    import sys

    for name in list(sys.modules):
        if name.split(".")[0] in ("rag",):
            del sys.modules[name]
    RagSecurityGuidanceProvider()
    assert not any(name.split(".")[0] == "rag" for name in sys.modules)


# ---------------------------------------------------------------------------
# 결과 모델
# ---------------------------------------------------------------------------


def test_guidance_result_helpers():
    item = IncidentSecurityGuidance(
        incident_id="i1",
        question="q",
        response="r [Page 3]",
        provider_name="fake",
        model="m",
    )
    result = SecurityGuidanceResult(
        focused_incident_ids=("i1", "i2"),
        guidance=(item,),
        failed_incident_ids=("i2",),
    )
    assert not result.is_empty
    assert result.has_failures
    assert result.guidance_for("i1") is item
    assert result.guidance_for("i2") is None


def test_page_citation_is_preserved_verbatim():
    response = "결론입니다.\n\n근거: [Page 94 | 섹션: Containment] 내용"
    item = IncidentSecurityGuidance(
        incident_id="i1", question="q", response=response, provider_name="fake"
    )
    assert item.response == response  # 요약·재작성하지 않는다
    assert "[Page 94" in item.response


# ---------------------------------------------------------------------------
# 계층 분리 / lazy import
# ---------------------------------------------------------------------------


def test_guidance_modules_do_not_import_rag_at_module_level():
    for name in ("__init__.py", "models.py", "question.py", "provider.py"):
        text = (PROJECT_ROOT / "guidance" / name).read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")) and not line.startswith(" " * 8):
                assert "rag" not in stripped.split()[1].split(".")[0], f"{name}: {stripped}"
                for forbidden in ("langchain", "supabase", "openai"):
                    assert forbidden not in stripped, f"{name}: {stripped}"


def test_orchestration_does_not_import_rag_modules():
    for name in ("state.py", "nodes.py", "graph.py", "__init__.py"):
        text = (PROJECT_ROOT / "orchestration" / name).read_text(encoding="utf-8")
        assert not re.search(r"^\s*(from|import)\s+rag\b", text, re.MULTILINE), name
        assert not re.search(r"^\s*(from|import)\s+\S*langchain", text, re.MULTILINE), name
        assert not re.search(r"^\s*(from|import)\s+supabase", text, re.MULTILINE), name


def test_ingest_pdf_is_never_imported_by_runtime():
    offenders = []
    for directory in ("orchestration", "guidance", "correlation", "scenario", "agents", "src"):
        for path in (PROJECT_ROOT / directory).rglob("*.py"):
            if "ingest_pdf" in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(PROJECT_ROOT)))
    assert offenders == []


def test_importing_rag_package_does_not_load_rag_tool_or_clients():
    """rag 패키지 import만으로 Supabase/OpenAI 클라이언트가 만들어지지 않는다.

    rag/__init__.py가 아무것도 import하지 않기 때문이다(docstring의 예시 코드는
    실행되지 않는다). 텍스트 검사보다 실제 동작으로 확인한다.
    """
    import importlib
    import sys

    for name in [n for n in sys.modules if n.split(".")[0] == "rag"]:
        del sys.modules[name]

    importlib.import_module("rag")
    loaded = {n for n in sys.modules if n.startswith("rag.")}
    assert loaded == set(), f"rag import만으로 하위 모듈이 로드됐다: {loaded}"


def test_rag_agent_uses_rag_package_import():
    text = (PROJECT_ROOT / "rag" / "rag_agent.py").read_text(encoding="utf-8")
    assert "from rag.rag_tool import search_runbook" in text
    assert "from src.tools.rag_tool" not in text
