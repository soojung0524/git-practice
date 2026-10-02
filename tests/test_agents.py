"""Agent 계층 독립 테스트.

검증 초점은 "Agent가 자기 Skill을 호출하고 Finding을 그대로 전달한다"다.
detector의 탐지 정확도와 Skill의 필터링은 각각 tests/test_apache_traffic.py,
tests/test_agent_skills.py에서 이미 검증한다.
"""

import re
from pathlib import Path

import pytest

from agent_skills.application_analysis.scripts.run_application_analysis import (
    run_application_analysis,
)
from agent_skills.network_analysis.scripts.run_network_analysis import (
    run_network_analysis,
)
from agent_skills.security_analysis.scripts.run_security_analysis import (
    run_security_analysis,
)
from agent_skills.server_analysis.scripts.run_server_analysis import run_server_analysis
from agents import (
    AgentResult,
    ApplicationAgent,
    AuthenticationAgent,
    NetworkAgent,
    SecurityAgent,
    ServerAgent,
)
from src.models import Finding
from tests.test_agent_skills import (
    _apache_events_with_spike,
    _auth_event,
    _fingerprint,
    _metric_events_with_spike,
    _network_metric_events,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

EVENT_AGENTS = [ApplicationAgent, ServerAgent, NetworkAgent, AuthenticationAgent]
ALL_AGENTS = EVENT_AGENTS + [SecurityAgent]


# ---------------------------------------------------------------------------
# Application Agent
# ---------------------------------------------------------------------------


def test_application_agent_invokes_application_skill():
    result = ApplicationAgent().run(_apache_events_with_spike())
    assert isinstance(result, AgentResult)
    assert result.agent_name == "application_agent"
    assert result.status == "ok"
    assert result.skills_used == ("application_analysis",)
    types = {f.finding_type for f in result.findings}
    assert "request_spike" in types
    assert "repeated_source_ip_scan" in types


def test_application_agent_does_not_alter_findings():
    events = _apache_events_with_spike()
    through_agent = ApplicationAgent().run(events).findings
    direct = run_application_analysis(events)
    assert [_fingerprint(f) for f in through_agent] == [_fingerprint(f) for f in direct]


def test_application_agent_passes_scope_arguments_to_skill():
    events = _apache_events_with_spike(host="webserver") + _apache_events_with_spike(
        host="intranet_server"
    )
    result = ApplicationAgent().run(events, host="webserver")
    assert result.findings
    assert {f.host for f in result.findings if f.host is not None} == {"webserver"}
    assert [_fingerprint(f) for f in result.findings] == [
        _fingerprint(f) for f in run_application_analysis(events, host="webserver")
    ]


# ---------------------------------------------------------------------------
# Server Agent
# ---------------------------------------------------------------------------


def test_server_agent_returns_same_findings_as_skill():
    events = _metric_events_with_spike()
    result = ServerAgent().run(events)
    assert result.status == "ok"
    assert result.skills_used == ("server_analysis",)
    assert [_fingerprint(f) for f in result.findings] == [
        _fingerprint(f) for f in run_server_analysis(events)
    ]


def test_server_agent_detectors_used_matches_skill():
    assert ServerAgent.DETECTORS == ("find_metric_anomaly",)
    result = ServerAgent().run(_metric_events_with_spike())
    assert result.detectors_used == ("find_metric_anomaly",)


# ---------------------------------------------------------------------------
# Network Agent
# ---------------------------------------------------------------------------


def test_network_agent_returns_only_network_findings():
    events = _network_metric_events() + _metric_events_with_spike()
    result = NetworkAgent().run(events)
    assert result.findings
    assert all(f.category == "network" for f in result.findings)
    assert {f.finding_type for f in result.findings} == {"network_usage_anomaly"}
    assert [_fingerprint(f) for f in result.findings] == [
        _fingerprint(f) for f in run_network_analysis(events)
    ]


def test_network_agent_is_partially_implemented_even_with_zero_findings():
    # CPU metric만 주면 network Finding이 없지만, 입력이 있으므로 status는 유지된다.
    result = NetworkAgent().run(_metric_events_with_spike())
    assert result.findings == []
    assert result.status == "partially_implemented"
    assert result.input_item_count > 0
    assert any("network detector" in note for note in result.notes)


# ---------------------------------------------------------------------------
# Authentication Agent
# ---------------------------------------------------------------------------


def test_authentication_agent_runs_without_error_and_makes_no_findings():
    result = AuthenticationAgent().run([_auth_event()])
    assert result.status == "not_implemented"
    assert result.findings == []
    assert result.detectors_used == ()
    assert result.notes  # 미구현 사유가 기록돼 있다


def test_authentication_agent_is_not_implemented_even_with_empty_input():
    result = AuthenticationAgent().run([])
    assert result.status == "not_implemented"  # no_input이 아니다
    assert result.input_item_count == 0
    assert result.findings == []


def test_authentication_agent_records_real_input_count():
    events = [_auth_event(event_id=f"a{i}") for i in range(7)]
    result = AuthenticationAgent().run(events)
    assert result.input_item_count == 7  # Skill이 소비하지 않아도 drain으로 센다


# ---------------------------------------------------------------------------
# Security Agent
# ---------------------------------------------------------------------------


def test_security_agent_selects_only_security_category():
    findings = run_application_analysis(_apache_events_with_spike())
    result = SecurityAgent().run(findings)
    assert result.status == "ok"
    assert result.findings
    assert all(f.category == "security" for f in result.findings)
    assert {f.finding_type for f in result.findings} == {"repeated_source_ip_scan"}
    assert any(f.category == "availability" for f in findings)  # 제외된 것이 실제로 있다


def test_security_agent_does_not_modify_finding_objects():
    findings = run_application_analysis(_apache_events_with_spike())
    expected = [f for f in findings if f.category == "security"]
    result = SecurityAgent().run(findings)
    # 원본 객체를 그대로 담는다(복사·수정하지 않는다).
    assert [id(f) for f in result.findings] == [id(f) for f in expected]
    assert [_fingerprint(f) for f in result.findings] == [_fingerprint(f) for f in expected]


def test_security_agent_input_item_count_is_input_finding_count():
    findings = run_application_analysis(_apache_events_with_spike())
    result = SecurityAgent().run(findings)
    assert result.input_item_count == len(findings)
    assert result.input_item_count > len(result.findings)  # 선별 수가 아니라 입력 수다


def test_security_agent_no_input_on_empty_findings():
    result = SecurityAgent().run([])
    assert result.status == "no_input"
    assert result.input_item_count == 0
    assert result.findings == []


def test_security_agent_matches_skill_result():
    findings = run_application_analysis(_apache_events_with_spike())
    assert SecurityAgent().run(findings).findings == run_security_analysis(findings)


def test_security_agent_does_not_call_rag_or_external_services():
    # 코드 수준에서 RAG/VectorDB 관련 참조가 없어야 한다.
    forbidden = ("supabase", "embedding", "vectordb", "vector_db", "retrieval", "openai")
    text = (PROJECT_ROOT / "agents" / "security_agent.py").read_text(encoding="utf-8").lower()
    for token in forbidden:
        # 문서상 "하지 않는다" 설명에는 등장할 수 있으므로 import/호출 형태만 금지한다.
        assert not re.search(rf"^\s*(from|import)\s+\S*{token}", text, re.MULTILINE)
        assert f"{token}(" not in text


# ---------------------------------------------------------------------------
# 공통: status 규칙 / input_item_count
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("agent_cls", [ApplicationAgent, ServerAgent, NetworkAgent])
def test_empty_event_input_yields_no_input(agent_cls):
    result = agent_cls().run([])
    assert result.status == "no_input"
    assert result.input_item_count == 0
    assert result.findings == []


def test_input_item_count_survives_when_skill_uses_no_events():
    # gaia_metric 이벤트만 주면 Application Skill은 전부 무시하지만,
    # 입력 item 수는 실제 입력 수를 유지하고 status는 ok다.
    events = _metric_events_with_spike()
    result = ApplicationAgent().run(events)
    assert result.status == "ok"
    assert result.findings == []
    assert result.input_item_count == len(events)


def test_input_item_count_survives_when_source_types_excludes_everything():
    # Skill이 입력을 한 건도 읽지 않고 즉시 반환하는 경로에서도 입력 수를 센다.
    events = _apache_events_with_spike()
    result = ApplicationAgent().run(events, source_types=["gaia_trace"])
    assert result.findings == []
    assert result.status == "ok"  # 입력 자체는 있었다
    assert result.input_item_count == len(events)


def test_input_item_count_equals_event_count():
    events = _metric_events_with_spike()
    assert ServerAgent().run(events).input_item_count == len(events)


def test_agents_accept_generators_and_consume_input_once():
    events = _apache_events_with_spike()
    result = ApplicationAgent().run(e for e in events)  # generator 입력
    assert result.input_item_count == len(events)
    assert result.findings


def test_status_and_findings_combination_is_distinguishable():
    # 빈 findings가 세 가지 다른 이유로 발생하고, status로 구분된다.
    assert ApplicationAgent().run([]).status == "no_input"
    assert ApplicationAgent().run(_metric_events_with_spike()).status == "ok"
    assert AuthenticationAgent().run([_auth_event()]).status == "not_implemented"
    assert NetworkAgent().run(_metric_events_with_spike()).status == "partially_implemented"


# ---------------------------------------------------------------------------
# 공통: provenance / determinism / threshold 불변
# ---------------------------------------------------------------------------


def test_dataset_provenance_is_preserved_not_overwritten():
    events = _metric_events_with_spike()
    result = ServerAgent().run(events, dataset="gaia")
    assert result.findings
    assert all(f.dataset == "gaia" for f in result.findings)

    # 엉뚱한 dataset을 주면 Finding이 0건이지, provenance가 바뀐 Finding이 나오지 않는다.
    wrong = ServerAgent().run(events, dataset="russellmitchell")
    assert wrong.findings == []
    assert wrong.status == "ok"
    assert wrong.input_item_count == len(events)


def test_mixed_dataset_events_keep_separate_provenance():
    events = _apache_events_with_spike() + _metric_events_with_spike()
    app = ApplicationAgent().run(events)
    server = ServerAgent().run(events)
    assert all(f.dataset == "russellmitchell" for f in app.findings)
    assert all(f.dataset == "gaia" for f in server.findings)


def test_repeated_runs_are_deterministic():
    events = _apache_events_with_spike()
    first = ApplicationAgent().run(events)
    second = ApplicationAgent().run(events)
    assert [_fingerprint(f) for f in first.findings] == [_fingerprint(f) for f in second.findings]
    assert first.status == second.status
    assert first.input_item_count == second.input_item_count


def test_reversed_input_order_yields_same_findings():
    events = _apache_events_with_spike()
    forward = ApplicationAgent().run(events).findings
    reverse = ApplicationAgent().run(list(reversed(events))).findings
    assert sorted(_fingerprint(f) for f in forward) == sorted(_fingerprint(f) for f in reverse)


def test_agent_does_not_change_severity_distribution():
    from collections import Counter

    events = _apache_events_with_spike()
    direct = Counter(f.severity for f in run_application_analysis(events))
    through_agent = Counter(f.severity for f in ApplicationAgent().run(events).findings)
    assert direct == through_agent


def test_all_returned_findings_are_finding_instances():
    result = ApplicationAgent().run(_apache_events_with_spike())
    assert result.findings
    assert all(isinstance(f, Finding) for f in result.findings)


def test_agent_result_is_frozen():
    result = ApplicationAgent().run([])
    with pytest.raises(Exception):
        result.status = "ok"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 구조 / 의존 방향
# ---------------------------------------------------------------------------


AGENT_MODULES = sorted((PROJECT_ROOT / "agents").glob("*.py"))


def test_agents_directory_contains_expected_modules():
    names = {p.name for p in AGENT_MODULES}
    assert names == {
        "__init__.py",
        "base.py",
        "application_agent.py",
        "server_agent.py",
        "network_agent.py",
        "authentication_agent.py",
        "security_agent.py",
    }


def test_src_and_evaluation_never_reference_agents():
    offenders = []
    for directory in ("src", "evaluation"):
        for path in (PROJECT_ROOT / directory).rglob("*.py"):
            if re.search(r"^\s*(from|import)\s+agents\b", path.read_text(encoding="utf-8"), re.MULTILINE):
                offenders.append(str(path.relative_to(PROJECT_ROOT)))
    assert offenders == []


def test_agent_skills_never_reference_agents():
    offenders = []
    for path in (PROJECT_ROOT / "agent_skills").rglob("*.py"):
        if re.search(r"^\s*(from|import)\s+agents\b", path.read_text(encoding="utf-8"), re.MULTILINE):
            offenders.append(str(path.relative_to(PROJECT_ROOT)))
    assert offenders == []


def test_agents_never_import_src_skills_directly():
    # Agent는 반드시 Agent Skill을 경유해야 한다. src.models는 타입 표기용으로 허용.
    offenders = []
    for path in AGENT_MODULES:
        if re.search(r"^\s*(from|import)\s+src\.skills", path.read_text(encoding="utf-8"), re.MULTILINE):
            offenders.append(path.name)
    assert offenders == []


def test_agents_never_import_evaluation():
    offenders = []
    for path in AGENT_MODULES:
        if re.search(r"^\s*(from|import)\s+evaluation\b", path.read_text(encoding="utf-8"), re.MULTILINE):
            offenders.append(path.name)
    assert offenders == []


def test_agent_modules_do_not_import_each_other():
    # agents/__init__.py만 re-export를 위해 각 Agent를 import한다.
    offenders = []
    for path in AGENT_MODULES:
        if path.name in ("__init__.py", "base.py"):
            continue
        text = path.read_text(encoding="utf-8")
        for other in AGENT_MODULES:
            if other.name in ("__init__.py", "base.py") or other.name == path.name:
                continue
            module = other.stem
            if re.search(rf"^\s*(from|import)\s+agents\.{module}\b", text, re.MULTILINE):
                offenders.append(f"{path.name} -> {other.name}")
    assert offenders == []


def test_no_rag_or_external_service_imports_in_agents():
    forbidden = ("supabase", "langchain", "langgraph", "openai", "chromadb", "pinecone", "faiss")
    offenders = []
    for path in AGENT_MODULES:
        text = path.read_text(encoding="utf-8").lower()
        for token in forbidden:
            if re.search(rf"^\s*(from|import)\s+\S*{token}", text, re.MULTILINE):
                offenders.append(f"{path.name}: {token}")
    assert offenders == []


# ---------------------------------------------------------------------------
# Agent <-> Skill <-> SKILLS.md 3단 일치
# ---------------------------------------------------------------------------


AGENT_SKILL_PAIRS = [
    (ApplicationAgent, "application_analysis", "run_application_analysis"),
    (ServerAgent, "server_analysis", "run_server_analysis"),
    (NetworkAgent, "network_analysis", "run_network_analysis"),
    (AuthenticationAgent, "authentication_analysis", "run_authentication_analysis"),
    (SecurityAgent, "security_analysis", "run_security_analysis"),
]


@pytest.mark.parametrize("agent_cls,skill_dir,module_name", AGENT_SKILL_PAIRS)
def test_agent_metadata_matches_its_skill(agent_cls, skill_dir, module_name):
    import importlib

    module = importlib.import_module(f"agent_skills.{skill_dir}.scripts.{module_name}")
    assert agent_cls.SKILL_NAME == module.SKILL_NAME == skill_dir
    assert agent_cls.DETECTORS == module.DETECTORS


@pytest.mark.parametrize("agent_cls,skill_dir,module_name", AGENT_SKILL_PAIRS)
def test_every_agent_has_a_matching_skills_md(agent_cls, skill_dir, module_name):
    assert (PROJECT_ROOT / "agent_skills" / skill_dir / "SKILLS.md").is_file()


def test_each_agent_uses_exactly_one_skill():
    for agent_cls, skill_dir, _ in AGENT_SKILL_PAIRS:
        if agent_cls is SecurityAgent:
            result = agent_cls().run([])
        else:
            result = agent_cls().run([])
        assert result.skills_used == (skill_dir,)
