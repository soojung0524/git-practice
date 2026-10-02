"""LangGraph workflow 독립 테스트.

Agent 자체의 동작은 tests/test_agents.py에서 검증한다. 여기서는 orchestration이
"필요한 Agent만 실행하고, AgentResult를 보존하고, Finding을 변조하지 않고,
SecurityAgent를 마지막에 실행하는지"를 본다.
"""

import operator
import re
from pathlib import Path
from typing import Annotated, TypedDict

import pytest
from langgraph.graph import END, START, StateGraph

from agents import (
    AgentResult,
    ApplicationAgent,
    AuthenticationAgent,
    NetworkAgent,
    SecurityAgent,
    ServerAgent,
)
from orchestration import (
    AUTHENTICATION_ROUTING_SOURCE_TYPES,
    ConflictingFindingError,
    NODE_APPLICATION,
    NODE_AUTHENTICATION,
    NODE_COLLECT,
    NODE_NETWORK,
    NODE_ROUTE,
    NODE_SECURITY,
    NODE_SERVER,
    PARALLEL_AGENT_NODES,
    build_graph,
    deduplicate_findings,
    merge_errors,
    merge_findings,
    run_investigation,
    select_agents,
)
from src.models import Finding
from tests.test_agent_skills import (
    _access_event,
    _apache_events_with_spike,
    _auth_event,
    _fingerprint,
    _metric_event,
    _metric_events_with_spike,
    _network_metric_events,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _trace_event(event_id="t1"):
    from datetime import datetime, timezone

    from src.models import NormalizedEvent

    return NormalizedEvent(
        event_id=event_id,
        source_type="gaia_trace",
        host="webservice1",
        source_path="trace/trace.csv",
        line_number=1,
        timestamp=datetime(2021, 7, 1, tzinfo=timezone.utc),
        raw="raw",
        dataset="gaia",
        event_type="gaia_trace_span",
        extra={"duration_seconds": 0.1},
    )


def _log_event(event_id="l1"):
    from datetime import datetime, timezone

    from src.models import NormalizedEvent

    return NormalizedEvent(
        event_id=event_id,
        source_type="gaia_log",
        host="webservice1",
        source_path="business/business.csv",
        line_number=1,
        timestamp=datetime(2021, 7, 1, tzinfo=timezone.utc),
        raw="raw",
        dataset="gaia",
        event_type="gaia_log_entry",
        extra={"level": "INFO"},
    )


# ---------------------------------------------------------------------------
# LangGraph fan-in barrier 동작 검증 (가정하지 않고 실제로 확인한다)
# ---------------------------------------------------------------------------


class _ProbeState(TypedDict):
    selected: list[str]
    items: Annotated[list[str], operator.add]
    errors: Annotated[dict[str, str], merge_errors]
    collect_calls: Annotated[list[list[str]], operator.add]


_PROBE_BRANCHES = ["a", "b", "c", "d"]


def _build_probe_graph():
    def branch(name):
        def node(state):
            return {"items": [name], "errors": {name: f"boom-{name}"}}

        return node

    def route(state):
        return {}

    def selector(state):
        return state["selected"] or [NODE_COLLECT]

    def collect(state):
        return {"collect_calls": [sorted(state["items"])]}

    graph = StateGraph(_ProbeState)
    graph.add_node(NODE_ROUTE, route)
    for name in _PROBE_BRANCHES:
        graph.add_node(name, branch(name))
    graph.add_node(NODE_COLLECT, collect)
    graph.add_edge(START, NODE_ROUTE)
    graph.add_conditional_edges(NODE_ROUTE, selector, [*_PROBE_BRANCHES, NODE_COLLECT])
    for name in _PROBE_BRANCHES:
        graph.add_edge(name, NODE_COLLECT)
    graph.add_edge(NODE_COLLECT, END)
    return graph.compile()


@pytest.mark.parametrize(
    "selected",
    [["a", "b", "c", "d"], ["a", "c"], ["b"], []],
)
def test_conditional_fanout_barrier_runs_collect_exactly_once(selected):
    """실행된 branch가 몇 개든 collect는 정확히 한 번, 모두 끝난 뒤 실행된다."""
    graph = _build_probe_graph()
    out = graph.invoke({"selected": selected, "items": [], "errors": {}, "collect_calls": []})
    assert len(out["collect_calls"]) == 1  # 정확히 한 번
    assert out["collect_calls"][0] == sorted(selected)  # 모든 branch 결과를 본다
    assert sorted(out["items"]) == sorted(selected)


def test_error_reducer_preserves_all_parallel_failures():
    graph = _build_probe_graph()
    out = graph.invoke(
        {"selected": ["a", "b", "c", "d"], "items": [], "errors": {}, "collect_calls": []}
    )
    assert sorted(out["errors"]) == ["a", "b", "c", "d"]  # 동시 실패가 모두 보존된다


def test_merge_reducers_do_not_mutate_inputs():
    a: list[Finding] = []
    b: list[Finding] = []
    assert merge_findings(a, b) == []
    left = {"x": "1"}
    right = {"y": "2"}
    assert merge_errors(left, right) == {"x": "1", "y": "2"}
    assert left == {"x": "1"}  # 입력을 변경하지 않는다


# ---------------------------------------------------------------------------
# graph 구조
# ---------------------------------------------------------------------------


def test_graph_compiles_with_expected_nodes():
    graph = build_graph()
    nodes = set(graph.get_graph().nodes)
    assert {
        NODE_ROUTE,
        NODE_APPLICATION,
        NODE_SERVER,
        NODE_NETWORK,
        NODE_AUTHENTICATION,
        NODE_COLLECT,
        NODE_SECURITY,
    } <= nodes


def test_parallel_agent_nodes_are_the_four_specialists():
    assert PARALLEL_AGENT_NODES == (
        NODE_APPLICATION,
        NODE_SERVER,
        NODE_NETWORK,
        NODE_AUTHENTICATION,
    )


# ---------------------------------------------------------------------------
# routing: 입력별로 실행되는 Agent
# ---------------------------------------------------------------------------


def test_select_agents_by_source_type():
    assert select_agents(frozenset({"apache_access"})) == (NODE_APPLICATION,)
    assert select_agents(frozenset({"gaia_trace"})) == (NODE_APPLICATION,)
    assert select_agents(frozenset({"gaia_log"})) == (NODE_APPLICATION,)
    assert select_agents(frozenset({"gaia_metric"})) == (NODE_SERVER, NODE_NETWORK)
    assert select_agents(frozenset({"syslog_auth"})) == (NODE_AUTHENTICATION,)
    assert select_agents(frozenset({"auditd"})) == (NODE_AUTHENTICATION,)
    assert select_agents(frozenset({"openvpn"})) == (NODE_AUTHENTICATION,)
    assert select_agents(frozenset()) == ()
    assert select_agents(frozenset({"dnsmasq"})) == ()  # 담당 Agent 없음


def test_authentication_routing_constant_matches_skills_md():
    # orchestration의 routing 상수와 SKILLS.md 참고 목록이 어긋나지 않는지 대조한다.
    text = (
        PROJECT_ROOT / "agent_skills" / "authentication_analysis" / "SKILLS.md"
    ).read_text(encoding="utf-8")
    for source_type in AUTHENTICATION_ROUTING_SOURCE_TYPES:
        assert f"`{source_type}`" in text


# ---------------------------------------------------------------------------
# 시나리오별 workflow 실행
# ---------------------------------------------------------------------------


def test_empty_input_completes_without_running_any_agent():
    state = run_investigation(events=[])
    assert state["routed_agents"] == ()
    assert state["application_result"] is None
    assert state["server_result"] is None
    assert state["network_result"] is None
    assert state["authentication_result"] is None
    assert state["findings"] == []
    assert state["errors"] == {}
    # SecurityAgent는 항상 실행되며, 입력이 없으므로 no_input이다.
    assert state["security_result"].status == "no_input"


def test_apache_only_runs_application_agent_only():
    state = run_investigation(events=_apache_events_with_spike())
    assert state["routed_agents"] == (NODE_APPLICATION,)
    assert isinstance(state["application_result"], AgentResult)
    assert state["server_result"] is None
    assert state["network_result"] is None
    assert state["authentication_result"] is None
    assert state["findings"]


def test_gaia_metric_only_runs_server_and_network():
    state = run_investigation(events=_metric_events_with_spike())
    assert state["routed_agents"] == (NODE_SERVER, NODE_NETWORK)
    assert isinstance(state["server_result"], AgentResult)
    assert isinstance(state["network_result"], AgentResult)
    assert state["application_result"] is None
    assert state["authentication_result"] is None


def test_gaia_trace_and_log_only_runs_application():
    state = run_investigation(events=[_trace_event(), _log_event()])
    assert state["routed_agents"] == (NODE_APPLICATION,)
    assert state["server_result"] is None
    assert state["network_result"] is None


def test_authentication_only_runs_authentication_agent_as_not_implemented():
    state = run_investigation(events=[_auth_event()])
    assert state["routed_agents"] == (NODE_AUTHENTICATION,)
    result = state["authentication_result"]
    assert result.status == "not_implemented"
    assert result.findings == []
    assert state["findings"] == []  # 가짜 Finding이 만들어지지 않는다
    assert state["application_result"] is None


def test_mixed_input_runs_every_applicable_agent():
    events = (
        _apache_events_with_spike()
        + _metric_events_with_spike()
        + _network_metric_events()
        + [_auth_event(), _trace_event(), _log_event()]
    )
    state = run_investigation(events=events)
    assert set(state["routed_agents"]) == {
        NODE_APPLICATION,
        NODE_SERVER,
        NODE_NETWORK,
        NODE_AUTHENTICATION,
    }
    for key in (
        "application_result",
        "server_result",
        "network_result",
        "authentication_result",
        "security_result",
    ):
        assert isinstance(state[key], AgentResult), key
    assert state["errors"] == {}


def test_unrelated_source_type_runs_no_specialist_agent():
    # dnsmasq는 담당 Agent가 없다. 억지로 어떤 Agent도 실행하지 않는다.
    from datetime import datetime, timezone

    from src.models import NormalizedEvent

    event = NormalizedEvent(
        event_id="d1",
        source_type="dnsmasq",
        host="inet-firewall",
        source_path="gather/inet-firewall/logs/dnsmasq.log",
        line_number=1,
        timestamp=datetime(2022, 1, 21, tzinfo=timezone.utc),
        raw="raw",
    )
    state = run_investigation(events=[event])
    assert state["routed_agents"] == ()
    assert state["findings"] == []


# ---------------------------------------------------------------------------
# AgentResult 보존 / Finding 무변조
# ---------------------------------------------------------------------------


def test_agent_result_fields_are_preserved_exactly():
    events = _apache_events_with_spike()
    direct = ApplicationAgent().run(events)
    state = run_investigation(events=events)
    through = state["application_result"]

    assert through.agent_name == direct.agent_name
    assert through.status == direct.status
    assert through.input_item_count == direct.input_item_count
    assert through.skills_used == direct.skills_used
    assert through.detectors_used == direct.detectors_used
    assert through.notes == direct.notes


def test_findings_are_not_altered_by_workflow():
    events = _apache_events_with_spike()
    direct = ApplicationAgent().run(events).findings
    state = run_investigation(events=events)
    assert [_fingerprint(f) for f in state["findings"]] == [_fingerprint(f) for f in direct]


def test_workflow_findings_match_direct_agent_execution_for_metrics():
    events = _metric_events_with_spike() + _network_metric_events()
    direct = ServerAgent().run(events).findings + NetworkAgent().run(events).findings
    state = run_investigation(events=events)

    # agent_findings는 Agent 직접 실행 결과와 그대로 일치한다(중복 포함).
    assert sorted(f.finding_id for f in state["agent_findings"]) == sorted(
        f.finding_id for f in direct
    )
    # findings는 중복 제거 후이므로 unique id 집합과 일치한다.
    assert sorted(f.finding_id for f in state["findings"]) == sorted(
        {f.finding_id for f in direct}
    )


def test_all_collected_items_are_finding_instances():
    state = run_investigation(events=_apache_events_with_spike())
    assert state["findings"]
    assert all(isinstance(f, Finding) for f in state["findings"])


# ---------------------------------------------------------------------------
# SecurityAgent 실행 시점과 선별
# ---------------------------------------------------------------------------


def test_security_agent_runs_after_all_findings_are_collected():
    events = _apache_events_with_spike() + _metric_events_with_spike()
    state = run_investigation(events=events)
    # SecurityAgent가 본 입력 수 == 병합된 findings 전체 수.
    # 앞선 Agent들이 모두 끝난 뒤 실행됐다는 것을 값으로 증명한다.
    assert state["security_result"].input_item_count == len(state["findings"])
    assert state["security_result"].input_item_count > 0


def test_security_result_holds_only_security_findings():
    state = run_investigation(events=_apache_events_with_spike())
    security = state["security_result"].findings
    assert security
    assert all(f.category == "security" for f in security)
    assert {f.finding_type for f in security} == {"repeated_source_ip_scan"}


def test_security_findings_are_original_objects_from_collected_findings():
    state = run_investigation(events=_apache_events_with_spike())
    collected = state["findings"]
    for finding in state["security_result"].findings:
        assert any(finding is c for c in collected)  # 동일 객체


def test_security_findings_are_not_added_back_to_findings():
    events = _apache_events_with_spike()
    state = run_investigation(events=events)
    direct_count = len(ApplicationAgent().run(events).findings)
    # security 결과를 findings에 되넣지 않으므로 중복이 생기지 않는다.
    # (apache 경로에는 detector 중복이 없어 dedup 전후 수가 같다)
    assert len(state["findings"]) == direct_count


# ---------------------------------------------------------------------------
# Finding deduplication (collect_findings node)
# ---------------------------------------------------------------------------


def _dup_pair():
    """같은 finding_id를 갖는 동일 내용 Finding 2개를 만든다(별개 객체)."""
    events = _network_metric_events()
    first = ServerAgent().run(events).findings
    second = NetworkAgent().run(events).findings
    return first, second


def test_deduplicate_keeps_unique_findings_unchanged():
    findings = ApplicationAgent().run(_apache_events_with_spike()).findings
    assert len(findings) > 1
    deduped = deduplicate_findings(findings)
    assert [id(f) for f in deduped] == [id(f) for f in findings]  # 그대로 유지


def test_deduplicate_collapses_identical_duplicate_ids():
    first, second = _dup_pair()
    combined = first + second
    duplicated_ids = {f.finding_id for f in first} & {f.finding_id for f in second}
    assert duplicated_ids  # 실제로 중복이 존재하는 입력이다

    deduped = deduplicate_findings(combined)
    ids = [f.finding_id for f in deduped]
    assert len(ids) == len(set(ids))  # 중복이 사라졌다
    assert set(ids) == {f.finding_id for f in combined}  # 잃어버린 Finding은 없다


def test_deduplicate_raises_when_same_id_has_different_content():
    from dataclasses import replace

    findings = ApplicationAgent().run(_apache_events_with_spike()).findings
    original = findings[0]
    # 같은 finding_id인데 severity만 다른 Finding을 만든다.
    conflicting = replace(original, severity="low" if original.severity != "low" else "high")
    assert conflicting.finding_id == original.finding_id

    with pytest.raises(ConflictingFindingError) as excinfo:
        deduplicate_findings([original, conflicting])
    assert original.finding_id in str(excinfo.value)


def test_deduplicate_detects_conflict_in_metrics_too():
    from dataclasses import replace

    findings = ApplicationAgent().run(_apache_events_with_spike()).findings
    original = findings[0]
    conflicting = replace(original, metrics={**original.metrics, "injected": 1})
    with pytest.raises(ConflictingFindingError):
        deduplicate_findings([original, conflicting])


def test_deduplicate_is_first_wins_and_preserves_order():
    first, second = _dup_pair()
    combined = first + second
    deduped = deduplicate_findings(combined)

    # 먼저 등장한 객체가 남는다(identity로 확인).
    by_id_first_seen = {}
    for finding in combined:
        by_id_first_seen.setdefault(finding.finding_id, finding)
    assert [id(f) for f in deduped] == [id(by_id_first_seen[f.finding_id]) for f in deduped]
    # 등장 순서가 보존된다.
    assert [f.finding_id for f in deduped] == list(by_id_first_seen)


def test_deduplicate_does_not_modify_finding_objects():
    first, second = _dup_pair()
    combined = first + second
    before = [_fingerprint(f) for f in combined]
    deduplicate_findings(combined)
    assert [_fingerprint(f) for f in combined] == before  # 입력이 변하지 않았다
    assert len(combined) == len(first) + len(second)  # 입력 리스트도 그대로


def test_workflow_deduplicates_server_and_network_overlap():
    events = _metric_events_with_spike() + _network_metric_events()
    state = run_investigation(events=events)

    raw = state["agent_findings"]
    final = state["findings"]
    raw_ids = [f.finding_id for f in raw]
    assert len(raw_ids) != len(set(raw_ids))  # 수집 단계에는 중복이 있었다
    assert len(final) == len(set(raw_ids))  # 최종은 unique 수와 같다
    assert len({f.finding_id for f in final}) == len(final)


def test_security_agent_input_count_reflects_deduplicated_findings():
    events = _metric_events_with_spike() + _network_metric_events()
    state = run_investigation(events=events)
    assert state["security_result"].input_item_count == len(state["findings"])
    assert state["security_result"].input_item_count < len(state["agent_findings"])


def test_conflicting_finding_error_propagates_out_of_workflow(monkeypatch):
    # collect_findings의 오류는 조용히 errors에 숨지 않고 workflow 밖으로 나온다.
    import orchestration.nodes as nodes

    from dataclasses import replace

    findings = ApplicationAgent().run(_apache_events_with_spike()).findings
    conflicting = replace(findings[0], severity="low" if findings[0].severity != "low" else "high")

    class FakeAgent:
        def run(self, events, **kwargs):
            return AgentResult(
                agent_name="application_agent",
                status="ok",
                findings=[findings[0], conflicting],
                input_item_count=1,
                skills_used=("application_analysis",),
                detectors_used=("find_request_spike",),
            )

    monkeypatch.setattr(nodes, "ApplicationAgent", FakeAgent)
    with pytest.raises(ConflictingFindingError):
        run_investigation(events=_apache_events_with_spike())


# ---------------------------------------------------------------------------
# provenance / determinism
# ---------------------------------------------------------------------------


def test_dataset_provenance_is_preserved():
    events = _metric_events_with_spike()
    state = run_investigation(events=events, dataset="gaia")
    assert state["findings"]
    assert all(f.dataset == "gaia" for f in state["findings"])


def test_dataset_filter_narrows_routing():
    events = _apache_events_with_spike() + _metric_events_with_spike()
    # dataset="gaia"면 apache_access 이벤트는 routing 판단에서 제외된다.
    state = run_investigation(events=events, dataset="gaia")
    assert NODE_APPLICATION not in state["routed_agents"]
    assert set(state["routed_agents"]) == {NODE_SERVER, NODE_NETWORK}


def test_mixed_datasets_keep_separate_provenance():
    events = _apache_events_with_spike() + _metric_events_with_spike()
    state = run_investigation(events=events)
    datasets = {f.dataset for f in state["findings"]}
    assert datasets <= {"russellmitchell", "gaia"}
    for finding in state["findings"]:
        if finding.detector == "find_metric_anomaly":
            assert finding.dataset == "gaia"
        else:
            assert finding.dataset == "russellmitchell"


def test_repeated_runs_are_deterministic():
    events = _apache_events_with_spike()
    first = run_investigation(events=events)
    second = run_investigation(events=events)
    assert [_fingerprint(f) for f in first["findings"]] == [
        _fingerprint(f) for f in second["findings"]
    ]
    assert first["routed_agents"] == second["routed_agents"]


def test_reversed_input_order_yields_same_findings():
    events = _apache_events_with_spike()
    forward = run_investigation(events=events)["findings"]
    reverse = run_investigation(events=list(reversed(events)))["findings"]
    assert sorted(_fingerprint(f) for f in forward) == sorted(_fingerprint(f) for f in reverse)


def test_scope_arguments_reach_the_agents():
    events = _apache_events_with_spike(host="webserver") + _apache_events_with_spike(
        host="intranet_server"
    )
    state = run_investigation(events=events, host="webserver")
    assert state["findings"]
    assert {f.host for f in state["findings"] if f.host is not None} == {"webserver"}


# ---------------------------------------------------------------------------
# event_source (대규모 이벤트 전달)
# ---------------------------------------------------------------------------


def test_event_source_gives_each_agent_a_fresh_iterator():
    events = _metric_events_with_spike() + _network_metric_events()
    calls = {"n": 0}

    def source():
        calls["n"] += 1
        return iter(events)

    state = run_investigation(event_source=source)
    # route 1회 + 실행된 Agent 2개(server, network) = 3회
    assert calls["n"] == 3
    assert state["server_result"].input_item_count == len(events)
    assert state["network_result"].input_item_count == len(events)


def test_event_source_and_events_are_mutually_exclusive():
    with pytest.raises(ValueError):
        run_investigation()
    with pytest.raises(ValueError):
        run_investigation(events=[], event_source=lambda: iter([]))


def test_generator_events_are_materialized_internally():
    events = _apache_events_with_spike()
    state = run_investigation(events=(e for e in events))
    assert state["application_result"].input_item_count == len(events)


# ---------------------------------------------------------------------------
# error handling
# ---------------------------------------------------------------------------


def test_data_error_in_one_agent_is_recorded_and_workflow_continues(monkeypatch):
    import orchestration.nodes as nodes

    class BrokenServerAgent:
        def run(self, events, **kwargs):
            raise RuntimeError("metric parsing blew up")

    monkeypatch.setattr(nodes, "ServerAgent", BrokenServerAgent)

    events = _metric_events_with_spike()
    state = run_investigation(events=events)

    assert state["server_result"] is None  # 실패한 Agent는 None
    assert NODE_SERVER in state["errors"]
    assert "metric parsing blew up" in state["errors"][NODE_SERVER]
    assert "Traceback" in state["errors"][NODE_SERVER]  # traceback 전문이 남는다
    # 다른 Agent는 계속 실행됐고 workflow는 완주했다.
    assert isinstance(state["network_result"], AgentResult)
    assert isinstance(state["security_result"], AgentResult)


def test_programming_error_is_reraised_not_hidden(monkeypatch):
    import orchestration.nodes as nodes

    class BuggyServerAgent:
        def run(self, events, **kwargs):
            raise AttributeError("typo in attribute name")

    monkeypatch.setattr(nodes, "ServerAgent", BuggyServerAgent)

    with pytest.raises(AttributeError):
        run_investigation(events=_metric_events_with_spike())


def test_multiple_simultaneous_agent_failures_are_all_recorded(monkeypatch):
    import orchestration.nodes as nodes

    class Broken:
        def __init__(self, name):
            self.name = name

        def run(self, *args, **kwargs):
            raise RuntimeError(f"{self.name} failed")

    monkeypatch.setattr(nodes, "ServerAgent", lambda: Broken("server"))
    monkeypatch.setattr(nodes, "NetworkAgent", lambda: Broken("network"))

    state = run_investigation(events=_metric_events_with_spike())
    assert set(state["errors"]) == {NODE_SERVER, NODE_NETWORK}  # 둘 다 보존된다
    assert state["server_result"] is None
    assert state["network_result"] is None


def test_unrun_and_failed_agents_are_distinguishable(monkeypatch):
    import orchestration.nodes as nodes

    class Broken:
        def run(self, *args, **kwargs):
            raise RuntimeError("boom")

    monkeypatch.setattr(nodes, "ServerAgent", Broken)
    state = run_investigation(events=_metric_events_with_spike())

    # 실패: result is None + errors에 키 있음
    assert state["server_result"] is None and NODE_SERVER in state["errors"]
    # 미실행: result is None + errors에 키 없음
    assert state["application_result"] is None and NODE_APPLICATION not in state["errors"]


# ---------------------------------------------------------------------------
# 의존 방향 / 금지 사항
# ---------------------------------------------------------------------------


ORCHESTRATION_MODULES = sorted((PROJECT_ROOT / "orchestration").glob("*.py"))


def test_lower_layers_never_import_orchestration():
    offenders = []
    for directory in ("src", "agents", "agent_skills", "evaluation"):
        for path in (PROJECT_ROOT / directory).rglob("*.py"):
            if re.search(
                r"^\s*(from|import)\s+orchestration\b",
                path.read_text(encoding="utf-8"),
                re.MULTILINE,
            ):
                offenders.append(str(path.relative_to(PROJECT_ROOT)))
    assert offenders == []


def test_orchestration_never_imports_evaluation_or_ground_truth():
    offenders = []
    for path in ORCHESTRATION_MODULES:
        text = path.read_text(encoding="utf-8")
        if re.search(r"^\s*(from|import)\s+evaluation\b", text, re.MULTILINE):
            offenders.append(f"{path.name}: evaluation")
        if "ground_truth" in text.lower():
            offenders.append(f"{path.name}: ground_truth")
    assert offenders == []


def test_orchestration_never_imports_src_skills_directly():
    # detector는 Agent -> Skill을 경유해야 한다. src.models는 타입 표기용으로 허용.
    offenders = []
    for path in ORCHESTRATION_MODULES:
        if re.search(
            r"^\s*(from|import)\s+src\.skills", path.read_text(encoding="utf-8"), re.MULTILINE
        ):
            offenders.append(path.name)
    assert offenders == []


def test_no_rag_or_external_service_imports_in_orchestration():
    forbidden = ("supabase", "openai", "chromadb", "pinecone", "faiss", "langchain_openai")
    offenders = []
    for path in ORCHESTRATION_MODULES:
        text = path.read_text(encoding="utf-8").lower()
        for token in forbidden:
            if re.search(rf"^\s*(from|import)\s+\S*{token}", text, re.MULTILINE):
                offenders.append(f"{path.name}: {token}")
    assert offenders == []


def test_orchestration_does_not_use_checkpointer_or_interrupt():
    """이번 단계에서 쓰지 않기로 한 LangGraph 기능이 실제로 사용되지 않았는지 확인한다.

    docstring에서 "쓰지 않는다"고 설명하는 것은 허용해야 하므로, 단어 등장이 아니라
    호출/인자 형태만 검사한다.
    """
    forbidden_usage = (
        r"checkpointer\s*=",
        r"interrupt_before\s*=",
        r"interrupt_after\s*=",
        r"interrupt\s*\(",
        r"MemorySaver",
        r"SqliteSaver",
    )
    offenders = []
    for path in ORCHESTRATION_MODULES:
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden_usage:
            if re.search(pattern, text):
                offenders.append(f"{path.name}: {pattern}")
    assert offenders == []
