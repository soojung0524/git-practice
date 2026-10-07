"""scripts/build_demo_replay.py - 시연용 demo JSON pack 검증.

실제 artifact(output/demo/...)가 있으면 그 값을 검증하고, 없으면 skip한다. 실제 결과가
없는 환경에서 가짜 fixture로 숫자를 만들어 통과시키지 않는다.

외부 API를 호출하지 않는다 - 이 테스트도, 검증 대상 스크립트도.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "build_demo_replay.py"
DEMO_DIR = PROJECT_ROOT / "output" / "demo" / "gaia_network_incident"
REPORT_PATH = PROJECT_ROOT / "output" / "reports" / "gaia-final_report_e4977bb394b7.json"
FINDINGS_PATH = PROJECT_ROOT / "output" / "findings" / "gaia.pkl"

# 실측으로 확인된 값. demo가 이 숫자를 재생산하는지 고정한다.
ANCHOR_FINDING_ID = (
    "gaia:find_metric_anomaly:dbservice1_docker_network_in_packets:2021-07-31T19:10:27+00:00"
)
EXPECTED_PROJECTION_FINDINGS = 5
EXPECTED_CANDIDATE_INCIDENTS = 4
EXPECTED_MULTI_FINDING_INCIDENTS = 1
EXPECTED_SINGLE_FINDING_INCIDENTS = 3
EXPECTED_FOCUSED_INCIDENTS = 1
EXPECTED_UNSELECTED_INCIDENTS = 3
EXPECTED_FOCUSED_SERVICE = "dbservice1"
EXPECTED_FOCUSED_EVIDENCE = 4
EXPECTED_REPLAY_EVENTS = 9
UNRELATED_SERVICE = "webservice2"

REAL_AGENT_NAMES = {
    "application_agent",
    "server_agent",
    "network_agent",
    "authentication_agent",
    "security_agent",
}

STEP_FILES = (
    "step_00_collecting.json",
    "step_01_finding_detected.json",
    "step_02_correlation.json",
    "step_03_focus_selected.json",
    "step_04_rag_analyzing.json",
    "step_05_rag_completed.json",
    "step_06_report_ready.json",
)

ALL_DEMO_FILES = ("manifest.json", "replay_events.json", "final_report.json", *STEP_FILES)


def _load_script_module():
    spec = importlib.util.spec_from_file_location("build_demo_replay", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


demo_script = _load_script_module()


requires_demo = pytest.mark.skipif(
    not (DEMO_DIR / "manifest.json").is_file(),
    reason="demo artifact가 없다 (python scripts/build_demo_replay.py 먼저 실행)",
)
requires_sources = pytest.mark.skipif(
    not (REPORT_PATH.is_file() and FINDINGS_PATH.is_file()),
    reason="실제 보고서/Finding 파일이 없다",
)


@pytest.fixture(scope="module")
def manifest() -> dict[str, Any]:
    return json.loads((DEMO_DIR / "manifest.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def steps() -> dict[str, dict[str, Any]]:
    return {
        name: json.loads((DEMO_DIR / name).read_text(encoding="utf-8")) for name in STEP_FILES
    }


@pytest.fixture(scope="module")
def replay() -> dict[str, Any]:
    return json.loads((DEMO_DIR / "replay_events.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 1~7. 파일 생성 / JSON 안정성
# ---------------------------------------------------------------------------


@requires_demo
def test_all_demo_files_exist() -> None:
    for name in ALL_DEMO_FILES:
        assert (DEMO_DIR / name).is_file(), name


@requires_demo
def test_step_file_count_is_seven() -> None:
    assert len(list(DEMO_DIR.glob("step_*.json"))) == 7


@requires_demo
def test_every_file_is_loadable_utf8_json() -> None:
    for name in ALL_DEMO_FILES:
        payload = json.loads((DEMO_DIR / name).read_text(encoding="utf-8"))
        assert isinstance(payload, dict)


@requires_demo
def test_korean_is_not_escaped() -> None:
    raw = (DEMO_DIR / "step_00_collecting.json").read_text(encoding="utf-8")
    assert "데이터 수집" in raw
    assert "\\u" not in raw


@requires_demo
def test_no_nan_or_infinity_literals() -> None:
    """json.load는 NaN/Infinity를 받아주므로 parse_constant로 명시적으로 거부한다."""

    def reject(value: str) -> None:  # pragma: no cover - 통과 시 호출되지 않는다
        raise AssertionError(f"JSON 표준이 아닌 상수: {value}")

    for name in ALL_DEMO_FILES:
        json.loads((DEMO_DIR / name).read_text(encoding="utf-8"), parse_constant=reject)


@requires_demo
def test_manifest_lists_every_step_file_in_order(manifest: dict[str, Any]) -> None:
    assert manifest["step_count"] == 7
    assert [step["order"] for step in manifest["steps"]] == list(range(7))
    assert [step["file"] for step in manifest["steps"]] == list(STEP_FILES)
    for step in manifest["steps"]:
        assert (DEMO_DIR / step["file"]).is_file()
        assert isinstance(step["recommended_delay_ms"], int)
    assert manifest["demo_only"] is True
    assert manifest["replay_event_file"] == "replay_events.json"
    assert manifest["source_report_file"] == "final_report.json"


@requires_demo
def test_manifest_title_does_not_claim_root_cause(manifest: dict[str, Any]) -> None:
    title = manifest["title"]
    assert EXPECTED_FOCUSED_SERVICE in title
    for banned in ("원인", "공격", "침해", "root cause", "Root Cause"):
        assert banned not in title


# ---------------------------------------------------------------------------
# 8. 재생성 시 byte-identical
# ---------------------------------------------------------------------------


# manifest는 입력 파일 경로를 기록하므로, 다른 경로 표기로 호출하면 그 두 필드만 달라진다.
_INPUT_PATH_FIELDS = ("source_report_origin", "source_findings_file")


@requires_sources
def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    """같은 입력으로 두 번 만들면 모든 파일이 바이트 동일하다(생성 시각 등을 넣지 않는다)."""
    first, second = tmp_path / "one", tmp_path / "two"
    for out in (first, second):
        demo_script.build_demo_pack(
            report_path=REPORT_PATH, findings_path=FINDINGS_PATH, out_dir=out
        )
    for name in ALL_DEMO_FILES:
        assert (first / name).read_bytes() == (second / name).read_bytes(), name


@requires_demo
@requires_sources
def test_regeneration_reproduces_the_committed_demo_pack(tmp_path: Path) -> None:
    """저장된 demo pack도 같은 generator가 같은 입력으로 만든 것과 같다."""
    out = tmp_path / "demo"
    demo_script.build_demo_pack(
        report_path=REPORT_PATH, findings_path=FINDINGS_PATH, out_dir=out
    )
    for name in ALL_DEMO_FILES:
        if name == "manifest.json":
            continue
        assert (out / name).read_bytes() == (DEMO_DIR / name).read_bytes(), name

    fresh = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    saved = json.loads((DEMO_DIR / "manifest.json").read_text(encoding="utf-8"))
    for field in _INPUT_PATH_FIELDS:
        assert fresh.pop(field).endswith(Path(saved.pop(field)).name)
    assert fresh == saved


# ---------------------------------------------------------------------------
# 9~14. 외부 호출 / detector / Ground Truth 금지
# ---------------------------------------------------------------------------


def test_script_does_not_import_external_services() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    for banned in ("openai", "supabase", "rag", "llm", "langchain", "langgraph", "dotenv"):
        assert banned not in imported, banned


def test_importing_script_does_not_load_external_clients() -> None:
    before = set(sys.modules)
    _load_script_module()
    added = set(sys.modules) - before
    for name in added:
        root = name.split(".")[0]
        assert root not in {"openai", "supabase", "rag", "llm"}, name


def test_script_never_calls_a_detector() -> None:
    """detector를 다시 실행하지 않는다 - find_* 호출이 소스에 없어야 한다."""
    tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
    called: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name.startswith("find_"):
                called.append(name)
    assert called == []


def test_script_does_not_use_ground_truth() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8").lower()
    for banned in ("ground_truth", "ground truth", "run_table", "evaluation"):
        assert banned not in source, banned


@requires_demo
def test_manifest_records_that_no_external_call_was_made(manifest: dict[str, Any]) -> None:
    assert manifest["external_calls"] == {
        "openai": False,
        "supabase": False,
        "rag_agent": False,
        "llm": False,
        "detector_rerun": False,
    }


# ---------------------------------------------------------------------------
# 15~21. 실제 분석 수치
# ---------------------------------------------------------------------------


@requires_demo
def test_anchor_finding_id_is_exact(manifest: dict[str, Any], steps) -> None:
    assert manifest["anchor_finding_id"] == ANCHOR_FINDING_ID
    for step in steps.values():
        assert step["source"]["anchor_finding_id"] == ANCHOR_FINDING_ID


@requires_demo
def test_correlation_counts_match_real_result(steps) -> None:
    counters = steps["step_02_correlation.json"]["dashboard"]["counters"]
    assert counters["projection_finding_count"] == EXPECTED_PROJECTION_FINDINGS
    assert counters["candidate_incident_count"] == EXPECTED_CANDIDATE_INCIDENTS
    assert counters["multi_finding_incident_count"] == EXPECTED_MULTI_FINDING_INCIDENTS
    assert counters["single_finding_incident_count"] == EXPECTED_SINGLE_FINDING_INCIDENTS


@requires_demo
def test_focus_selection_counts_match_real_result(steps) -> None:
    counters = steps["step_03_focus_selected.json"]["dashboard"]["counters"]
    assert counters["focused_incident_count"] == EXPECTED_FOCUSED_INCIDENTS
    assert counters["unselected_candidate_incident_count"] == EXPECTED_UNSELECTED_INCIDENTS
    assert counters["unmatched_anchor_count"] == 0


@requires_demo
def test_focused_incident_is_dbservice1_only(steps) -> None:
    focused = steps["step_03_focus_selected.json"]["detail"]["focused_incident"]
    assert focused["finding_ids"] == [ANCHOR_FINDING_ID]
    assert focused["impact"]["affected_services"] == [EXPECTED_FOCUSED_SERVICE]
    assert focused["evidence"]["total_evidence_count"] == EXPECTED_FOCUSED_EVIDENCE
    assert focused["hypotheses"] == []
    assert focused["hypotheses_note"]


@requires_demo
@pytest.mark.parametrize("name", STEP_FILES[3:])
def test_focused_detail_never_contains_unrelated_service(steps, name: str) -> None:
    focused = steps[name]["detail"]["focused_incident"]
    assert focused is not None
    assert UNRELATED_SERVICE not in json.dumps(focused, ensure_ascii=False)
    assert UNRELATED_SERVICE not in json.dumps(focused["timeline"], ensure_ascii=False)
    assert UNRELATED_SERVICE not in json.dumps(focused["impact"], ensure_ascii=False)


@requires_demo
def test_guidance_question_never_contains_unrelated_service(steps) -> None:
    for name in ("step_04_rag_analyzing.json", "step_06_report_ready.json"):
        question = steps[name]["detail"]["security_guidance"]["question"]
        assert question
        assert UNRELATED_SERVICE not in question


@requires_demo
def test_unselected_candidates_may_contain_unrelated_service(steps) -> None:
    """무관한 incident는 '선택되지 않은 후보' 목록에만 남는다."""
    candidates = steps["step_03_focus_selected.json"]["detail"]["candidates"]
    unselected = candidates["unselected_incidents"]
    assert len(unselected) == EXPECTED_UNSELECTED_INCIDENTS
    assert all(item["affected_services"] == [UNRELATED_SERVICE] for item in unselected)
    assert sum(1 for item in unselected if item["finding_count"] == 2) == 1
    assert candidates["unselected_note"]


# ---------------------------------------------------------------------------
# 22~23 (focused 누출)은 위 parametrize 테스트가 담당. 아래는 step별 공개 범위.
# ---------------------------------------------------------------------------


@requires_demo
def test_step_00_shows_nothing_and_claims_no_normal_state(steps) -> None:
    step = steps["step_00_collecting.json"]
    dashboard, detail = step["dashboard"], step["detail"]
    assert step["demo"]["phase"] == "collecting"
    assert dashboard["counters"]["revealed_findings_count"] == 0
    assert dashboard["timeline_preview"] == []
    assert dashboard["revealed_finding_ids"] == []
    assert detail["focused_incident"] is None
    assert detail["candidates"] is None
    assert detail["security_guidance"]["status"] == "not_started"
    assert dashboard["status"]["report"] == "not_ready"
    # "정상 / 문제 없음"이라고 주장하지 않는다. 그 표현은 부정하는 문장에서만 나온다.
    note = step["demo"]["step_note"]
    assert "'정상' 또는 '문제 없음'을 뜻하지 않는다" in note
    raw = json.dumps(step, ensure_ascii=False).replace(note, "")
    for banned in ("문제 없음", "시스템 정상", "이상 없음"):
        assert banned not in raw, banned
    assert dashboard["operational_state"] is None


@requires_demo
def test_step_01_reveals_only_the_anchor_finding(steps) -> None:
    dashboard = steps["step_01_finding_detected.json"]["dashboard"]
    assert dashboard["counters"]["revealed_findings_count"] == 1
    assert dashboard["revealed_finding_ids"] == [ANCHOR_FINDING_ID]
    assert dashboard["revealed_severity_counts"] == {"low": 1}
    assert dashboard["revealed_finding_type_counts"] == {"network_usage_anomaly": 1}
    (entry,) = dashboard["timeline_preview"]
    assert entry["finding_id"] == ANCHOR_FINDING_ID
    assert entry["service"] == EXPECTED_FOCUSED_SERVICE
    assert entry["severity"] == "low"
    assert entry["original_start_time"] == "2021-07-31T19:10:27+00:00"
    assert entry["original_end_time"] == "2021-07-31T19:13:57+00:00"
    assert entry["relative_start_seconds"] == 600.0
    assert entry["relative_end_seconds"] == 810.0


@requires_demo
def test_step_02_lists_candidates_without_revealing_the_selection(steps) -> None:
    step = steps["step_02_correlation.json"]
    candidates = step["detail"]["candidates"]
    assert candidates["selection_completed"] is False
    assert candidates["focused_incident_ids"] is None
    assert candidates["unselected_incidents"] is None
    assert step["detail"]["focused_incident"] is None
    assert len(candidates["candidate_incidents"]) == EXPECTED_CANDIDATE_INCIDENTS
    # 후보 목록에 webservice2가 있는 것은 허용된다(원인이라고 쓰지 않는다).
    assert any(
        item["affected_services"] == [UNRELATED_SERVICE]
        for item in candidates["candidate_incidents"]
    )
    assert len(step["dashboard"]["timeline_preview"]) == EXPECTED_PROJECTION_FINDINGS


@requires_demo
def test_guidance_is_hidden_until_step_05(steps) -> None:
    for name in STEP_FILES[:4]:
        guidance = steps[name]["detail"]["security_guidance"]
        assert guidance["status"] == "not_started"
        assert guidance["response"] is None
        assert guidance["question"] is None
        assert guidance["demo_derived"] is None

    analyzing = steps["step_04_rag_analyzing.json"]["detail"]["security_guidance"]
    assert analyzing["status"] == "analyzing"
    assert analyzing["question"]  # 질문은 보여준다
    assert analyzing["provider_name"] == "rag_agent"
    assert analyzing["response"] is None  # 응답은 숨긴다
    assert analyzing["demo_derived"] is None  # 근거 페이지도 숨긴다

    for name in STEP_FILES[5:]:
        guidance = steps[name]["detail"]["security_guidance"]
        assert guidance["status"] == "completed"
        assert guidance["response"]
        assert guidance["demo_derived"]["citation_pages"]


@requires_demo
def test_guidance_response_is_verbatim_with_citations(steps) -> None:
    report = json.loads((DEMO_DIR / "final_report.json").read_text(encoding="utf-8"))
    original = report["security_guidance"]["items"][0]
    for name in STEP_FILES[5:]:
        guidance = steps[name]["detail"]["security_guidance"]
        assert guidance["response"] == original["response"]
        assert guidance["question"] == original["question"]
        assert guidance["incident_id"] == original["incident_id"]
        assert guidance["model"] == original["model"]
        assert "[Page" in guidance["response"]
        assert guidance["source_note"] == report["security_guidance"]["source_note"]


@requires_demo
def test_citation_pages_are_deduplicated_and_sorted(steps) -> None:
    guidance = steps[STEP_FILES[6]]["detail"]["security_guidance"]
    pages = guidance["demo_derived"]["citation_pages"]
    assert pages == sorted(set(pages))
    assert all(isinstance(page, int) for page in pages)
    assert guidance["demo_derived"]["citation_count"] >= len(pages)
    assert guidance["demo_derived"]["note"]
    # response에 실제로 있는 페이지만 나온다.
    for page in pages:
        assert f"[Page {page}" in guidance["response"]


@requires_demo
def test_narrative_summary_only_in_step_06(steps) -> None:
    for name in STEP_FILES[:6]:
        assert steps[name]["detail"]["narrative_summary"] is None
        assert steps[name]["detail"]["final_report_file"] is None
    step = steps["step_06_report_ready.json"]
    narrative = step["detail"]["narrative_summary"]
    assert narrative["text"]
    assert narrative["model"]
    assert step["detail"]["final_report_file"] == "final_report.json"
    assert step["dashboard"]["status"]["report"] == "ready"


@requires_demo
def test_limitations_are_copied_verbatim(steps) -> None:
    report = json.loads((DEMO_DIR / "final_report.json").read_text(encoding="utf-8"))
    for name in STEP_FILES[2:]:
        assert steps[name]["detail"]["limitations"] == report["limitations"]


# ---------------------------------------------------------------------------
# 31~33. Agent 카드
# ---------------------------------------------------------------------------


@requires_demo
@pytest.mark.parametrize("name", STEP_FILES)
def test_agent_cards_use_only_real_agents(steps, name: str) -> None:
    cards = steps[name]["dashboard"]["agents"]
    names = [card["agent_name"] for card in cards]
    assert set(names) == REAL_AGENT_NAMES
    assert len(names) == len(set(names))


@requires_demo
def test_agent_cards_do_not_invent_execution_status(steps) -> None:
    """최종 보고서에 AgentResult가 없으므로 execution_status는 null이어야 한다."""
    report = json.loads((DEMO_DIR / "final_report.json").read_text(encoding="utf-8"))
    available = {item["agent_name"] for item in report["agent_statistics"]["agents"]}
    for card in steps["step_06_report_ready.json"]["dashboard"]["agents"]:
        if card["agent_name"] in available:
            continue
        assert card["report"]["statistic_available"] is False
        assert card["report"]["execution_status"] is None
        assert card["report"]["final_findings_count"] is None
        assert card["report"]["input_item_count"] is None


@requires_demo
@pytest.mark.parametrize("name", STEP_FILES)
def test_no_normal_warning_failure_mapping_anywhere(steps, name: str) -> None:
    raw = json.dumps(steps[name], ensure_ascii=False)
    for banned in ('"normal_count": 0', '"warning_count": 0', '"failure_count": 0'):
        assert banned not in raw
    for card in steps[name]["dashboard"]["agents"]:
        assert set(card["demo_revealed"]) == {
            "findings_count",
            "finding_ids",
            "severity_counts",
            "finding_type_counts",
        }
        assert "normal" not in card["demo_revealed"]["severity_counts"]


@requires_demo
def test_operational_state_null_policy_is_preserved(steps) -> None:
    report = json.loads((DEMO_DIR / "final_report.json").read_text(encoding="utf-8"))
    state = steps["step_06_report_ready.json"]["dashboard"]["operational_state"]
    assert state == report["agent_statistics"]["operational_state"]
    assert state["normal_count"] is None
    assert state["warning_count"] is None
    assert state["failure_count"] is None
    assert state["policy"]
    for name in STEP_FILES[:6]:
        assert steps[name]["dashboard"]["operational_state"] is None


@requires_demo
def test_revealed_count_is_separate_from_report_count(steps) -> None:
    for name in STEP_FILES:
        for card in steps[name]["dashboard"]["agents"]:
            assert "findings_count" in card["demo_revealed"]
            assert "final_findings_count" in card["report"]
        assert steps[name]["dashboard"]["agent_attribution_note"]


@requires_demo
def test_authentication_agent_has_no_detector_and_no_finding(steps) -> None:
    cards = {
        card["agent_name"]: card for card in steps[STEP_FILES[6]]["dashboard"]["agents"]
    }
    auth = cards["authentication_agent"]
    assert auth["declared"]["detectors"] == []
    assert auth["demo_revealed"]["findings_count"] == 0


# ---------------------------------------------------------------------------
# 34~36. replay events / final_report 복사본
# ---------------------------------------------------------------------------


@requires_demo
def test_replay_events_come_from_real_evidence_references(replay: dict[str, Any]) -> None:
    report = json.loads((DEMO_DIR / "final_report.json").read_text(encoding="utf-8"))
    assert replay["total_count"] == EXPECTED_REPLAY_EVENTS
    assert len(replay["events"]) == EXPECTED_REPLAY_EVENTS
    assert len(replay["source_finding_ids"]) == EXPECTED_PROJECTION_FINDINGS

    # 보고서 evidence에 있는 event_id는 모두 stream에 있다.
    report_event_ids = {
        row["event_id"]
        for group in report["evidence"]["groups"]
        for row in group["items"]
    }
    stream_event_ids = {event["event_id"] for event in replay["events"]}
    assert report_event_ids <= stream_event_ids

    for index, event in enumerate(replay["events"], start=1):
        assert event["sequence"] == index
        assert event["event_id"]
        assert event["source_file"]
        assert isinstance(event["line_number"], int)
        assert event["source_type"]
        assert event["dataset"] == "gaia"
        assert event["cited_by_finding_id"] in replay["source_finding_ids"]
        # event_id는 source_file:line_number 규약을 따른다 - 조작하지 않았다.
        assert event["event_id"].endswith(f":{event['line_number']}")


@requires_demo
def test_replay_events_are_time_ordered(replay: dict[str, Any]) -> None:
    timestamps = [event["timestamp"] for event in replay["events"]]
    assert timestamps == sorted(timestamps)
    relatives = [event["relative_seconds"] for event in replay["events"]]
    assert relatives == sorted(relatives)
    assert relatives[0] >= 0.0
    assert relatives[-1] <= replay["window"]["window_length_seconds"]


@requires_demo
def test_replay_events_contain_no_fabricated_log_text(replay: dict[str, Any]) -> None:
    assert replay["raw_available"] is False
    assert replay["raw_note"]
    for event in replay["events"]:
        assert event["raw"] is None
        assert event["raw_available"] is False


@requires_demo
def test_replay_stream_includes_unrelated_service_events(replay: dict[str, Any]) -> None:
    """stream에는 여러 service가 섞여도 된다 - 좁히는 것은 Correlation/Focus 단계다."""
    services = {event["cited_by_finding_service"] for event in replay["events"]}
    assert EXPECTED_FOCUSED_SERVICE in services
    assert UNRELATED_SERVICE in services
    assert replay["stream_note"]


@requires_demo
def test_final_report_copy_hash_matches_manifest(manifest: dict[str, Any]) -> None:
    copied = DEMO_DIR / "final_report.json"
    assert demo_script.sha256_of(copied) == manifest["source_report_sha256"]
    assert json.loads(copied.read_text(encoding="utf-8"))["report_id"] == manifest[
        "source_report_id"
    ]


@requires_demo
@requires_sources
def test_final_report_copy_is_identical_to_the_original() -> None:
    assert (DEMO_DIR / "final_report.json").read_bytes() == REPORT_PATH.read_bytes()


@requires_demo
def test_identity_fields_agree_across_manifest_steps_and_report(
    manifest: dict[str, Any], steps
) -> None:
    report = json.loads((DEMO_DIR / "final_report.json").read_text(encoding="utf-8"))
    for step in steps.values():
        source = step["source"]
        assert source["report_id"] == report["report_id"] == manifest["source_report_id"]
        assert source["scenario_id"] == report["scenario_id"] == manifest["scenario_id"]
        assert source["incident_id"] == report["incident_id"] == manifest["incident_id"]
        assert source["generated_from"] == report["generated_from"]
        assert source["investigation_id"] == report["investigation_id"]


# ---------------------------------------------------------------------------
# timeline 구분 / 순수 함수
# ---------------------------------------------------------------------------


@requires_demo
@pytest.mark.parametrize("name", STEP_FILES)
def test_workflow_timeline_entries_are_tagged(steps, name: str) -> None:
    for entry in steps[name]["dashboard"]["timeline_preview"]:
        assert entry["timeline_type"] in {"observed_finding", "demo_workflow"}
        if entry["timeline_type"] == "demo_workflow":
            # 관측 event처럼 보이지 않게 finding_id/시각을 갖지 않는다.
            assert "finding_id" not in entry
            assert entry["relative_start_seconds"] is None
            assert entry["note"]
        else:
            assert entry["finding_id"]


@requires_demo
def test_observed_timeline_entries_exist_in_the_report_or_projection(steps) -> None:
    report = json.loads((DEMO_DIR / "final_report.json").read_text(encoding="utf-8"))
    known = {row["finding_id"] for row in report["timeline"]["items"]}
    projection = {
        row["finding_id"]
        for row in steps["step_02_correlation.json"]["detail"]["projection_findings"]
    }
    for name in STEP_FILES:
        for entry in steps[name]["dashboard"]["timeline_preview"]:
            if entry["timeline_type"] == "observed_finding":
                assert entry["finding_id"] in known | projection


def test_extract_citation_pages_dedupes_and_sorts() -> None:
    text = "foo [Page 84] bar [Page 11] baz [Page 84] [Page  9] qux"
    assert demo_script.extract_citation_pages(text) == [9, 11, 84]
    assert demo_script.extract_citation_pages("인용 없음") == []


def test_write_json_is_deterministic_and_rejects_nan(tmp_path: Path) -> None:
    first = demo_script.write_json(tmp_path / "a.json", {"b": 1, "a": "한글"})
    second = demo_script.write_json(tmp_path / "b.json", {"a": "한글", "b": 1})
    assert first.read_bytes() == second.read_bytes()
    assert "한글" in first.read_text(encoding="utf-8")
    with pytest.raises(ValueError):
        demo_script.write_json(tmp_path / "c.json", {"x": float("inf")})


def test_agent_attribution_uses_declared_detectors_only() -> None:
    """finding_type 문자열이 아니라 Agent.DETECTORS / Skill selector로 귀속한다."""
    from datetime import UTC, datetime

    from src.models import Finding

    moment = datetime(2021, 7, 31, 19, 10, tzinfo=UTC)
    metric_network = Finding(
        finding_id="f1",
        dataset="gaia",
        category="network",
        finding_type="network_usage_anomaly",
        start_time=moment,
        end_time=moment,
        host=None,
        service="dbservice1",
        severity="low",
        summary="s",
        detector="find_metric_anomaly",
    )
    scan = Finding(
        finding_id="f2",
        dataset="russellmitchell",
        category="security",
        finding_type="repeated_source_ip_scan",
        start_time=moment,
        end_time=moment,
        host="h",
        service="apache2",
        severity="high",
        summary="s",
        detector="find_scan_pattern",
    )
    attributed = demo_script.attribute_findings_to_agents([metric_network, scan])

    assert set(attributed) == REAL_AGENT_NAMES
    assert [f.finding_id for f in attributed["network_agent"]] == ["f1"]
    assert [f.finding_id for f in attributed["server_agent"]] == ["f1"]
    assert [f.finding_id for f in attributed["application_agent"]] == ["f2"]
    assert [f.finding_id for f in attributed["security_agent"]] == ["f2"]
    assert attributed["authentication_agent"] == []


def test_agent_attribution_ignores_unknown_detectors() -> None:
    from datetime import UTC, datetime

    from src.models import Finding

    moment = datetime(2021, 7, 31, 19, 10, tzinfo=UTC)
    unknown = Finding(
        finding_id="f3",
        dataset="gaia",
        category="performance",
        finding_type="made_up",
        start_time=moment,
        end_time=moment,
        host=None,
        service="svc",
        severity="low",
        summary="s",
        detector="find_nothing_real",
    )
    attributed = demo_script.attribute_findings_to_agents([unknown])
    assert all(not findings for findings in attributed.values())
