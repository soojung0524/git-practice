"""추가 시연 scenario 3종(demo/scenarios.py)의 demo pack 검증.

기존 tests/test_demo_replay.py(gaia_network_incident)는 그대로 두고, 여기서는
scenario 설정으로 일반화된 generator가 만든 pack을 검증한다.

실제 artifact가 없으면 skip한다 - 가짜 fixture로 숫자를 만들어 통과시키지 않는다.
외부 API를 호출하지 않는다.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from demo import SCENARIOS, SCENARIOS_BY_KEY, DemoScenario, get_scenario, make_steps

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "build_demo_replay.py"

# 이번 단계에서 추가한 scenario. 기존 gaia_network_incident는 test_demo_replay.py가 맡는다.
NEW_SCENARIO_KEYS = (
    "gaia_service_degradation",
    "gaia_server_resource_anomaly",
    "russellmitchell_web_scan",
)

REAL_AGENT_NAMES = {
    "application_agent",
    "server_agent",
    "network_agent",
    "authentication_agent",
    "security_agent",
}

# 실제 cache를 조사해서 확인한 값. demo가 이 숫자를 재생산하는지 고정한다.
EXPECTED: dict[str, dict[str, Any]] = {
    "gaia_service_degradation": {
        "anchor": "gaia:find_latency_anomaly:dbservice1:2021-07-19T23:12:12.933626+00:00",
        "incident_id": "latency-window:incident:44fbe5137bf8",
        "projection": 4,
        "candidates": 2,
        "multi": 1,
        "single": 1,
        "unselected": 1,
        "focused_findings": 3,
        "evidence": 3,
        "services": ["dbservice1"],
        "hosts": [],
        "severity": {"high": 3},
        "finding_types": {"service_latency_spike": 3},
        "grouping_basis": ["shared_entity"],
        "replay_events": 8,
        "uses_rag": False,
        "main_agent": "application_agent",
    },
    "gaia_server_resource_anomaly": {
        "anchor": (
            "gaia:find_metric_anomaly:redis_docker_cpu_user_pct:2021-07-20T09:34:55+00:00"
        ),
        "incident_id": "resource-window:incident:dc499ecd48f8",
        "projection": 13,
        "candidates": 3,
        "multi": 2,
        "single": 1,
        "unselected": 2,
        "focused_findings": 1,
        "evidence": 1,
        "services": ["redis"],
        "hosts": [],
        "severity": {"low": 1},
        "finding_types": {"cpu_usage_anomaly": 1},
        "grouping_basis": [],
        "replay_events": 17,
        "uses_rag": False,
        "main_agent": "server_agent",
    },
    "russellmitchell_web_scan": {
        "anchor": (
            "russellmitchell:find_request_spike:intranet_server:2022-01-24T03:57:00+00:00"
        ),
        "incident_id": "webscan-window:incident:67ac678edaa7",
        "projection": 2,
        "candidates": 2,
        "multi": 0,
        "single": 2,
        "unselected": 1,
        "focused_findings": 1,
        "evidence": 5,
        "services": ["apache2"],
        "hosts": ["intranet_server"],
        "severity": {"high": 1},
        "finding_types": {"request_spike": 1},
        "grouping_basis": [],
        "replay_events": 10,
        "uses_rag": True,
        "main_agent": "application_agent",
    },
}


def _load_script_module():
    spec = importlib.util.spec_from_file_location("build_demo_replay_scenarios", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


demo_script = _load_script_module()


def _demo_dir(key: str) -> Path:
    return PROJECT_ROOT / get_scenario(key).out_dir


def _has_pack(key: str) -> bool:
    return (_demo_dir(key) / "manifest.json").is_file()


def _read(key: str, name: str) -> dict[str, Any]:
    return json.loads((_demo_dir(key) / name).read_text(encoding="utf-8"))


def _manifest(key: str) -> dict[str, Any]:
    return _read(key, "manifest.json")


def _steps(key: str) -> list[dict[str, Any]]:
    return [_read(key, step["file"]) for step in _manifest(key)["steps"]]


def _all_files(key: str) -> list[str]:
    manifest = _manifest(key)
    return [
        "manifest.json",
        manifest["replay_event_file"],
        manifest["source_report_file"],
        *[step["file"] for step in manifest["steps"]],
    ]


def _blob(key: str) -> str:
    """pack 전체를 하나의 문자열로. 금지 표현 검사에 쓴다."""
    return "".join(
        (_demo_dir(key) / name).read_text(encoding="utf-8") for name in _all_files(key)
    )


pytestmark = pytest.mark.parametrize("key", NEW_SCENARIO_KEYS)


def _skip_if_missing(key: str) -> None:
    if not _has_pack(key):
        pytest.skip(f"{key} demo artifact가 없다 (scripts/build_demo_replay.py --all 실행)")


# ---------------------------------------------------------------------------
# 1~8. 산출물 / JSON 규칙 / 결정론
# ---------------------------------------------------------------------------


def test_directory_and_files_exist(key: str) -> None:
    _skip_if_missing(key)
    for name in _all_files(key):
        assert (_demo_dir(key) / name).is_file(), f"{key}/{name}"


def test_seven_steps_in_order(key: str) -> None:
    _skip_if_missing(key)
    manifest = _manifest(key)
    assert manifest["step_count"] == 7
    assert [step["order"] for step in manifest["steps"]] == list(range(7))
    for index, step in enumerate(_steps(key)):
        assert step["demo"]["step_index"] == index
        assert step["demo"]["step_count"] == 7
        assert step["demo"]["demo_only"] is True
        assert step["demo"]["presentation_metadata_note"]
    assert _steps(key)[-1]["demo"]["is_last_step"] is True


def test_json_is_utf8_without_nan(key: str) -> None:
    _skip_if_missing(key)

    def reject(value: str) -> None:  # pragma: no cover - 통과 시 호출되지 않는다
        raise AssertionError(f"JSON 표준이 아닌 상수: {value}")

    for name in _all_files(key):
        raw = (_demo_dir(key) / name).read_text(encoding="utf-8")
        assert isinstance(json.loads(raw, parse_constant=reject), dict)
        assert "\\u" not in raw


def test_regeneration_is_byte_identical(key: str, tmp_path: Path) -> None:
    _skip_if_missing(key)
    scenario = get_scenario(key)
    if not (
        (PROJECT_ROOT / scenario.findings_path).is_file()
        and (PROJECT_ROOT / scenario.report_path).is_file()
    ):
        pytest.skip("원본 Finding/보고서 파일이 없다")

    import dataclasses

    outputs = []
    for index in (0, 1):
        out = tmp_path / f"run{index}"
        demo_script.build_scenario(dataclasses.replace(scenario, out_dir=str(out)))
        outputs.append(out)
    for name in _all_files(key):
        assert (outputs[0] / name).read_bytes() == (outputs[1] / name).read_bytes(), name


def test_manifest_has_required_fields(key: str) -> None:
    _skip_if_missing(key)
    manifest = _manifest(key)
    required = {
        "demo_schema_version",
        "demo_only",
        "scenario_key",
        "title",
        "generated_by",
        "external_calls",
        "source_report_id",
        "source_report_file",
        "source_report_origin",
        "source_report_sha256",
        "source_findings_file",
        "scenario_id",
        "incident_id",
        "anchor_finding_id",
        "replay_event_file",
        "replay_event_count",
        "step_count",
        "presentation_metadata_note",
        "steps",
    }
    assert required <= set(manifest)
    assert manifest["scenario_key"] == key
    assert manifest["external_calls"] == {
        "openai": False,
        "supabase": False,
        "rag_agent": False,
        "llm": False,
        "detector_rerun": False,
    }


# ---------------------------------------------------------------------------
# 9~14. 실제 분석 수치 / anchor / focus
# ---------------------------------------------------------------------------


def test_anchor_matches_the_configured_real_finding(key: str) -> None:
    _skip_if_missing(key)
    expected = EXPECTED[key]
    assert get_scenario(key).anchor_finding_id == expected["anchor"]
    assert _manifest(key)["anchor_finding_id"] == expected["anchor"]
    for step in _steps(key):
        assert step["source"]["anchor_finding_id"] == expected["anchor"]


def test_counts_match_the_real_pipeline_result(key: str) -> None:
    _skip_if_missing(key)
    expected = EXPECTED[key]
    counters = _steps(key)[-1]["dashboard"]["counters"]
    assert counters["projection_finding_count"] == expected["projection"]
    assert counters["candidate_incident_count"] == expected["candidates"]
    assert counters["multi_finding_incident_count"] == expected["multi"]
    assert counters["single_finding_incident_count"] == expected["single"]
    assert counters["focused_incident_count"] == 1
    assert counters["unselected_candidate_incident_count"] == expected["unselected"]
    assert counters["unmatched_anchor_count"] == 0


def test_focused_incident_contains_the_anchor(key: str) -> None:
    _skip_if_missing(key)
    expected = EXPECTED[key]
    focused = _steps(key)[-1]["detail"]["focused_incident"]
    assert focused["incident_id"] == expected["incident_id"] == _manifest(key)["incident_id"]
    assert expected["anchor"] in focused["finding_ids"]
    assert focused["finding_count"] == expected["focused_findings"]
    assert focused["correlation_basis"]["grouping_basis"] == expected["grouping_basis"]


def test_impact_and_evidence_are_the_real_values(key: str) -> None:
    _skip_if_missing(key)
    expected = EXPECTED[key]
    focused = _steps(key)[-1]["detail"]["focused_incident"]
    assert focused["impact"]["affected_services"] == expected["services"]
    assert focused["impact"]["affected_hosts"] == expected["hosts"]
    assert focused["impact"]["severity_counts"] == expected["severity"]
    assert focused["impact"]["finding_type_counts"] == expected["finding_types"]
    assert focused["evidence"]["total_evidence_count"] == expected["evidence"]


def test_hypotheses_are_kept_as_is(key: str) -> None:
    _skip_if_missing(key)
    report = _read(key, "final_report.json")
    focused = _steps(key)[-1]["detail"]["focused_incident"]
    assert focused["hypotheses"] == report["hypotheses"]
    if not focused["hypotheses"]:
        assert focused["hypotheses_note"] == "현재 규칙을 만족하는 가설 후보가 없음"
    # Root Cause를 만들지 않는다.
    assert "Root Cause 없음" not in _blob(key)


def test_unselected_incidents_do_not_leak_into_focused_detail(key: str) -> None:
    _skip_if_missing(key)
    last = _steps(key)[-1]
    focused_raw = json.dumps(last["detail"]["focused_incident"], ensure_ascii=False)
    candidates = last["detail"]["candidates"]
    assert len(candidates["unselected_incidents"]) == EXPECTED[key]["unselected"]
    for incident in candidates["unselected_incidents"]:
        assert incident["incident_id"] not in focused_raw
        for finding_id in _unselected_finding_ids(key, incident["incident_id"]):
            assert finding_id not in focused_raw


def _unselected_finding_ids(key: str, incident_id: str) -> list[str]:
    """unselected incident에 속한 Finding ID. projection 목록에서 역으로 찾는다."""
    focused = _steps(key)[-1]["detail"]["focused_incident"]["finding_ids"]
    projected = [
        row["finding_id"]
        for row in _steps(key)[-1]["detail"]["projection_findings"]
    ]
    return [fid for fid in projected if fid not in focused]


def test_guidance_question_has_no_unselected_incident(key: str) -> None:
    _skip_if_missing(key)
    guidance = _steps(key)[-1]["detail"]["security_guidance"]
    if guidance["question"] is None:
        pytest.skip("이 scenario는 Security Guidance를 요청하지 않았다")
    candidates = _steps(key)[-1]["detail"]["candidates"]
    for incident in candidates["unselected_incidents"]:
        assert incident["incident_id"] not in guidance["question"]


# ---------------------------------------------------------------------------
# 15~16. replay events
# ---------------------------------------------------------------------------


def test_replay_events_are_real_evidence_references(key: str) -> None:
    _skip_if_missing(key)
    manifest = _manifest(key)
    replay = _read(key, manifest["replay_event_file"])
    report = _read(key, "final_report.json")

    assert replay["total_count"] == EXPECTED[key]["replay_events"]
    assert len(replay["events"]) == replay["total_count"] == manifest["replay_event_count"]
    assert len(replay["source_finding_ids"]) == EXPECTED[key]["projection"]

    report_event_ids = {
        row["event_id"] for group in report["evidence"]["groups"] for row in group["items"]
    }
    stream_event_ids = {event["event_id"] for event in replay["events"]}
    assert report_event_ids <= stream_event_ids

    for index, event in enumerate(replay["events"], start=1):
        assert event["sequence"] == index
        assert event["event_id"].endswith(f":{event['line_number']}")
        assert event["cited_by_finding_id"] in replay["source_finding_ids"]
        assert event["source_type"]
        assert event["source_file"]
    timestamps = [event["timestamp"] for event in replay["events"]]
    assert timestamps == sorted(timestamps)


def test_replay_events_have_no_fabricated_log_text(key: str) -> None:
    _skip_if_missing(key)
    replay = _read(key, _manifest(key)["replay_event_file"])
    assert replay["raw_available"] is False
    assert replay["raw_note"]
    for event in replay["events"]:
        assert event["raw"] is None
        assert event["raw_available"] is False


# ---------------------------------------------------------------------------
# 17~19. Agent 카드 / 운영 상태
# ---------------------------------------------------------------------------


def test_only_the_five_real_agents_appear(key: str) -> None:
    _skip_if_missing(key)
    for step in _steps(key):
        names = [card["agent_name"] for card in step["dashboard"]["agents"]]
        assert set(names) == REAL_AGENT_NAMES
        assert len(names) == len(set(names))


def test_agent_health_is_not_invented(key: str) -> None:
    _skip_if_missing(key)
    report = _read(key, "final_report.json")
    available = {item["agent_name"] for item in report["agent_statistics"]["agents"]}
    for card in _steps(key)[-1]["dashboard"]["agents"]:
        if card["agent_name"] in available:
            continue
        assert card["report"]["statistic_available"] is False
        assert card["report"]["execution_status"] is None
        assert card["report"]["final_findings_count"] is None


def test_main_agent_reveals_the_anchor_finding(key: str) -> None:
    _skip_if_missing(key)
    expected = EXPECTED[key]
    cards = {c["agent_name"]: c for c in _steps(key)[1]["dashboard"]["agents"]}
    main = cards[expected["main_agent"]]
    assert main["demo_revealed"]["finding_ids"] == [expected["anchor"]]
    assert _steps(key)[0]["dashboard"]["counters"]["revealed_findings_count"] == 0


def test_no_normal_warning_failure_mapping(key: str) -> None:
    _skip_if_missing(key)
    report = _read(key, "final_report.json")
    state = _steps(key)[-1]["dashboard"]["operational_state"]
    assert state == report["agent_statistics"]["operational_state"]
    assert state["normal_count"] is None
    assert state["warning_count"] is None
    assert state["failure_count"] is None
    for step in _steps(key):
        for card in step["dashboard"]["agents"]:
            assert set(card["demo_revealed"]["severity_counts"]) <= {
                "low",
                "medium",
                "high",
                "critical",
            }


# ---------------------------------------------------------------------------
# 20~22. final_report 복사본 / step 공개 순서
# ---------------------------------------------------------------------------


def test_final_report_copy_hash_matches(key: str) -> None:
    _skip_if_missing(key)
    manifest = _manifest(key)
    copied = _demo_dir(key) / manifest["source_report_file"]
    assert demo_script.sha256_of(copied) == manifest["source_report_sha256"]
    origin = PROJECT_ROOT / manifest["source_report_origin"]
    if origin.is_file():
        assert copied.read_bytes() == origin.read_bytes()


def test_step_reveal_order(key: str) -> None:
    _skip_if_missing(key)
    steps = _steps(key)
    assert steps[0]["dashboard"]["counters"]["revealed_findings_count"] == 0
    assert steps[0]["dashboard"]["timeline_preview"] == []
    assert steps[0]["detail"]["candidates"] is None
    assert steps[0]["detail"]["focused_incident"] is None
    assert steps[1]["dashboard"]["counters"]["revealed_findings_count"] == 1
    assert steps[2]["detail"]["candidates"]["selection_completed"] is False
    assert steps[2]["detail"]["focused_incident"] is None
    assert steps[3]["detail"]["candidates"]["selection_completed"] is True
    assert steps[3]["detail"]["focused_incident"] is not None
    assert steps[-1]["dashboard"]["status"]["report"] == "ready"
    assert steps[-1]["detail"]["final_report_file"] == "final_report.json"
    # 보고서 준비 전 단계는 final_report를 가리키지 않는다.
    for step in steps[:-1]:
        assert step["detail"]["final_report_file"] is None


def test_step_00_does_not_claim_a_normal_state(key: str) -> None:
    _skip_if_missing(key)
    step = _steps(key)[0]
    note = step["demo"]["step_note"]
    assert "'정상' 또는 '문제 없음'을 뜻하지 않는다" in note
    raw = json.dumps(step, ensure_ascii=False).replace(note, "")
    for banned in ("문제 없음", "시스템 정상", "이상 없음"):
        assert banned not in raw, banned
    assert step["dashboard"]["operational_state"] is None


def test_workflow_timeline_entries_are_tagged(key: str) -> None:
    _skip_if_missing(key)
    for step in _steps(key):
        for entry in step["dashboard"]["timeline_preview"]:
            assert entry["timeline_type"] in {"observed_finding", "demo_workflow"}
            if entry["timeline_type"] == "demo_workflow":
                assert "finding_id" not in entry
                assert entry["relative_start_seconds"] is None
            else:
                assert entry["finding_id"]


# ---------------------------------------------------------------------------
# RAG 사용 여부별 표현
# ---------------------------------------------------------------------------


def test_guidance_status_matches_whether_rag_was_used(key: str) -> None:
    _skip_if_missing(key)
    scenario = get_scenario(key)
    assert scenario.uses_rag == EXPECTED[key]["uses_rag"]
    report = _read(key, "final_report.json")
    steps = _steps(key)

    if scenario.uses_rag:
        assert report["security_guidance"] is not None
        assert [s["detail"]["security_guidance"]["status"] for s in steps] == [
            "not_started",
            "not_started",
            "not_started",
            "not_started",
            "analyzing",
            "completed",
            "completed",
        ]
        analyzing = steps[4]["detail"]["security_guidance"]
        assert analyzing["question"]
        assert analyzing["response"] is None
        assert analyzing["demo_derived"] is None
        item = report["security_guidance"]["items"][0]
        for step in steps[5:]:
            guidance = step["detail"]["security_guidance"]
            assert guidance["response"] == item["response"]  # 원문 보존
            assert "[Page" in guidance["response"]
            assert guidance["demo_derived"]["citation_pages"]
    else:
        # RAG가 없는 scenario를 "보안 가이던스 완료"처럼 보이게 하지 않는다.
        assert report["security_guidance"] is None
        for step in steps:
            guidance = step["detail"]["security_guidance"]
            assert guidance["status"] == "not_requested"
            assert guidance["response"] is None
            assert guidance["available"] is False
            assert guidance["not_requested_reason"]
        assert all(
            step["demo"]["phase"] not in {"rag_analyzing", "rag_completed"} for step in steps
        )


def test_narrative_is_revealed_at_the_right_step(key: str) -> None:
    _skip_if_missing(key)
    scenario = get_scenario(key)
    steps = _steps(key)
    report = _read(key, "final_report.json")
    assert report["narrative_summary"]["text"]

    first_revealed = next(
        index for index, s in enumerate(steps) if s["detail"]["narrative_summary"] is not None
    )
    assert first_revealed == (6 if scenario.uses_rag else 5)
    for step in steps[:first_revealed]:
        assert step["detail"]["narrative_summary"] is None
    assert steps[-1]["detail"]["narrative_summary"] == report["narrative_summary"]


# ---------------------------------------------------------------------------
# scenario별 금지 표현 (실제 데이터가 말하지 않는 것)
# ---------------------------------------------------------------------------

_BANNED_BY_SCENARIO: dict[str, tuple[str, ...]] = {
    # 실제 Finding은 응답 지연만 말한다. DB 원인 문구를 넣지 않는다.
    "gaia_service_degradation": (
        "connection pool",
        "커넥션 풀",
        "slow query",
        "슬로우 쿼리",
        "index 누락",
        "API timeout 원인",
    ),
    # cache에 존재하는 resource Finding은 cpu_usage_anomaly뿐이다.
    "gaia_server_resource_anomaly": (
        "memory_usage_anomaly",
        "메모리 이상",
        "디스크 이상",
        "process crash",
        "프로세스 크래시",
        "CPU 때문",
        "CPU로 인해",
    ),
    # detector가 말하는 것은 요청 급증 / 반복 경로 접근 / 404 비율 / scan pattern까지다.
    "russellmitchell_web_scan": (
        "WordPress",
        "wordpress",
        "webshell",
        "웹쉘",
        "CVE",
        "dnsteal",
        "데이터 유출",
        "공격이 성공",
        "침해가 발생",
        "권한 상승",
    ),
}


def test_scenario_does_not_invent_undetected_facts(key: str) -> None:
    _skip_if_missing(key)
    blob = _blob(key)
    hits = [word for word in _BANNED_BY_SCENARIO[key] if word in blob]
    assert hits == [], f"{key}: 탐지되지 않은 내용이 들어갔다 - {hits}"


def test_scenario_uses_the_real_finding_type(key: str) -> None:
    _skip_if_missing(key)
    expected_types = set(EXPECTED[key]["finding_types"])
    focused = _steps(key)[-1]["detail"]["focused_incident"]
    assert set(focused["impact"]["finding_type_counts"]) == expected_types
    for row in focused["findings"]["items"]["items"]:
        assert row["finding_type"] in expected_types
    # title도 관측된 service/host 이름만 쓴다.
    title = _manifest(key)["title"]
    identifiers = EXPECTED[key]["services"] + EXPECTED[key]["hosts"]
    assert any(name in title for name in identifiers), title


def test_web_scan_evidence_comes_from_apache_logs(key: str) -> None:
    _skip_if_missing(key)
    if key != "russellmitchell_web_scan":
        pytest.skip("scenario C 전용")
    replay = _read(key, _manifest(key)["replay_event_file"])
    assert {event["source_type"] for event in replay["events"]} == {"apache_access"}
    assert all("apache2" in event["source_file"] for event in replay["events"])
    focused = _steps(key)[-1]["detail"]["focused_incident"]
    for group in focused["evidence"]["groups"]:
        for row in group["items"]:
            assert row["source_type"] == "apache_access"


def test_security_agent_sees_the_scan_finding(key: str) -> None:
    _skip_if_missing(key)
    if key != "russellmitchell_web_scan":
        pytest.skip("scenario C 전용")
    cards = {c["agent_name"]: c for c in _steps(key)[-1]["dashboard"]["agents"]}
    security = cards["security_agent"]
    # scan Finding은 security selector가 고르지만 조사 대상 incident는 아니다.
    assert security["demo_revealed"]["findings_count"] == 1
    scan_id = security["demo_revealed"]["finding_ids"][0]
    assert "find_scan_pattern" in scan_id
    assert scan_id not in _steps(key)[-1]["detail"]["focused_incident"]["finding_ids"]


# ---------------------------------------------------------------------------
# 설정 자체에 대한 테스트 (artifact 없이도 돈다)
# ---------------------------------------------------------------------------


def test_scenario_config_is_consistent(key: str) -> None:
    scenario = get_scenario(key)
    assert scenario.scenario_key == key
    assert scenario.out_dir.endswith(key)
    assert scenario.anchor_finding_id == EXPECTED[key]["anchor"]
    assert scenario.uses_rag == EXPECTED[key]["uses_rag"]
    assert scenario.window_minutes == 20
    assert scenario.lead_minutes == 10
    if scenario.uses_rag:
        assert scenario.guidance_not_requested_reason is None
    else:
        assert scenario.guidance_not_requested_reason


def test_step_layout_matches_rag_usage(key: str) -> None:
    scenario = get_scenario(key)
    files = [spec.file for spec in scenario.steps]
    assert len(files) == 7
    if scenario.uses_rag:
        assert files[4:6] == ["step_04_rag_analyzing.json", "step_05_rag_completed.json"]
    else:
        assert files[4:6] == ["step_04_analysis.json", "step_05_analysis_completed.json"]
    assert make_steps(uses_rag=scenario.uses_rag) == scenario.steps


@pytest.mark.parametrize("ignored", [None])
def test_registry_has_four_unique_scenarios(key: str, ignored: None) -> None:
    assert len(SCENARIOS) == 4
    assert len(SCENARIOS_BY_KEY) == 4
    assert "gaia_network_incident" in SCENARIOS_BY_KEY
    assert set(NEW_SCENARIO_KEYS) < set(SCENARIOS_BY_KEY)
    out_dirs = [s.out_dir for s in SCENARIOS]
    assert len(set(out_dirs)) == len(out_dirs)
    anchors = [s.anchor_finding_id for s in SCENARIOS]
    assert len(set(anchors)) == len(anchors)
    with pytest.raises(KeyError):
        get_scenario("does_not_exist")
    assert all(isinstance(s, DemoScenario) for s in SCENARIOS)
