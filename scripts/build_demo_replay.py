"""발표/시연용 pseudo-real-time demo JSON pack을 만든다.

실시간 backend를 만들지 않는다. 이미 생성된 **실제** 분석 결과를 시간 순서대로 읽을 수
있게 재배열하기만 한다. 웹팀은 API server 없이 manifest.json -> step_NN_*.json 순서로
파일을 읽으며 화면을 바꿀 수 있다.

사실 데이터의 출처는 두 개뿐이다.

  1. output/reports/<report>.json  - 최종 IncidentReport (security_guidance / narrative_summary 포함)
  2. output/findings/<dataset>.pkl - 저장된 Finding (scenario projection / correlation / focus 재계산용)

호출하지 않는 것: OpenAI, Supabase, rag_agent, search_runbook, embedding, LLM.
다시 실행하지 않는 것: detector.
만들지 않는 것: Finding, Agent, raw log 문장, Root Cause, host/service/IP, severity 변경.

projection / correlation / focus는 기존 코드(scenario, correlation)를 그대로 호출해
재계산한다. 이것은 순수 함수이며 외부 호출이 없고, 최종 보고서와 같은 Window/anchor를
쓰므로 같은 결과가 나온다(incident_id / scenario_id 일치를 생성 시점에 검증한다).

사용:

    python scripts/build_demo_replay.py \
        --report output/reports/gaia-final_report_e4977bb394b7.json \
        --findings output/findings/gaia.pkl \
        --out output/demo/gaia_network_incident
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent_skills.network_analysis.scripts import run_network_analysis as network_skill  # noqa: E402
from agent_skills.security_analysis.scripts import run_security_analysis as security_skill  # noqa: E402
from agents import (  # noqa: E402
    ApplicationAgent,
    AuthenticationAgent,
    NetworkAgent,
    SecurityAgent,
    ServerAgent,
)
from correlation import correlate_scenario, focus_on, select_incidents  # noqa: E402
from demo import SCENARIOS, DemoScenario, StepSpec, get_scenario, make_steps  # noqa: E402
from demo.scenarios import (  # noqa: E402
    PHASE_ANALYSIS_COMPLETED,
    PHASE_ANALYZING,
    PHASE_COLLECTING,
    PHASE_CORRELATING,
    PHASE_FINDING_DETECTED,
    PHASE_FOCUS_SELECTED,
    PHASE_RAG_ANALYZING,
    PHASE_RAG_COMPLETED,
    PHASE_REPORT_READY,
)
from scenario import make_analysis_scenario, project_findings  # noqa: E402
from src.models import Finding  # noqa: E402
from src.models.finding_store import load_findings  # noqa: E402

DEMO_SCHEMA_VERSION = "1.0"

DEFAULT_REPORT = "output/reports/gaia-final_report_e4977bb394b7.json"
DEFAULT_FINDINGS = "output/findings/gaia.pkl"
DEFAULT_OUT = "output/demo/gaia_network_incident"
DEFAULT_SCENARIO_KEY = "gaia_network_incident"

# 최종 보고서를 만들 때 쓴 값과 같아야 한다(scripts/build_incident_report.py 기본값).
DEFAULT_SCENARIO_ID = "report-window"
DEFAULT_WINDOW_MINUTES = 20
DEFAULT_LEAD_MINUTES = 10
DEFAULT_ANCHOR_FINDING_TYPE = "network_usage_anomaly"
DEFAULT_ANCHOR_SERVICE = "dbservice1"

FINAL_REPORT_FILE = "final_report.json"
REPLAY_EVENT_FILE = "replay_events.json"
MANIFEST_FILE = "manifest.json"

# --- presentation metadata ------------------------------------------------
#
# phase / phase_label / recommended_delay_ms는 **시연 진행용** 값이다. 실제 사건 발생
# 시각도 아니고 분석에 걸린 시간도 아니다. 실제 분석 값과 섞이지 않도록 모든 step JSON의
# "demo" 블록 안에만 둔다.
PRESENTATION_NOTE = (
    "phase / phase_label / recommended_delay_ms / step_index는 시연 진행용 "
    "presentation metadata다. 실제 사건 발생 시각도, 분석에 걸린 시간도 아니다. "
    "실제 분석 값은 source / dashboard / detail 블록에 있다."
)

GUIDANCE_NOT_STARTED = "not_started"
# RAG를 호출하지 않은 scenario. "아직 응답이 안 왔다"가 아니라 "요청하지 않았다"는
# 뜻이며, 보안 가이던스가 완료된 것처럼 보이지 않게 완료 상태와 구분한다.
GUIDANCE_NOT_REQUESTED = "not_requested"
GUIDANCE_ANALYZING = "analyzing"
GUIDANCE_COMPLETED = "completed"

REPORT_NOT_READY = "not_ready"
REPORT_READY = "ready"

# step 00에서 "정상 / 문제 없음"이라고 쓰지 않는다. 이 시스템에는 정상 상태를 관측하는
# 모델이 없다(report/models.py OPERATIONAL_STATE_POLICY).
COLLECTING_NOTE = (
    "데이터 수집·분석 중이며 아직 공개된 Finding이 없는 단계다. "
    "이것은 '정상' 또는 '문제 없음'을 뜻하지 않는다 - 이 시스템은 이상 징후만 관측하며 "
    "정상 상태를 관측하는 모델이 없다."
)

HYPOTHESES_EMPTY_NOTE = "현재 규칙을 만족하는 가설 후보가 없음"

UNSELECTED_NOTE = (
    "같은 분석 Window 안에 함께 존재했을 뿐이며, 조사 대상 incident의 원인이나 "
    "관련 incident가 아니다. 조사 대상은 anchor Finding으로 지정됐다."
)

RAW_NOTE = (
    "EvidenceReference에는 원본 로그 문장이 없다(source_type / source_file / "
    "line_number / event_id / timestamp만 있다). 화면을 채우기 위해 로그 문장을 "
    "만들지 않았으므로 raw는 null이다. 원본은 source_file의 line_number로 찾을 수 있다."
)

AGENT_ATTRIBUTION_NOTE = (
    "demo_revealed.findings_count는 Finding.detector와 각 Agent Skill이 선언한 "
    "DETECTORS, 그리고 Skill이 실제로 제공하는 selector 함수로 귀속한 demo 파생 값이다. "
    "finding_type 문자열로 추측하지 않았다. server_analysis와 network_analysis가 같은 "
    "detector(find_metric_anomaly)를 공유하고 security_analysis는 이미 만들어진 Finding을 "
    "고르는 selector이므로, 한 Finding이 두 Agent 카드에 함께 집계될 수 있다 - 카드 합계는 "
    "전체 Finding 수와 일치하지 않는다. report 블록의 execution_status / input_item_count는 "
    "최종 보고서의 agent_statistics에서만 가져오며, 없으면 null이다(임의로 만들지 않는다)."
)

CITATION_NOTE = (
    "실제 RAG 응답 문자열에서 '[Page N]' 패턴만 추출해 중복을 제거하고 숫자순으로 정렬한 "
    "demo 파생 필드다. canonical report field가 아니며 response 원문은 수정하지 않았다."
)

_PAGE_RE = re.compile(r"\[Page\s+(\d+)")


# ---------------------------------------------------------------------------
# JSON 쓰기 (결정론적)
# ---------------------------------------------------------------------------


def write_json(path: Path, payload: Any) -> Path:
    """report/serialize.py와 같은 규칙으로 쓴다.

    UTF-8 / ensure_ascii=False / sort_keys=True / allow_nan=False.
    생성 시각 같은 값을 넣지 않으므로 같은 입력이면 바이트 동일 파일이 나온다.
    """
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False, indent=2)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")
    return path


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


# ---------------------------------------------------------------------------
# Agent 귀속 (demo 파생)
# ---------------------------------------------------------------------------

# (Agent class, 그 Agent Skill 모듈). 실제 구현된 Agent 5개뿐이며 가상 Agent를 넣지 않는다.
AGENT_SPECS = (
    (ApplicationAgent, None),
    (ServerAgent, None),
    (NetworkAgent, network_skill),
    (AuthenticationAgent, None),
    (SecurityAgent, security_skill),
)


def _by_detector(findings: list[Finding], detectors: tuple[str, ...]) -> list[Finding]:
    return [f for f in findings if f.detector in detectors]


def attribute_findings_to_agents(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Finding을 Agent에 귀속한다. 추측하지 않고 실제 코드 선언만 쓴다.

    - detector를 직접 실행하는 Skill(application / server / network): 그 Agent의
      DETECTORS에 선언된 detector가 만든 Finding.
    - network_analysis는 그 위에 자기 selector(select_network_findings)를 적용한다.
    - security_analysis는 detector를 실행하지 않는 selector다(DETECTORS == ()).
      그래서 run_security_analysis()를 그대로 호출해 귀속한다.
    - authentication_analysis는 연결된 detector가 없다(DETECTORS == ()) - 항상 0건이다.
    """
    result: dict[str, list[Finding]] = {}
    for agent_cls, skill in AGENT_SPECS:
        if agent_cls is SecurityAgent:
            # selector-only Agent. 입력이 Finding이므로 detector gate를 쓰지 않는다.
            selected = security_skill.run_security_analysis(findings)
        else:
            selected = _by_detector(findings, agent_cls.DETECTORS)
            if skill is network_skill:
                selected = network_skill.select_network_findings(selected)
        result[agent_cls.AGENT_NAME] = selected
    return result


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return dict(sorted(counts.items()))


def _finding_type_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.finding_type] = counts.get(finding.finding_type, 0) + 1
    return dict(sorted(counts.items()))


def build_agent_cards(
    revealed: list[Finding], report_agent_statistics: dict[str, Any]
) -> list[dict[str, Any]]:
    """Agent 카드. 실제 구현된 5개만 만든다."""
    by_name = {item["agent_name"]: item for item in report_agent_statistics.get("agents", [])}
    attributed = attribute_findings_to_agents(revealed)

    cards: list[dict[str, Any]] = []
    for agent_cls, _skill in AGENT_SPECS:
        name = agent_cls.AGENT_NAME
        mine = attributed[name]
        stat = by_name.get(name)
        cards.append(
            {
                "agent_name": name,
                "declared": {
                    "skill_name": agent_cls.SKILL_NAME,
                    "detectors": list(agent_cls.DETECTORS),
                },
                # 최종 보고서의 agent_statistics에서만 가져온다. 보고서가 저장된
                # Finding으로 만들어졌다면 AgentResult가 없으므로 전부 null이다.
                "report": {
                    "statistic_available": stat is not None,
                    "execution_status": None if stat is None else stat["execution_status"],
                    "input_item_count": None if stat is None else stat["input_item_count"],
                    "final_findings_count": None if stat is None else stat["findings_count"],
                    "skills_used": None if stat is None else list(stat["skills_used"]),
                    "detectors_used": None if stat is None else list(stat["detectors_used"]),
                    "notes": [] if stat is None else list(stat["notes"]),
                },
                "demo_revealed": {
                    "findings_count": len(mine),
                    "finding_ids": [f.finding_id for f in mine],
                    "severity_counts": _severity_counts(mine),
                    "finding_type_counts": _finding_type_counts(mine),
                },
            }
        )
    return cards


# ---------------------------------------------------------------------------
# timeline / finding 표시용 변환
# ---------------------------------------------------------------------------


def timeline_entry_to_dict(entry: Any) -> dict[str, Any]:
    """correlation.TimelineEntry -> 화면용 dict. 값을 바꾸지 않는다."""
    return {
        "timeline_type": "observed_finding",
        "finding_id": entry.finding_id,
        "dataset": entry.dataset,
        "relative_start_seconds": entry.relative_start_seconds,
        "relative_end_seconds": entry.relative_end_seconds,
        "original_start_time": _iso(entry.original_start_time),
        "original_end_time": _iso(entry.original_end_time),
        "category": entry.category,
        "finding_type": entry.finding_type,
        "severity": entry.severity,
        "host": entry.host,
        "service": entry.service,
        "summary": entry.summary,
        "was_clipped": entry.was_clipped,
        "is_long_span": entry.is_long_span,
    }


def workflow_timeline_entry(label: str) -> dict[str, Any]:
    """시연 진행 표시용 항목. 관측된 event가 아니므로 timeline_type으로 구분한다."""
    return {
        "timeline_type": "demo_workflow",
        "label": label,
        "note": (
            "분석 workflow 진행 표시이며 관측된 event가 아니다. "
            "실제 incident timeline과 섞어 관측 event처럼 취급하지 말 것."
        ),
        "relative_start_seconds": None,
        "relative_end_seconds": None,
    }


def scenario_finding_to_dict(scenario_finding: Any) -> dict[str, Any]:
    finding = scenario_finding.finding
    return {
        "finding_id": finding.finding_id,
        "dataset": finding.dataset,
        "category": finding.category,
        "finding_type": finding.finding_type,
        "severity": finding.severity,
        "detector": finding.detector,
        "host": finding.host,
        "service": finding.service,
        "original_start_time": _iso(finding.start_time),
        "original_end_time": _iso(finding.end_time),
        "relative_start_seconds": scenario_finding.relative_effective_start_seconds,
        "relative_end_seconds": scenario_finding.relative_effective_end_seconds,
        "summary": finding.summary,
        "evidence_count": len(finding.evidence),
    }


def incident_to_candidate_dict(incident: Any) -> dict[str, Any]:
    return {
        "incident_id": incident.incident_id,
        "finding_count": incident.finding_count,
        "is_single_finding": incident.is_single_finding,
        "datasets": list(incident.datasets),
        "affected_services": list(incident.impact.affected_services),
        "affected_hosts": list(incident.impact.affected_hosts),
        "relative_start_seconds": incident.relative_start_seconds,
        "relative_end_seconds": incident.relative_end_seconds,
        "finding_type_counts": dict(sorted(incident.impact.finding_type_counts.items())),
        "severity_counts": dict(sorted(incident.impact.severity_counts.items())),
        "grouping_basis": list(incident.grouping_basis),
    }


# ---------------------------------------------------------------------------
# replay events
# ---------------------------------------------------------------------------


def build_replay_events(projection: Any, window: Any) -> list[dict[str, Any]]:
    """projection에 들어온 Finding의 EvidenceReference를 시간순으로 늘어놓는다.

    가짜 로그를 만들지 않는다. EvidenceReference에 없는 값(raw/message)은 null이고
    raw_available=false다. host/service는 그 evidence를 인용한 Finding의 값이며,
    evidence 자체의 속성이 아니라는 점을 필드 이름(cited_by_*)으로 구분한다.
    """
    rows: list[dict[str, Any]] = []
    for scenario_finding in projection.findings:
        finding = scenario_finding.finding
        for ref in finding.evidence:
            rows.append(
                {
                    "event_id": ref.event_id,
                    "timestamp": _iso(ref.timestamp),
                    "relative_seconds": (
                        None if ref.timestamp is None else window.relative_seconds(ref.timestamp)
                    ),
                    "dataset": finding.dataset,
                    "source_type": ref.source_type,
                    "source_file": ref.source_file,
                    "line_number": ref.line_number,
                    "cited_by_finding_id": finding.finding_id,
                    "cited_by_finding_type": finding.finding_type,
                    "cited_by_finding_host": finding.host,
                    "cited_by_finding_service": finding.service,
                    "raw": None,
                    "raw_available": False,
                }
            )

    rows.sort(
        key=lambda row: (
            row["timestamp"] is None,
            row["timestamp"] or "",
            row["source_file"],
            row["line_number"],
            row["cited_by_finding_id"],
        )
    )
    for index, row in enumerate(rows, start=1):
        row["sequence"] = index
    return rows


# ---------------------------------------------------------------------------
# security guidance 블록
# ---------------------------------------------------------------------------


def extract_citation_pages(response: str) -> list[int]:
    """response에서 [Page N]만 뽑아 중복 제거 후 숫자순 정렬. 원문은 건드리지 않는다."""
    return sorted({int(match.group(1)) for match in _PAGE_RE.finditer(response)})


def build_guidance_block(
    report: dict[str, Any], status: str, *, not_requested_reason: str | None = None
) -> dict[str, Any]:
    """step 단계에 따라 공개 범위를 다르게 한 guidance 블록.

    status는 시연 단계 표시이며 실제 runtime 기록이 아니다(demo 블록의 phase와 짝).
    공개할 때 response는 보고서 원문을 그대로 쓴다 - 요약·재작성하지 않는다.
    """
    guidance = report.get("security_guidance")
    block: dict[str, Any] = {
        "status": status,
        "status_is_presentation_state": True,
        "available": guidance is not None,
        "focused_incident_ids": None,
        "failed_incident_ids": None,
        "incident_id": None,
        "question": None,
        "provider_name": None,
        "model": None,
        "response": None,
        "notes": None,
        "source_note": None if guidance is None else guidance["source_note"],
        "demo_derived": None,
        # RAG를 쓰지 않은 scenario에서만 값이 있다. 왜 호출하지 않았는지 남긴다.
        "not_requested_reason": (
            not_requested_reason if status == GUIDANCE_NOT_REQUESTED else None
        ),
    }
    if guidance is None or status in (GUIDANCE_NOT_STARTED, GUIDANCE_NOT_REQUESTED):
        return block

    item = guidance["items"][0] if guidance["items"] else None
    block["focused_incident_ids"] = list(guidance["focused_incident_ids"])
    block["failed_incident_ids"] = list(guidance["failed_incident_ids"])
    block["notes"] = list(guidance["notes"])
    if item is not None:
        block["incident_id"] = item["incident_id"]
        block["question"] = item["question"]
        block["provider_name"] = item["provider_name"]
        block["model"] = item["model"]

    if status == GUIDANCE_ANALYZING:
        # 응답과 근거 페이지는 아직 숨긴다.
        return block

    if item is not None:
        block["response"] = item["response"]  # 원문 그대로
        pages = extract_citation_pages(item["response"])
        block["demo_derived"] = {
            "citation_pages": pages,
            "citation_count": len(_PAGE_RE.findall(item["response"])),
            "distinct_citation_page_count": len(pages),
            "note": CITATION_NOTE,
        }
    return block


# ---------------------------------------------------------------------------
# step 조립
# ---------------------------------------------------------------------------


def build_steps(
    *,
    report: dict[str, Any],
    projection: Any,
    correlation: Any,
    selection: Any,
    anchor: Finding,
    scenario_key: str,
    steps_spec: tuple[StepSpec, ...],
    uses_rag: bool,
    guidance_not_requested_reason: str | None = None,
) -> list[dict[str, Any]]:
    step_count = len(steps_spec)
    focused_ids = list(selection.focused_incident_ids)
    focused = correlation.incident_by_id(focused_ids[0]) if focused_ids else None
    unselected = [item for item in correlation.incidents if item.incident_id not in set(focused_ids)]

    all_findings = [sf.finding for sf in projection.findings]
    anchor_only = [f for f in all_findings if f.finding_id == anchor.finding_id]

    all_timeline = [timeline_entry_to_dict(entry) for entry in correlation.timeline]
    focused_timeline = (
        [timeline_entry_to_dict(entry) for entry in focused.timeline] if focused is not None else []
    )
    anchor_timeline = [e for e in all_timeline if e["finding_id"] == anchor.finding_id]

    source_block = {
        "report_id": report["report_id"],
        "investigation_id": report["investigation_id"],
        "generated_from": report["generated_from"],
        "scenario_id": report["scenario_id"],
        "incident_id": report["incident_id"],
        "anchor_finding_id": anchor.finding_id,
        "dataset": anchor.dataset,
        "source_report_file": FINAL_REPORT_FILE,
        "replay_event_file": REPLAY_EVENT_FILE,
    }

    # 후보 공개(step 02)와 선정 결과 공개(step 03 이후)를 분리한다. 선정 전 단계에서
    # focused/unselected를 미리 보여주면 "조사 대상을 고르는 중"이라는 표현이 깨진다.
    candidates_before_selection = {
        "projection_finding_count": len(projection),
        "candidate_incident_count": len(correlation.incidents),
        "multi_finding_incident_count": len(correlation.multi_finding_incidents),
        "single_finding_incident_count": len(correlation.single_finding_incidents),
        "candidate_incidents": [
            incident_to_candidate_dict(item) for item in correlation.incidents
        ],
        "selection_completed": False,
        "focused_incident_ids": None,
        "unmatched_anchor_finding_ids": None,
        "unselected_candidate_incident_ids": None,
        "unselected_incidents": None,
        "unselected_note": UNSELECTED_NOTE,
        "notes": None,
    }
    candidates_after_selection = {
        **candidates_before_selection,
        "selection_completed": True,
        "focused_incident_ids": focused_ids,
        "unmatched_anchor_finding_ids": list(selection.unmatched_anchor_finding_ids),
        "unselected_candidate_incident_ids": [item.incident_id for item in unselected],
        "unselected_incidents": [incident_to_candidate_dict(item) for item in unselected],
        "notes": list(selection.notes),
    }

    focused_detail = None
    if focused is not None:
        focused_detail = {
            "incident_id": focused.incident_id,
            "scenario_id": focused.scenario_id,
            "datasets": list(focused.datasets),
            "finding_ids": list(focused.finding_ids),
            "finding_count": focused.finding_count,
            "relative_start_seconds": focused.relative_start_seconds,
            "relative_end_seconds": focused.relative_end_seconds,
            "timeline": focused_timeline,
            "hypotheses": list(report["hypotheses"]),
            "hypotheses_note": HYPOTHESES_EMPTY_NOTE if not report["hypotheses"] else None,
            "impact": report["impact"],
            "evidence": report["evidence"],
            "findings": report["findings"],
            "correlation_basis": {
                "grouping_basis": list(focused.grouping_basis),
                "edge_ids": list(focused.edge_ids),
                "edge_count": report["correlation"]["edge_count"],
                "grouping_edge_count": report["correlation"]["grouping_edge_count"],
                "long_span_finding_ids": list(focused.long_span_finding_ids),
            },
        }

    correlation_counters = {
        "projection_finding_count": len(projection),
        "candidate_incident_count": len(correlation.incidents),
        "multi_finding_incident_count": len(correlation.multi_finding_incidents),
        "single_finding_incident_count": len(correlation.single_finding_incidents),
        "focused_incident_count": None,
        "unselected_candidate_incident_count": None,
        "unmatched_anchor_count": None,
    }
    selection_counters = {
        **correlation_counters,
        "focused_incident_count": len(focused_ids),
        "unselected_candidate_incident_count": len(unselected),
        "unmatched_anchor_count": len(selection.unmatched_anchor_finding_ids),
    }
    # 아직 공개되지 않은 값은 키를 유지하고 null로 둔다(키 유무로 의미가 갈리지 않게).
    hidden_counters: dict[str, Any] = dict.fromkeys(selection_counters)

    # RAG를 쓰는 scenario와 쓰지 않는 scenario에서 step 4/5의 의미가 다르다.
    # RAG가 없으면 '보안 가이던스 완료'처럼 보이게 하지 않고, 그 자리에서 요약 분석
    # 결과(narrative)를 공개한다.
    middle_guidance = GUIDANCE_NOT_STARTED if uses_rag else GUIDANCE_NOT_REQUESTED
    final_guidance = GUIDANCE_COMPLETED if uses_rag else GUIDANCE_NOT_REQUESTED
    completed_label = "보안 가이던스 조회 완료" if uses_rag else "요약 분석 완료"

    plans: dict[str, dict[str, Any]] = {
        PHASE_COLLECTING: {
            "revealed": [],
            "timeline": [],
            "counters": hidden_counters,
            "candidates": None,
            "focused": False,
            "guidance": middle_guidance,
            "report": REPORT_NOT_READY,
            "narrative": False,
            "note": COLLECTING_NOTE,
        },
        PHASE_FINDING_DETECTED: {
            "revealed": anchor_only,
            "timeline": anchor_timeline,
            "counters": hidden_counters,
            "candidates": None,
            "focused": False,
            "guidance": middle_guidance,
            "report": REPORT_NOT_READY,
            "narrative": False,
            "note": "anchor Finding을 처음 공개한 단계다.",
        },
        PHASE_CORRELATING: {
            "revealed": all_findings,
            "timeline": all_timeline,
            "counters": correlation_counters,
            "candidates": candidates_before_selection,
            "focused": False,
            "guidance": middle_guidance,
            "report": REPORT_NOT_READY,
            "narrative": False,
            "note": (
                "Window 안의 Finding과 후보 incident를 공개했고 조사 대상은 "
                "아직 고르지 않은 단계다."
            ),
        },
        PHASE_FOCUS_SELECTED: {
            "revealed": all_findings,
            "timeline": focused_timeline,
            "counters": selection_counters,
            "candidates": candidates_after_selection,
            "focused": True,
            "guidance": middle_guidance,
            "report": REPORT_NOT_READY,
            "narrative": False,
            "note": "anchor가 속한 incident만 조사 대상으로 선택된 단계다.",
        },
        PHASE_RAG_ANALYZING: {
            "revealed": all_findings,
            "timeline": focused_timeline,
            "counters": selection_counters,
            "candidates": candidates_after_selection,
            "focused": True,
            "guidance": GUIDANCE_ANALYZING,
            "report": REPORT_NOT_READY,
            "narrative": False,
            "note": "보안 가이던스 질문을 보냈고 응답은 아직 공개하지 않은 단계다.",
        },
        PHASE_RAG_COMPLETED: {
            "revealed": all_findings,
            "timeline": focused_timeline + [workflow_timeline_entry(completed_label)],
            "counters": selection_counters,
            "candidates": candidates_after_selection,
            "focused": True,
            "guidance": GUIDANCE_COMPLETED,
            "report": REPORT_NOT_READY,
            "narrative": False,
            "note": "최종 보고서에 저장된 실제 보안 가이던스를 공개한 단계다.",
        },
        PHASE_ANALYZING: {
            "revealed": all_findings,
            "timeline": focused_timeline,
            "counters": selection_counters,
            "candidates": candidates_after_selection,
            "focused": True,
            "guidance": GUIDANCE_NOT_REQUESTED,
            "report": REPORT_NOT_READY,
            "narrative": False,
            "note": (
                "조사 대상 incident의 요약 분석이 진행 중인 단계다. 이 scenario는 "
                "보안 가이던스를 요청하지 않았다."
            ),
        },
        PHASE_ANALYSIS_COMPLETED: {
            "revealed": all_findings,
            "timeline": focused_timeline + [workflow_timeline_entry(completed_label)],
            "counters": selection_counters,
            "candidates": candidates_after_selection,
            "focused": True,
            "guidance": GUIDANCE_NOT_REQUESTED,
            "report": REPORT_NOT_READY,
            "narrative": True,
            "note": "최종 보고서에 저장된 실제 요약 분석 결과를 공개한 단계다.",
        },
        PHASE_REPORT_READY: {
            "revealed": all_findings,
            "timeline": focused_timeline
            + [
                workflow_timeline_entry(completed_label),
                workflow_timeline_entry("최종 보고서 생성 완료"),
            ],
            "counters": selection_counters,
            "candidates": candidates_after_selection,
            "focused": True,
            "guidance": final_guidance,
            "report": REPORT_READY,
            "narrative": True,
            "note": (
                "최종 보고서가 준비된 단계다. 상세 페이지는 final_report.json을 "
                "그대로 쓴다."
            ),
        },
    }

    identity_keys = {
        "schema_version",
        "report_id",
        "investigation_id",
        "generated_from",
        "scenario_id",
        "incident_id",
    }

    steps: list[dict[str, Any]] = []
    for spec in steps_spec:
        plan = plans[spec.phase]
        revealed: list[Finding] = plan["revealed"]
        guidance_status: str = plan["guidance"]
        report_ready = plan["report"] == REPORT_READY
        narrative_revealed = plan["narrative"]

        steps.append(
            {
                "demo": {
                    "demo_only": True,
                    "demo_schema_version": DEMO_SCHEMA_VERSION,
                    "scenario_key": scenario_key,
                    "step_index": spec.order,
                    "step_count": step_count,
                    "file": spec.file,
                    "phase": spec.phase,
                    "phase_label": spec.phase_label,
                    "recommended_delay_ms": spec.recommended_delay_ms,
                    "is_last_step": spec.order == step_count - 1,
                    "step_note": plan["note"],
                    "presentation_metadata_note": PRESENTATION_NOTE,
                },
                "source": source_block,
                "dashboard": {
                    "status": {
                        "analysis_phase": spec.phase,
                        "security_guidance": guidance_status,
                        "report": plan["report"],
                    },
                    "counters": {
                        "revealed_findings_count": len(revealed),
                        **plan["counters"],
                    },
                    "revealed_finding_ids": [f.finding_id for f in revealed],
                    "revealed_severity_counts": _severity_counts(revealed),
                    "revealed_finding_type_counts": _finding_type_counts(revealed),
                    "agents": build_agent_cards(revealed, report["agent_statistics"]),
                    "agent_attribution_note": AGENT_ATTRIBUTION_NOTE,
                    "operational_state": (
                        report["agent_statistics"]["operational_state"] if report_ready else None
                    ),
                    "timeline_preview": plan["timeline"],
                },
                "detail": {
                    "projection_findings": (
                        [scenario_finding_to_dict(sf) for sf in projection.findings]
                        if plan["candidates"] is not None
                        else None
                    ),
                    "candidates": plan["candidates"],
                    "focused_incident": focused_detail if plan["focused"] else None,
                    "security_guidance": build_guidance_block(
                        report,
                        guidance_status,
                        not_requested_reason=guidance_not_requested_reason,
                    ),
                    "limitations": report["limitations"] if plan["candidates"] is not None else None,
                    "narrative_summary": (
                        report["narrative_summary"] if narrative_revealed else None
                    ),
                    "final_report_file": FINAL_REPORT_FILE if report_ready else None,
                    "report_sections_available": (
                        sorted(key for key in report if key not in identity_keys)
                        if report_ready
                        else None
                    ),
                },
            }
        )
    return steps


# ---------------------------------------------------------------------------
# 전체 생성
# ---------------------------------------------------------------------------


def build_demo_pack(
    *,
    report_path: Path,
    findings_path: Path,
    out_dir: Path,
    scenario_key: str = DEFAULT_SCENARIO_KEY,
    scenario_id: str = DEFAULT_SCENARIO_ID,
    anchor_finding_id: str | None = None,
    anchor_finding_type: str | None = DEFAULT_ANCHOR_FINDING_TYPE,
    anchor_service: str | None = DEFAULT_ANCHOR_SERVICE,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    lead_minutes: int = DEFAULT_LEAD_MINUTES,
    title: str | None = None,
    uses_rag: bool = True,
    steps_spec: tuple[StepSpec, ...] | None = None,
    guidance_not_requested_reason: str | None = None,
    verbose: bool = False,
) -> dict[str, Any]:
    """demo pack을 만들고 manifest dict를 돌려준다. 외부 API를 호출하지 않는다."""

    def log(message: str) -> None:
        if verbose:
            print(message)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    log(f"[1/6] 최종 보고서 적재: {report_path} (report_id={report['report_id']})")

    findings = list(load_findings(findings_path))
    log(f"[2/6] Finding 적재: {len(findings):,}건 ({findings_path})")

    # anchor_finding_id가 있으면 그것만 쓴다. 없으면 type/service로 좁힌 뒤 가장 이른
    # Finding을 고른다(기존 동작).
    candidates = [
        finding
        for finding in findings
        if (anchor_finding_id is None or finding.finding_id == anchor_finding_id)
        and (anchor_finding_type is None or finding.finding_type == anchor_finding_type)
        and (anchor_service is None or finding.service == anchor_service)
    ]
    if not candidates:
        raise ValueError(f"anchor 조건에 맞는 Finding이 없다 (id={anchor_finding_id!r})")
    anchor = min(candidates, key=lambda f: (f.start_time, f.finding_id))
    log(f"[3/6] anchor: {anchor.finding_id}")

    scenario = make_analysis_scenario(
        scenario_id,
        anchors={anchor.dataset: anchor.start_time},
        duration=timedelta(minutes=window_minutes),
        lead=timedelta(minutes=lead_minutes),
    )
    window = scenario.window_for(anchor.dataset)
    projection = project_findings(findings, scenario, on_missing_window="skip")
    correlation = correlate_scenario(projection)
    selection = select_incidents(correlation, focus_on([anchor]))
    log(
        f"[4/6] projection {len(projection)} / candidate {len(correlation.incidents)} "
        f"(multi {len(correlation.multi_finding_incidents)}) / "
        f"focused {len(selection.focused_incident_ids)}"
    )

    # 최종 보고서와 어긋나면 demo를 만들지 않는다. 숫자를 맞추려고 고치지도 않는다.
    if report["scenario_id"] != scenario.scenario_id:
        raise ValueError(
            f"scenario_id 불일치: report={report['scenario_id']!r} demo={scenario.scenario_id!r}"
        )
    if report["incident_id"] not in set(selection.focused_incident_ids):
        raise ValueError(
            f"incident_id 불일치: report={report['incident_id']!r} "
            f"focused={selection.focused_incident_ids!r}"
        )
    focused_incident = correlation.incident_by_id(report["incident_id"])
    if set(focused_incident.finding_ids) != set(report["correlation"]["incident_finding_ids"]):
        raise ValueError("focused incident의 finding_ids가 최종 보고서와 다르다")

    resolved_steps = steps_spec if steps_spec is not None else make_steps(uses_rag=uses_rag)
    steps = build_steps(
        report=report,
        projection=projection,
        correlation=correlation,
        selection=selection,
        anchor=anchor,
        scenario_key=scenario_key,
        steps_spec=resolved_steps,
        uses_rag=uses_rag,
        guidance_not_requested_reason=guidance_not_requested_reason,
    )
    replay_events = build_replay_events(projection, window)

    out_dir.mkdir(parents=True, exist_ok=True)

    # final_report.json은 원본 바이트를 그대로 복사한다(다시 생성하지 않는다).
    final_copy = out_dir / FINAL_REPORT_FILE
    final_copy.write_bytes(report_path.read_bytes())
    report_sha256 = sha256_of(report_path)
    if sha256_of(final_copy) != report_sha256:
        raise ValueError("final_report.json 복사본의 hash가 원본과 다르다")

    write_json(
        out_dir / REPLAY_EVENT_FILE,
        {
            "demo_only": True,
            "demo_schema_version": DEMO_SCHEMA_VERSION,
            "scenario_key": scenario_key,
            "scenario_id": scenario.scenario_id,
            "dataset": anchor.dataset,
            "window": {
                "window_start": _iso(window.window_start),
                "window_end": _iso(window.window_end),
                "window_length_seconds": window.window_length_seconds,
            },
            "source": (
                f"ScenarioProjection에 포함된 Finding {len(projection)}건의 EvidenceReference"
            ),
            "source_finding_ids": list(projection.finding_ids),
            "total_count": len(replay_events),
            "raw_available": False,
            "raw_note": RAW_NOTE,
            "stream_note": (
                "실시간 stream에는 조사 대상과 무관한 service의 event도 함께 들어온다. "
                "조사 범위를 좁히는 것은 Correlation / Focus 단계이며, focused incident "
                "상세에는 무관한 service가 섞이지 않는다."
            ),
            "events": replay_events,
        },
    )

    for step in steps:
        write_json(out_dir / step["demo"]["file"], step)

    manifest = {
        "demo_schema_version": DEMO_SCHEMA_VERSION,
        "demo_only": True,
        "scenario_key": scenario_key,
        "title": title
        or (
            f"{anchor.service} {anchor.finding_type} 조사"
            if anchor.service
            else f"{anchor.finding_type} 조사"
        ),
        "generated_by": "scripts/build_demo_replay.py",
        "external_calls": {
            "openai": False,
            "supabase": False,
            "rag_agent": False,
            "llm": False,
            "detector_rerun": False,
        },
        "source_report_id": report["report_id"],
        "source_report_file": FINAL_REPORT_FILE,
        "source_report_origin": report_path.as_posix(),
        "source_report_sha256": report_sha256,
        "source_findings_file": findings_path.as_posix(),
        "scenario_id": scenario.scenario_id,
        "incident_id": report["incident_id"],
        "anchor_finding_id": anchor.finding_id,
        "replay_event_file": REPLAY_EVENT_FILE,
        "replay_event_count": len(replay_events),
        "step_count": len(resolved_steps),
        "uses_rag": uses_rag,
        "presentation_metadata_note": PRESENTATION_NOTE,
        "steps": [
            {
                "order": spec.order,
                "phase": spec.phase,
                "phase_label": spec.phase_label,
                "file": spec.file,
                "recommended_delay_ms": spec.recommended_delay_ms,
            }
            for spec in resolved_steps
        ],
    }
    write_json(out_dir / MANIFEST_FILE, manifest)
    log(f"[5/6] 생성 완료: {out_dir}")
    log(f"[6/6] replay event {len(replay_events)}건 / step {len(resolved_steps)}개")
    return manifest


def build_scenario(scenario: DemoScenario, *, verbose: bool = False) -> dict[str, Any]:
    """demo/scenarios.py의 설정 하나로 demo pack을 만든다."""
    return build_demo_pack(
        report_path=Path(scenario.report_path),
        findings_path=Path(scenario.findings_path),
        out_dir=Path(scenario.out_dir),
        scenario_key=scenario.scenario_key,
        scenario_id=scenario.scenario_id,
        anchor_finding_id=scenario.anchor_finding_id,
        anchor_finding_type=None,
        anchor_service=None,
        window_minutes=scenario.window_minutes,
        lead_minutes=scenario.lead_minutes,
        title=scenario.title,
        uses_rag=scenario.uses_rag,
        steps_spec=scenario.steps,
        guidance_not_requested_reason=scenario.guidance_not_requested_reason,
        verbose=verbose,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        default=DEFAULT_SCENARIO_KEY,
        help="demo/scenarios.py에 정의된 scenario_key",
    )
    parser.add_argument("--all", action="store_true", help="정의된 scenario를 모두 생성한다")
    args = parser.parse_args(argv)

    targets = list(SCENARIOS) if args.all else [get_scenario(args.scenario)]

    for scenario in targets:
        report_path = Path(scenario.report_path)
        findings_path = Path(scenario.findings_path)
        if not report_path.is_file():
            print(f"[중단] 보고서 파일이 없다: {report_path}")
            return 1
        if not findings_path.is_file():
            print(f"[중단] Finding 파일이 없다: {findings_path}")
            return 1

        print(f"\n=== {scenario.scenario_key} ===")
        build_scenario(scenario, verbose=True)
        out_dir = Path(scenario.out_dir)
        for path in sorted(out_dir.iterdir()):
            print(f"       {path.as_posix()}  ({path.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
