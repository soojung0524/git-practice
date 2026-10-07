"""Streamlit 화면과 백엔드(orchestration, RAG 에이전트) 사이의 연결 함수.

화면 코드(app.py)는 이 파일의 함수만 부른다. 백엔드 객체(AgentResult, Finding 등)를
그대로 화면에 넘기지 않고, 여기서 dict/list 같은 단순한 값으로 바꾼다.
그래야 결과를 JSON 으로 저장했다가 분석 없이 다시 불러올 수 있다(발표 데모용).
"""

from __future__ import annotations

import dataclasses
import itertools
import json
import re
import sys
from collections.abc import Callable
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

# 프로젝트 루트(orchestration/ 폴더가 있는 곳)를 찾아 import 경로에 넣는다.
# frontend/ 안에 두든 루트에 두든 orchestration, src 등을 찾을 수 있게.
def _find_project_root() -> Path:
    here = Path(__file__).resolve().parent
    for candidate in (here, *here.parents):
        if (candidate / "orchestration").is_dir() and (candidate / "src").is_dir():
            return candidate
    return here.parent


PROJECT_ROOT = _find_project_root()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

SEVERITY_ORDER = ("critical", "high", "medium", "low")
EXTRA_STATE_KEYS = ("scenario_projection", "correlation_result", "incident_selection",
                    "security_guidance", "incident_report")
AGENT_RESULT_KEYS = {
    "application_result": "Application",
    "server_result": "Server",
    "network_result": "Network",
    "authentication_result": "Authentication",
    "security_result": "Security",
}


# ───────────────────────── 직렬화 ─────────────────────────
def to_plain(obj: Any) -> Any:
    """dataclass / pydantic / datetime / set 등을 JSON 으로 저장 가능한 값으로 바꾼다."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_plain(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if hasattr(obj, "model_dump"):  # pydantic v2
        return to_plain(obj.model_dump())
    if hasattr(obj, "dict") and callable(obj.dict):  # pydantic v1
        try:
            return to_plain(obj.dict())
        except TypeError:
            pass
    if isinstance(obj, dict):
        return {str(k): to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        items = [to_plain(v) for v in obj]
        return sorted(items, key=str) if isinstance(obj, (set, frozenset)) else items
    if hasattr(obj, "__dict__"):
        return {k: to_plain(v) for k, v in vars(obj).items() if not k.startswith("_")}
    return str(obj)


def summarize_agent(result: Any) -> dict[str, Any]:
    """AgentResult 를 화면용 dict 로. 필드가 바뀌어도 깨지지 않게 getattr 로 읽는다."""
    findings = getattr(result, "findings", None) or []
    known = {"status", "input_item_count", "findings"}
    extra = {k: v for k, v in (to_plain(result) or {}).items() if k not in known} if result else {}
    return {
        "status": str(getattr(result, "status", "unknown")),
        "input_item_count": getattr(result, "input_item_count", None),
        "finding_count": len(findings),
        "finding_ids": [getattr(f, "finding_id", "") for f in findings],
        "extra": extra,
    }


def serialize_state(state: dict[str, Any]) -> dict[str, Any]:
    """최종 InvestigationState 에서 화면에 필요한 것만 뽑아 단순한 값으로 바꾼다.

    event_source(함수)는 저장할 수 없으므로 뺀다.
    """
    agents = {}
    for key, label in AGENT_RESULT_KEYS.items():
        result = state.get(key)
        agents[label] = summarize_agent(result) if result is not None else None

    return {
        "investigation_id": state.get("investigation_id"),
        "scope": {
            k: to_plain(state.get(k))
            for k in ("dataset", "host", "service", "start_time", "end_time", "source_types")
        },
        "available_source_types": to_plain(state.get("available_source_types") or []),
        "routed_agents": to_plain(state.get("routed_agents") or []),
        "agents": agents,
        "findings": [to_plain(f) for f in state.get("findings") or []],
        "errors": to_plain(state.get("errors") or {}),
        "interpretation": to_plain(state.get("interpretation")),
        # 팀 백엔드의 선택 기능 결과 (켜지 않으면 None). 화면 연결 전에도 JSON 에는 남긴다.
        "extras": {k: to_plain(state.get(k)) for k in EXTRA_STATE_KEYS if state.get(k) is not None},
        "notes": {},  # finding_id -> 보안상 주의사항 (화면에서 만들어 채운다)
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }


def result_to_json(result: dict[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2)


def result_from_json(text: str) -> dict[str, Any]:
    data = json.loads(text)
    if "findings" not in data or "agents" not in data:
        raise ValueError("분석 결과 JSON 이 아닙니다 (findings, agents 키가 없음).")
    return data


# ───────────────────────── 분석 실행 ─────────────────────────
def list_event_files() -> list[str]:
    """output/ 아래의 이벤트 파일(.pkl) 목록. 프로젝트 루트 기준 상대 경로."""
    out = PROJECT_ROOT / "output"
    if not out.exists():
        return []
    return sorted(str(p.relative_to(PROJECT_ROOT)) for p in out.rglob("*.pkl"))


def run_analysis(
    *,
    event_path: str,
    investigation_id: str | None,
    dataset: str | None,
    host: str | None,
    service: str | None,
    start_time: datetime | None,
    end_time: datetime | None,
    source_types: list[str] | None,
    interpret: bool,
    on_progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """run_investigation 과 같은 일을 하되, node 가 끝날 때마다 on_progress 를 부른다.

    graph.stream 으로 실행 과정을 화면에 보여주고, 실패하면 run_investigation 으로 다시 돌린다.
    """
    import uuid

    from orchestration.graph import build_graph, run_investigation
    from orchestration.state import new_state
    from src.models.event_store import load_events

    path = event_path if Path(event_path).is_absolute() else str(PROJECT_ROOT / event_path)
    if not Path(path).exists():
        raise FileNotFoundError(f"이벤트 파일이 없습니다: {event_path}")

    # 첫 순회(라우팅 단계)에서만 호스트 목록과 이벤트 수를 기록한다. 분석 범위 표시에 쓴다.
    hosts: set[str] = set()
    types: dict[str, int] = {}
    datasets: dict[str, int] = {}
    counter = {"events": 0, "recorded": False}

    def _recording(events):
        for e in events:
            counter["events"] += 1
            ds = e.get("dataset") if isinstance(e, dict) else getattr(e, "dataset", None)
            if ds:
                datasets[str(ds)] = datasets.get(str(ds), 0) + 1
            if dataset and ds and ds != dataset:
                yield e  # 다른 데이터셋 이벤트는 분석 범위 집계에서 뺀다(백엔드도 건너뜀)
                continue
            h = e.get("host") if isinstance(e, dict) else getattr(e, "host", None)
            if h:
                hosts.add(str(h))
            t = e.get("source_type") if isinstance(e, dict) else getattr(e, "source_type", None)
            if t:
                types[str(t)] = types.get(str(t), 0) + 1
            yield e

    def source():
        if counter["recorded"]:
            return load_events(path)
        counter["recorded"] = True
        return _recording(load_events(path))

    scope = dict(
        dataset=dataset or None,
        host=host or None,
        service=service or None,
        start_time=start_time,
        end_time=end_time,
        source_types=source_types or None,
    )
    inv_id = investigation_id or str(uuid.uuid4())

    graph = build_graph(interpret=interpret)
    initial = new_state(investigation_id=inv_id, event_source=source, **scope)
    final = None
    started = False
    try:
        for item in graph.stream(initial, stream_mode=["updates", "values"]):
            started = True
            mode, chunk = item
            if mode == "updates" and on_progress:
                for node_name in chunk:
                    on_progress(node_name)
            elif mode == "values":
                final = chunk
    except (TypeError, ValueError) as e:
        # 첫 결과도 받기 전에 실패 = stream_mode 목록을 지원하지 않는 LangGraph 버전.
        # 분석 도중의 오류는 그대로 올린다(같은 분석을 두 번 돌리지 않도록).
        if started:
            raise
        if on_progress:
            on_progress(f"(진행 표시 없이 실행: {type(e).__name__})")
        final = run_investigation(
            event_source=source, investigation_id=inv_id, interpret=interpret, **scope
        )
    if final is None:
        raise RuntimeError("분석 결과를 받지 못했습니다.")

    result = serialize_state(final)
    result["hosts"] = sorted(hosts)
    result["event_count"] = counter["events"]
    result["source_type_counts"] = dict(sorted(types.items(), key=lambda kv: -kv[1]))
    result["dataset_counts"] = datasets
    result["scope_dataset"] = dataset or None
    return result


# ───────────────────────── 근거 원문 ─────────────────────────
def read_source_line(source_file: str, line_number: int, context: int = 2) -> list[tuple[int, str]]:
    """근거 파일에서 해당 줄과 앞뒤 몇 줄을 읽는다. 큰 파일도 처음부터 한 번만 훑는다.

    line_number 는 1부터 센다고 가정한다(GAIA 는 헤더 제외 행 번호라 CSV 는 +1 줄).
    """
    path = Path(source_file)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    if not path.exists():
        raise FileNotFoundError(str(path))

    target = line_number + (1 if path.suffix.lower() == ".csv" else 0)
    first = max(1, target - context)
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = itertools.islice(fh, first - 1, target + context)
        return [(first + i, line.rstrip("\n")) for i, line in enumerate(lines)]


# ───────────────────────── RAG ─────────────────────────
def build_rag_question(finding: dict[str, Any]) -> str:
    """탐지 결과 하나를 RAG 에이전트에 보낼 질문으로 바꾼다."""
    metrics = finding.get("metrics") or {}
    entities = finding.get("entities") or {}
    lines = [
        "다음 탐지 결과에 대해 AWS Security Incident Response 기준으로 어떤 순서로 대응해야 하는지 알려주세요.",
        "",
        f"- 탐지 유형: {finding.get('finding_type')} ({finding.get('category')})",
        f"- 심각도: {finding.get('severity')}",
        f"- 요약: {finding.get('summary')}",
        f"- 기간: {finding.get('start_time')} ~ {finding.get('end_time')}",
    ]
    if finding.get("host"):
        lines.append(f"- 호스트: {finding['host']}")
    if finding.get("service"):
        lines.append(f"- 서비스: {finding['service']}")
    if metrics:
        shown = ", ".join(f"{k}={v}" for k, v in list(metrics.items())[:8])
        lines.append(f"- 주요 수치: {shown}")
    for kind, values in list(entities.items())[:5]:
        lines.append(f"- {kind}: {', '.join(map(str, values[:5]))}")
    lines += [
        "",
        "답변은 화면에 바로 보여줄 수 있게 짧게 작성해 주세요.",
        "- 관련 대응 절차: 가장 중요한 순서대로 최대 5단계, 단계마다 1~2문장",
        "- 확인해야 할 사항, 권장 대응 방향: 각각 최대 4개 항목, 항목마다 한 문장",
    ]
    return "\n".join(lines)


_PAGE_RE = re.compile(r"^\[(Page [^\]]+)\]", re.MULTILINE)


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(p.get("text", "") if isinstance(p, dict) else str(p) for p in content)
    return str(content or "")


def ask_rag(history: list[dict[str, str]]) -> dict[str, Any]:
    """대화 기록 전체를 RAG 에이전트에 보내고 답변과 참고 페이지를 돌려준다.

    history: [{"role": "user"|"assistant", "content": "..."}, ...] (마지막이 이번 질문)
    """
    from src.agents.rag_agent import rag_agent

    result = rag_agent.invoke({"messages": [{"role": m["role"], "content": m["content"]} for m in history]})
    messages = result["messages"]

    # 이번 질문 이후에 생긴 메시지만 본다(이전 대화의 검색 결과 제외)
    new_msgs = messages[len(history):] or messages
    queries, pages = [], []
    page_info: dict[int, dict[str, Any]] = {}
    for m in new_msgs:
        for call in getattr(m, "tool_calls", None) or []:
            q = (call.get("args") or {}).get("query")
            if q:
                queries.append(q)
        if getattr(m, "type", "") == "tool":
            for header in _PAGE_RE.findall(_text(m.content)):
                if header not in pages:
                    pages.append(header)
                info = _parse_page_header(header)
                if info and info["page"] not in page_info:
                    page_info[info["page"]] = info

    answer = _text(messages[-1].content)
    return {"answer": answer, "queries": queries, "pages": pages,
            "refs": cited_refs(answer, page_info)}


def _parse_page_header(header: str) -> dict[str, Any] | None:
    """'Page 101 | 문서 표기 p.94 | 섹션: A > B > Attachments; Tags | 유사도 0.44' → dict"""
    m = re.match(r"Page\s+(\d+)", header)
    if not m:
        return None
    info: dict[str, Any] = {"page": int(m.group(1)), "printed": None, "section": ""}
    for part in header.split("|")[1:]:
        part = part.strip()
        if part.startswith("문서 표기"):
            info["printed"] = part.replace("문서 표기", "").strip()
        elif part.startswith("섹션:"):
            sec = part[len("섹션:"):].strip()
            info["section"] = sec.split(">")[-1].split(";")[0].strip()
    return info


def cited_refs(answer: str, page_info: dict[int, dict[str, Any]], limit: int = 6) -> list[dict[str, Any]]:
    """답변에 [Page N] 으로 인용된 페이지를 인용 순서대로. 인용이 없으면 검색된 페이지 앞쪽."""
    cited: list[int] = []
    for n in re.findall(r"Page\s*(\d+)", answer):
        n = int(n)
        if n not in cited:
            cited.append(n)
    pages = cited or list(page_info)
    return [page_info.get(n, {"page": n, "printed": None, "section": ""}) for n in pages[:limit]]


# ───────────────────────── 보안상 주의사항 ─────────────────────────
_SECTION_KEYS = {
    "상황 요약": "summary",
    "관련 대응 절차": "procedure",
    "확인해야 할 사항": "checks",
    "권장 대응 방향": "actions",
    "참고 문서": "refs",
}
_HEAD_RE = re.compile(r"^\s*(?:#{1,6}\s*)?(?:\*\*)?\s*\d\s*[.)]\s*(.+?)\s*(?:\*\*)?\s*:?\s*$")
_ITEM_RE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+(.*)$")
_LABELS = {"문서에 명시된 내용", "문서를 바탕으로 한 해석"}


def _clean(text: str) -> str:
    text = re.sub(r"\s*\[Page[^\]]*\]", "", text)
    return text.replace("**", "").strip(" :")


def parse_rag_sections(answer: str) -> dict[str, list[str]]:
    """RAG 답변(1. 상황 요약 / 2. 관련 대응 절차 / ...)을 섹션별 항목 목록으로 나눈다.

    형식을 따르지 않은 짧은 답변이면 전체를 summary 에 넣는다.
    """
    sections: dict[str, list[str]] = {}
    current = None
    for line in answer.splitlines():
        head = _HEAD_RE.match(line)
        if head:
            name = _clean(head.group(1))
            key = next((v for k, v in _SECTION_KEYS.items() if name.startswith(k)), None)
            if key:
                current = key
                sections.setdefault(key, [])
                continue
        if current is None or not line.strip():
            continue
        item = _ITEM_RE.match(line)
        text = _clean(item.group(1) if item else line)
        if text and text not in _LABELS:
            sections[current].append(text)

    if not sections:
        paras = [_clean(p) for p in re.split(r"\n\s*\n", answer) if _clean(p)]
        sections["summary"] = paras or [_clean(answer)]
    return sections


def security_notes(finding: dict[str, Any]) -> dict[str, Any]:
    """탐지 결과 하나에 대한 보안상 주의사항(보안 매뉴얼 기반)을 만든다."""
    question = build_rag_question(finding)
    out = ask_rag([{"role": "user", "content": question}])
    return {
        "question": question,
        "answer": out["answer"],
        "sections": parse_rag_sections(out["answer"]),
        "refs": out["refs"],
        "queries": out["queries"],
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }


# ───────────────────────── 화면용 요약 ─────────────────────────
AREA_LABELS = {  # 화면에 보일 분석 영역 이름 (AGENT_RESULT_KEYS 의 값 → 한국어)
    "Application": "애플리케이션 로그",
    "Server": "서버",
    "Network": "네트워크",
    "Authentication": "인증 로그",
    "Security": "보안 종합",
}
NODE_LABELS = {  # 긴 이름부터 비교한다 ("security_guidance" 가 "security" 로 잘못 잡히지 않게)
    "security_guidance": "보안 대응 가이드 생성",
    "incident_report": "사건 보고서 작성",
    "scenario_projection": "공격 시나리오 매핑",
    "evidence_correlation": "탐지 결과 연관 분석",
    "select_incident": "조사 대상 사건 선택",
    "collect_findings": "탐지 결과 정리",
    "interpret": "LLM 해석",
    "route": "로그 유형 확인",
    "application": "애플리케이션 로그 조사",
    "server": "서버 상태 조사",
    "network": "네트워크 조사",
    "authentication": "인증 로그 조사",
    "security": "보안 종합 판단",
}
CATEGORY_KO = {
    "security": "보안 사고", "authentication": "인증 이상", "network": "네트워크 이상",
    "performance": "성능 이상", "availability": "가용성 장애", "error": "오류 증가", "resource": "자원 이상",
}


# 성능·자원 이상은 보안 사고로 판단된 바가 없으므로 보안 매뉴얼에 묻지 않는다(팀 방침).
NO_GUIDANCE_REASONS = {
    "performance": ("이 탐지는 통계 탐지기가 관측한 성능 이상이며 보안 사고로 판단된 바가 없습니다. "
                    "AWS Security Incident Response User Guide는 보안 사고 대응 문서이므로, 성능 이상을 "
                    "보안 사고처럼 설명하지 않기 위해 보안 가이드를 요청하지 않았습니다."),
    "resource": ("이 탐지는 통계 탐지기가 관측한 자원 사용량 이상이며 보안 사고로 판단된 바가 없습니다. "
                 "AWS Security Incident Response User Guide는 보안 사고 대응 문서이므로, 단순 자원 이상을 "
                 "보안 사고로 확대하지 않기 위해 보안 가이드를 요청하지 않았습니다."),
}


def guidance_skip_reason(finding: dict[str, Any] | None) -> str | None:
    """보안 가이드를 요청하지 않는 탐지면 그 이유, 요청 대상이면 None."""
    if not finding:
        return None
    return NO_GUIDANCE_REASONS.get(finding.get("category"))


def node_label(node: str) -> str:
    for key, label in NODE_LABELS.items():
        if key in node.lower():
            return label
    return node


def fmt_time(value: Any, with_date: bool = True) -> str:
    if not value:
        return "-"
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return str(value)
    return dt.strftime("%Y-%m-%d %H:%M" if with_date else "%H:%M")


def sorted_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    """위험도 높은 순, 같으면 먼저 시작한 순."""
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(result.get("findings") or [],
                  key=lambda f: (rank.get(f.get("severity"), 9), str(f.get("start_time") or "")))


def headline_finding(result: dict[str, Any]) -> dict[str, Any] | None:
    found = sorted_findings(result)
    return found[0] if found else None


def area_observed(result: dict[str, Any], area: str) -> dict[str, int] | None:
    """분석 영역(Server, Network 등)이 실제로 관측한 값만 센다. 실행되지 않았으면 None.

    정상/경고/장애로 판정하지 않는다. 팀 보고서(report/models.py OPERATIONAL_STATE_POLICY)
    방침대로, 이 시스템은 이상 징후만 관측하고 심각도 기준이 탐지기마다 달라 운영 상태로
    환산할 근거가 없기 때문이다.
    """
    agent = (result.get("agents") or {}).get(area)
    if agent is None:
        return None
    ids = set(agent.get("finding_ids") or [])
    mine = [f for f in result.get("findings") or [] if f.get("finding_id") in ids]
    return {
        "hosts": len({f.get("host") or f.get("service") or "?" for f in mine}),
        "findings": len(mine),
        "high": sum(1 for f in mine if f.get("severity") in ("critical", "high")),
    }


def related_findings(result: dict[str, Any], finding: dict[str, Any]) -> list[dict[str, Any]]:
    """같은 호스트이거나 같은 IP·사용자 등 개체를 공유하는 다른 탐지 결과."""
    mine = {(k, v) for k, vs in (finding.get("entities") or {}).items() for v in vs}
    out = []
    for f in sorted_findings(result):
        if f["finding_id"] == finding["finding_id"]:
            continue
        theirs = {(k, v) for k, vs in (f.get("entities") or {}).items() for v in vs}
        if (finding.get("host") and f.get("host") == finding.get("host")) or (mine & theirs):
            out.append(f)
    return out


def finding_bullets(finding: dict[str, Any]) -> list[str]:
    """탐지 결과 하나를 사람이 읽을 문장 몇 개로."""
    m = finding.get("metrics") or {}
    out = [f"{CATEGORY_KO.get(finding.get('category'), finding.get('category'))} · "
           f"{finding.get('finding_type')} 탐지 (탐지 규칙: {finding.get('detector') or '-'})",
           f"기간: {fmt_time(finding.get('start_time'))} ~ {fmt_time(finding.get('end_time'))}"]
    where = " / ".join(x for x in (finding.get("host"), finding.get("service")) if x)
    if where:
        out.append(f"대상: {where}")
    for kind, values in (finding.get("entities") or {}).items():
        out.append(f"관련 {kind}: {', '.join(map(str, values[:5]))}")
    if "observed_count" in m:
        line = f"관측 {m['observed_count']}건"
        if "baseline" in m:
            line += f" (평소 {m['baseline']}"
            line += f", {m['ratio']}배)" if "ratio" in m else ")"
        out.append(line)
    else:
        shown = [f"{k}={v}" for k, v in m.items() if k != "evidence_count"][:3]
        if shown:
            out.append("주요 수치: " + ", ".join(shown))
    sources = sorted({e.get("source_type") for e in finding.get("evidence") or [] if e.get("source_type")})
    total = m.get("evidence_count", len(finding.get("evidence") or []))
    out.append(f"근거 이벤트 {total}건" + (f" ({', '.join(sources)})" if sources else ""))
    return out


def system_status() -> tuple[bool, str]:
    """보안 매뉴얼 검색에 필요한 연결 상태를 가볍게 확인한다(키 존재 + DB 주소 확인)."""
    import os
    import socket
    from urllib.parse import urlparse

    try:
        from dotenv import load_dotenv
        load_dotenv(PROJECT_ROOT / ".env")
    except ImportError:
        pass
    problems = []
    url = os.getenv("SUPABASE_URL")
    if not url:
        problems.append("SUPABASE_URL 없음")
    else:
        try:
            socket.getaddrinfo(urlparse(url).hostname, 443)
        except (OSError, UnicodeError):
            problems.append("문서 DB 연결 안 됨")
    if not os.getenv("OPENAI_API_KEY"):
        problems.append("OPENAI_API_KEY 없음")
    return (not problems, "매뉴얼 검색 연결됨" if not problems else " · ".join(problems))


# ───────────────────────── 시연 데이터 (팀 scripts/build_demo_replay.py 산출물) ─────────────────────────
GUIDANCE_STATUS_KO = {
    "not_started": "대기", "analyzing": "조회 중", "completed": "완료", "not_requested": "요청 안 함",
}
REPORT_STATUS_KO = {"not_ready": "작성 전", "ready": "준비됨"}
AGENT_KO = {
    "application_agent": "애플리케이션 로그", "server_agent": "서버", "network_agent": "네트워크",
    "authentication_agent": "인증 로그", "security_agent": "보안 종합",
}
GROUPING_KO = {
    "same_host": "같은 호스트", "same_service": "같은 서비스", "shared_entity": "공유 개체(IP·계정 등)",
    "shared_evidence": "공유 근거 이벤트", "temporal_overlap": "시간 겹침", "temporal_precedes": "시간 선후",
}


def list_demo_packs() -> list[dict[str, Any]]:
    """output/demo/<시나리오>/manifest.json 을 찾아 목록으로. 제목 순."""
    root = PROJECT_ROOT / "output" / "demo"
    packs = []
    for manifest in sorted(root.glob("*/manifest.json")) if root.exists() else []:
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        data["_dir"] = str(manifest.parent)
        packs.append(data)
    return packs


def load_demo_file(pack_dir: str, name: str) -> dict[str, Any]:
    return json.loads((Path(pack_dir) / name).read_text(encoding="utf-8"))


# 시연 시나리오 설명 (팀 시연 계획표). 키는 팀 demo/scenarios.py 의 scenario_key 와 같다.
# 표에 없는 시나리오(샘플 등)는 설명 없이 manifest 제목만 보여준다.
DEMO_SCENARIOS: dict[str, dict[str, Any]] = {
    "gaia_network_incident": {
        "no": 1, "name": "네트워크 이상 발생 및 조사 대상 선정", "area": "Network / Server",
        "details": ["dbservice1에서 평소와 다른 네트워크 사용량 이상이 발생",
                    "같은 시간대의 여러 이상 현상을 비교하고 상관분석·조사 대상 선정으로 실제 조사 대상 사건만 선택",
                    "여러 이상 중 관련 있는 사건만 추려내는 과정"],
        "point": "여러 이상 현상 중 실제 조사해야 할 사건을 구분하고 선택하는 과정",
    },
    "gaia_service_degradation": {
        "no": 2, "name": "서비스 응답 지연 이상", "area": "Application",
        "details": ["dbservice1에서 짧은 시간 동안 심각한 응답 지연이 반복 발생",
                    "같은 서비스에서 연속으로 발생한 지연 탐지를 상관분석해 하나의 사건으로 묶어 조사",
                    "반복된 이상을 하나의 사건으로 통합하는 과정"],
        "point": "같은 서비스에서 반복 발생한 이상을 하나의 사건으로 묶는 과정",
    },
    "gaia_server_resource_anomaly": {
        "no": 3, "name": "CPU 사용량 이상", "area": "Server",
        "details": ["redis에서 평소보다 높은 CPU 사용량 이상이 발생",
                    "같은 시간대의 다른 서비스 지연과 비교하지만 연결 근거가 없어 별도 사건으로 분리",
                    "동시에 발생한 문제를 근거 없이 원인과 결과로 연결하지 않는 모습"],
        "point": "동시에 발생한 문제라고 해서 무조건 원인과 결과로 연결하지 않는 과정",
    },
    "russellmitchell_web_scan": {
        "no": 4, "name": "웹 요청 급증 및 보안성 이상 조사", "area": "Application / Security",
        "details": ["intranet_server에 짧은 시간 동안 비정상적으로 많은 웹 요청과 높은 오류 응답이 발생",
                    "요청 급증과 같은 시간대의 스캔 패턴을 각각 분석하고, 직접적인 연관성이 없으면 별도 사건으로 구분한 뒤 "
                    "보안 매뉴얼(RAG)로 대응 절차를 확인",
                    "비정상 웹 요청 탐지부터 보안 대응 가이드까지 이어지는 흐름"],
        "point": "비정상적인 웹 요청을 탐지하고, 별도 보안 이상과 구분한 뒤 보안 매뉴얼로 대응 가이드까지 제공하는 과정",
    },
}


# ───────────────────────── 화면 설정 (시연 모드 켜기/끄기) ─────────────────────────
# 브라우저를 새로고침해도 유지되도록 파일에 저장한다. output/ 는 git 에 올라가지 않는다.
SETTINGS_FILE = PROJECT_ROOT / "output" / "frontend_settings.json"


def load_settings() -> dict[str, Any]:
    try:
        return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def demo_mode_enabled() -> bool:
    return bool(load_settings().get("demo_mode", True))  # 설정 파일이 없으면 메뉴를 보여준다


def set_demo_mode(on: bool) -> None:
    data = load_settings()
    data["demo_mode"] = bool(on)
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")



# ───────────────────────── 분석 범위 (탐지 0건일 때 '정상'으로 오해하지 않도록) ─────────────────────────
# 팀 Agent Skill 이 실제로 탐지기를 돌리는 로그 종류. 백엔드에서 읽어 오고, 못 읽으면 아래 값을 쓴다.
_FALLBACK_ANALYZED_TYPES = {"apache_access", "gaia_log", "gaia_trace", "gaia_metric"}


def analyzed_source_types() -> set[str]:
    out: set[str] = set()
    for mod in ("application_analysis.scripts.run_application_analysis",
                "server_analysis.scripts.run_server_analysis",
                "network_analysis.scripts.run_network_analysis",
                "authentication_analysis.scripts.run_authentication_analysis",
                "security_analysis.scripts.run_security_analysis"):
        try:
            m = __import__(f"agent_skills.{mod}", fromlist=["SOURCE_TYPES"])
            out |= set(getattr(m, "SOURCE_TYPES", ()) or ())
        except Exception:
            return set(_FALLBACK_ANALYZED_TYPES)
    return out or set(_FALLBACK_ANALYZED_TYPES)


def analysis_coverage(result: dict[str, Any]) -> dict[str, Any]:
    """이번 분석에서 탐지기가 실제로 검사한 로그와 검사하지 못한 로그를 나눈다.

    source_type_counts 가 없는 예전 결과 JSON 이면 available_source_types(종류만)를 쓴다.
    """
    counts = result.get("source_type_counts")
    if not counts:
        counts = {t: None for t in result.get("available_source_types") or []}
    covered = analyzed_source_types()
    checked = {t: n for t, n in counts.items() if t in covered}
    skipped = {t: n for t, n in counts.items() if t not in covered}
    limited = []  # 실행됐지만 '미구현/부분 구현'이라고 스스로 밝힌 분석 영역
    for area, agent in (result.get("agents") or {}).items():
        if not agent:
            continue
        status = str(agent.get("status") or "").lower()
        if "not_implemented" in status or "partial" in status:
            notes = (agent.get("extra") or {}).get("notes") or []
            limited.append((AREA_LABELS.get(area, area), status, notes[0] if notes else ""))
    # 지정한 데이터셋이 파일에 없으면 백엔드가 이벤트를 전부 건너뛴다(탐지 0건의 흔한 원인)
    mismatch = None
    want, have = result.get("scope_dataset"), result.get("dataset_counts") or {}
    if want and have and want not in have:
        mismatch = {"selected": want, "in_file": list(have)}
    return {"checked": checked, "skipped": skipped, "limited": limited, "mismatch": mismatch}


def fmt_types(types: dict[str, Any]) -> str:
    return ", ".join(f"{t} {n:,}건" if isinstance(n, int) else t for t, n in types.items()) or "없음"
