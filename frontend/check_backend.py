"""백엔드가 바뀐 뒤 프론트엔드와 맞는지 점검한다. 분석은 돌리지 않고 몇 초 안에 끝난다.

실행 (프로젝트 루트에서):
    uv run python frontend/check_backend.py

각 항목은 OK / 주의 / 깨짐 으로 표시된다. '깨짐'이 있으면 그 화면이 동작하지 않으니
결과를 그대로 복사해 공유하면 어디를 고쳐야 하는지 바로 알 수 있다.
"""

from __future__ import annotations

import dataclasses
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import services as svc  # noqa: E402  (프로젝트 루트를 import 경로에 넣는다)

results: list[tuple[str, str, str]] = []


def check(name: str, level: str, detail: str = "") -> None:
    results.append((level, name, detail))


def params(fn) -> set[str]:
    return set(inspect.signature(fn).parameters)


# 1) orchestration ─────────────────────────────────────────────
try:
    from orchestration.graph import build_graph, run_investigation
    p = params(build_graph)
    check("build_graph(interpret=)", "OK" if "interpret" in p else "깨짐", f"인자: {sorted(p)}")
    need = {"event_source", "investigation_id", "dataset", "host", "service",
            "start_time", "end_time", "source_types", "interpret"}
    miss = need - params(run_investigation)
    check("run_investigation 인자", "OK" if not miss else "깨짐", f"없어진 인자: {sorted(miss)}" if miss else "")
except Exception as e:
    check("orchestration.graph import", "깨짐", repr(e))

try:
    from orchestration.state import new_state
    need = {"investigation_id", "event_source", "dataset", "host", "service",
            "start_time", "end_time", "source_types"}
    miss = need - params(new_state)
    check("new_state 인자", "OK" if not miss else "깨짐", f"없어진 인자: {sorted(miss)}" if miss else "")
    state = new_state(investigation_id="check", event_source=lambda: iter(()))
    keys = {"findings", "errors", "routed_agents", "available_source_types", "interpretation",
            *svc.AGENT_RESULT_KEYS}
    miss = keys - set(state)
    check("State 결과 키", "OK" if not miss else "깨짐", f"없어진 키: {sorted(miss)}" if miss else "")
    extra = set(state) - keys - need - {"agent_findings"}
    if extra:
        check("State 새 키", "주의", f"화면에 아직 안 보이는 새 키: {sorted(extra)}")
except Exception as e:
    check("orchestration.state", "깨짐", repr(e))

# 2) Finding / AgentResult ─────────────────────────────────────
try:
    from src.models import finding as fmod
    fields = {f.name for f in dataclasses.fields(fmod.Finding)}
    used = {"finding_id", "dataset", "category", "finding_type", "start_time", "end_time", "host",
            "service", "severity", "summary", "metrics", "evidence", "entities", "detector"}
    miss = used - fields
    check("Finding 필드", "OK" if not miss else "깨짐", f"없어진 필드: {sorted(miss)}" if miss else "")
    if fields - used:
        check("Finding 새 필드", "주의", f"화면에 아직 안 보이는 새 필드: {sorted(fields - used)}")
    sev = tuple(getattr(fmod, "SEVERITY_LEVELS", ()))
    check("severity 단계", "OK" if set(sev) == set(svc.SEVERITY_ORDER) else "깨짐",
          f"백엔드 {sev} / 프론트 {svc.SEVERITY_ORDER}")
    cats = set(getattr(fmod, "CATEGORIES", ()))
    new_cats = cats - set(svc.CATEGORY_KO)
    check("category 목록", "OK" if not new_cats else "주의",
          f"한국어 이름이 없는 새 분류(영어로 표시됨): {sorted(new_cats)}" if new_cats else "")
    ev = {f.name for f in dataclasses.fields(fmod.EvidenceReference)}
    miss = {"source_type", "source_file", "line_number", "timestamp", "event_id"} - ev
    check("EvidenceReference 필드", "OK" if not miss else "깨짐", f"없어진 필드: {sorted(miss)}" if miss else "")
except Exception as e:
    check("src.models.finding", "깨짐", repr(e))

try:
    from agents import AgentResult
    names = ({f.name for f in dataclasses.fields(AgentResult)} if dataclasses.is_dataclass(AgentResult)
             else set(getattr(AgentResult, "model_fields", {})) or set(getattr(AgentResult, "__annotations__", {})))
    miss = {"status", "input_item_count", "findings"} - names
    check("AgentResult 필드", "OK" if not miss else "깨짐", f"없어진 필드: {sorted(miss)}" if miss else "")
except Exception as e:
    check("agents.AgentResult", "깨짐", repr(e))

# 3) 이벤트 로딩 ───────────────────────────────────────────────
try:
    from src.models.event_store import load_events
    check("load_events", "OK", f"인자: {sorted(params(load_events))}")
    files = svc.list_event_files()
    if files:
        first = next(iter(load_events(str(svc.PROJECT_ROOT / files[0]))), None)
        has_host = first is not None and (first.get("host") if isinstance(first, dict) else hasattr(first, "host"))
        check("이벤트 host 속성", "OK" if has_host else "주의",
              "" if has_host else "host 가 없어 서버·네트워크 '정상' 개수가 0으로 나올 수 있음")
    else:
        check("이벤트 파일", "주의", "output/ 에 .pkl 이 없어 이벤트 형식은 확인하지 못함")
except Exception as e:
    check("src.models.event_store", "깨짐", repr(e))

# 4) 그래프 노드 이름 (진행 표시용) ──────────────────────────
try:
    nodes = set(build_graph(interpret=True).get_graph().nodes) - {"__start__", "__end__"}
    unknown = {n for n in nodes if svc.node_label(n) == n}
    check("그래프 노드", "OK" if not unknown else "주의",
          f"진행 표시에 영어 그대로 나오는 노드: {sorted(unknown)}" if unknown else f"{sorted(nodes)}")
except Exception as e:
    check("그래프 노드", "주의", repr(e))

# 5) RAG (import 만, 호출하지 않음) ─────────────────────────────
try:
    from src.agents.rag_agent import rag_agent
    check("rag_agent", "OK" if hasattr(rag_agent, "invoke") else "깨짐")
except Exception as e:
    check("src.agents.rag_agent import", "깨짐", repr(e))

# ── 출력 ──
mark = {"OK": "✅", "주의": "⚠️ ", "깨짐": "❌"}
print("\n프론트엔드 ↔ 백엔드 연결 점검\n" + "-" * 60)
for level, name, detail in results:
    print(f"{mark[level]} {name}" + (f"\n     {detail}" if detail and level != "OK" else ""))
broken = sum(1 for r in results if r[0] == "깨짐")
warn = sum(1 for r in results if r[0] == "주의")
print("-" * 60)
print("결론:", "프론트 수정이 필요합니다." if broken else
      ("동작은 하지만 확인할 점이 있습니다." if warn else "프론트 수정 없이 그대로 쓰면 됩니다."))
sys.exit(1 if broken else 0)
