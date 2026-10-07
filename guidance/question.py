"""Focused Incident를 RAG 질문으로 바꾸는 template 기반 순수 함수.

질문을 LLM으로 다시 만들지 않는다. 같은 incident면 항상 같은 질문이 나온다.

=== 기존 SYSTEM_PROMPT와 중복하지 않는다 ===

rag_agent의 SYSTEM_PROMPT가 이미 보장하는 것은 여기서 다시 적지 않는다.
  - 답변 전 search_runbook 검색 의무, 영어 키워드 query 작성
  - [Page N] 근거 표시
  - 사고 대응 시나리오 질문의 5단 답변 형식(상황 요약 / 관련 대응 절차 / 확인해야 할
    사항 / 권장 대응 방향 / 참고 문서 및 페이지)
  - 봉쇄 시 전제조건·권한 설명, 서비스가 하는 일과 고객이 하는 일 구분
  - 문서에서 확인되지 않으면 그 사실을 밝히기

그래서 이 계층이 덧붙이는 것은 "관측 상황"과 그에 대한 맥락 연결 한 문장뿐이다.
SYSTEM_PROMPT의 "사고 대응 시나리오 질문" 분기가 이 경우를 그대로 다룬다.

=== 넣지 않는 것 ===

Ground Truth, raw event, evidence 원문, 다른 incident, 확정된 Root Cause,
Finding에 없는 추측값. 전부 CorrelatedIncident에 실제로 있는 값만 쓴다.

이 모듈은 rag_agent / rag_tool / langchain / supabase를 import하지 않는다.
"""

from __future__ import annotations

from correlation import CorrelatedIncident

# 질문에 담을 timeline 최대 줄 수. GAIA에는 한 service에 latency Finding이 수천 건
# 나올 수 있어(실측 7,248건) 상한이 없으면 프롬프트가 통제되지 않는다.
DEFAULT_MAX_TIMELINE_ENTRIES = 10

_REQUEST_BLOCK = """## 요청
위 관측 상황에 대해 AWS Security Incident Response User Guide를 근거로 다음을 확인해 주십시오.

1. 이 상황에 적용 가능한 사고 대응 절차
2. 확인·검증해야 할 사항
3. AWS Security Incident Response가 수행하는 역할과 고객이 직접 수행해야 하는 역할
4. 봉쇄(containment)가 관련된다면 문서가 요구하는 전제조건과 권한
5. 이 상황이 문서 범위에 없다면 그 사실

관측 상황은 통계 기반 탐지기가 만든 Finding이며 근본 원인은 확정되지 않았습니다.
위에 적힌 관측값을 다른 상황으로 확대 해석하지 마십시오."""


def _format_seconds(value: float) -> str:
    return f"T+{value:,.0f}s"


def build_security_guidance_question(
    incident: CorrelatedIncident,
    *,
    max_timeline_entries: int = DEFAULT_MAX_TIMELINE_ENTRIES,
) -> str:
    """focused incident 하나를 질문 문자열로 만든다.

    입력은 incident 하나다. 여러 incident를 한 질문에 섞지 않는다.
    """
    if max_timeline_entries < 1:
        raise ValueError("max_timeline_entries는 1 이상이어야 한다")

    impact = incident.impact
    lines: list[str] = ["## 관측 상황"]

    lines.append(f"- incident_id: {incident.incident_id}")
    lines.append(f"- scenario_id: {incident.scenario_id}")
    lines.append(f"- 데이터 출처(dataset): {', '.join(incident.datasets)}")
    lines.append(
        f"- 분석 Window 기준 상대 구간: "
        f"{_format_seconds(incident.relative_start_seconds)} ~ "
        f"{_format_seconds(incident.relative_end_seconds)}"
    )

    if incident.timeline:
        first = incident.timeline[0]
        last = max(incident.timeline, key=lambda e: e.original_end_time)
        lines.append(
            f"- 원본 관측 시각: {first.original_start_time.isoformat()} ~ "
            f"{last.original_end_time.isoformat()}"
        )

    lines.append(f"- 관측된 Finding 수: {incident.finding_count}")
    if impact.finding_type_counts:
        rendered = ", ".join(f"{k}={v}" for k, v in impact.finding_type_counts.items())
        lines.append(f"- Finding 유형: {rendered}")
    if impact.categories:
        lines.append(f"- 분류(category): {', '.join(impact.categories)}")
    if impact.severity_counts:
        rendered = ", ".join(f"{k}={v}" for k, v in impact.severity_counts.items())
        lines.append(f"- severity 분포: {rendered}")

    # 관측된 대상만 적는다. 비어 있으면 줄 자체를 쓰지 않는다(없는 자산을 암시하지 않는다).
    if impact.affected_hosts:
        lines.append(f"- 관측된 host: {', '.join(impact.affected_hosts)}")
    if impact.affected_services:
        lines.append(f"- 관측된 service: {', '.join(impact.affected_services)}")
    if impact.affected_ips:
        lines.append(f"- 관측된 IP: {', '.join(impact.affected_ips)}")
    if impact.affected_users:
        lines.append(f"- 관측된 사용자: {', '.join(impact.affected_users)}")

    # --- timeline ---
    shown = incident.timeline[:max_timeline_entries]
    lines.append("")
    lines.append(f"## 시간 순서 (상위 {len(shown)}건)")
    for entry in shown:
        target = entry.host or entry.service or "대상 미기록"
        marks = []
        if entry.is_long_span:
            marks.append("장기간")
        if entry.was_clipped:
            marks.append("Window 경계 절단")
        suffix = f" ({', '.join(marks)})" if marks else ""
        lines.append(
            f"- {_format_seconds(entry.relative_start_seconds)}"
            f"~{_format_seconds(entry.relative_end_seconds)} "
            f"[{entry.severity}] {entry.finding_type} / {target}{suffix}"
        )
    omitted = len(incident.timeline) - len(shown)
    if omitted > 0:
        lines.append(f"- (나머지 {omitted}건은 분량 때문에 생략. 위 집계에는 포함돼 있다)")

    # --- hypothesis ---
    lines.append("")
    lines.append("## 관계 분석에서 나온 가설 후보")
    if incident.hypotheses:
        for hypothesis in incident.hypotheses:
            lines.append(f"- [{hypothesis.rule_name}] {hypothesis.statement}")
    else:
        lines.append("- 없음 (시간 근접과 식별자 공유 조건을 만족하는 조합이 없었다)")

    # --- caveat ---
    caveats: list[str] = []
    if incident.long_span_finding_ids:
        caveats.append(
            f"장기간에 걸친 Finding {len(incident.long_span_finding_ids)}건이 포함돼 있어 "
            "시간적 근접성은 약한 근거다"
        )
    clipped = [entry for entry in incident.timeline if entry.was_clipped]
    if clipped:
        caveats.append(
            f"Finding {len(clipped)}건은 분석 Window 경계에서 구간이 잘렸다 "
            "(원본 관측 구간은 더 길다)"
        )
    if caveats:
        lines.append("")
        lines.append("## 해석 시 주의")
        for caveat in caveats:
            lines.append(f"- {caveat}")

    lines.append("")
    lines.append(_REQUEST_BLOCK)

    return "\n".join(lines)
