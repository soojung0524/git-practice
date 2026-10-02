"""RAG 에이전트 평가 스크립트

rag_testset.jsonl 의 문항을 rag_agent 에 하나씩 보내고 채점합니다.

  1) 키워드 채점  : must_include / must_not_include 로 빠르게 1차 판정
  2) LLM 채점     : --judge 를 주면 기대 정답과 의미 비교 (0/1/2점 + 환각 여부)
  3) 실패 원인    : --judge 사용 시, 틀린 문항의 검색 결과에 근거가 있었는지 보고
                    '검색 실패' 와 '생성 실패' 를 구분 (원문이 영어라 키워드로는 판단 불가)

사용 예
  python tests/eval_rag.py                                   # 키워드 채점만
  python tests/eval_rag.py --judge openai:gpt-4o-mini        # LLM 채점 추가
  python tests/eval_rag.py --ids Q01 Q27 Q47                 # 일부 문항만
  python tests/eval_rag.py --category 환각함정 시나리오
  python tests/eval_rag.py --ids Q06 Q19 Q48 --repeat 3 --judge openai:gpt-4o-mini

키워드 규칙: must_include 의 각 항목은 모두 있어야 하고,
            'A|B' 처럼 쓰면 A 또는 B 중 하나만 있으면 됩니다.
"""
import argparse
import csv
import json
import re
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.append(str(Path(__file__).resolve().parents[1]))  # 프로젝트 루트

from src.agents.rag_agent import rag_agent  # noqa: E402


# ───────────────────────── 유틸 ─────────────────────────
def to_text(content) -> str:
    """메시지 content 가 문자열이든 블록 리스트든 텍스트로 변환."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict):
                parts.append(p.get("text") or "")
            else:
                parts.append(str(p))
        return "\n".join(parts)
    return str(content or "")


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).lower()


def check_keywords(text: str, must: list[str], must_not: list[str]):
    t = norm(text)
    missing = [k for k in must if not any(norm(a) in t for a in k.split("|"))]
    forbidden = [k for k in must_not if norm(k) in t]
    return missing, forbidden


def extract(result: dict):
    """에이전트 결과에서 최종 답변과 검색(도구) 결과 텍스트를 뽑는다."""
    msgs = result["messages"]
    answer = to_text(msgs[-1].content)
    tool_texts = [to_text(m.content) for m in msgs if getattr(m, "type", "") == "tool"]
    return answer, "\n".join(tool_texts), len(tool_texts)


# ───────────────────────── LLM 채점 ─────────────────────────
# 채점 모델이 점수를 바로 매기면 답변을 잘못 읽거나(내용이 있는데 없다고 판단),
# 근거 있는 추가 정보를 감점하는 일이 잦았다. 그래서 기대 정답을 핵심 요소로
# 나눈 뒤 요소별로 '포함 / 누락 / 모순' 을 먼저 적게 하고, 점수는 코드가 계산한다.
JUDGE_PROMPT = """당신은 RAG 시스템의 답변을 채점하는 평가자입니다.

[질문]
{question}

[기대 정답 (핵심)]
{expected}

[채점 조건]
{notes}

[에이전트 답변]
{answer}

채점 절차
1. 핵심 요소는 [기대 정답 (핵심)] 에서만 뽑으십시오 (1~4개).
   [채점 조건] 의 문장은 요소가 아닙니다. 에이전트 답변의 문장도 요소가 아닙니다.
2. 각 요소를 에이전트 답변과 비교해 분류하십시오.
   - covered: 답변에 같은 의미의 문장이 있음. 반드시 "요소 ← 답변 인용: '...'" 형식으로
     답변의 해당 부분을 짧게 그대로 인용하십시오. 인용할 문장이 없으면 covered 가 아닙니다.
   - missing: 답변 전체를 끝까지 읽어도 같은 의미의 문장이 없음
   - contradicted: 답변이 반대 내용이나 다른 값을 단정함
   표현·언어·순서가 달라도 의미가 같으면 covered 입니다.
   질문에 이미 들어 있는 전제(예: "실패했다")를 답변이 반복하지 않아도 누락이 아닙니다.
3. [기대 정답] 이 "문서에 없다" 류인데 에이전트가 해당 기능·절차가 있다고 단정하면 contradicted 입니다.
4. 기대 정답에 없는 추가 정보는 감점하지 마십시오.
   추가 정보가 기대 정답과 명백히 모순될 때만 contradicted 에 적으십시오.
5. capped_by_rule: [채점 조건] 에 "최대 1점" 또는 "0점" 조건이 적혀 있고 답변이 그 조건에
   해당할 때만 true. [채점 조건] 이 "(없음)" 이면 항상 false.
   "0점" 조건에 해당하면 그 내용을 contradicted 에도 적으십시오.

hallucination 판정
- true: 기대 정답과 모순되는 구체적 사실(수치, 기간, 기능 유무, 절차)을 단정한 경우,
        또는 "문서에 없다"가 정답인데 구체적인 기능·절차를 있는 것처럼 단정한 경우
- false: 그 밖의 경우. 기대 정답에 없을 뿐 그럴듯한 추가 설명은 환각이 아닙니다.

reason 은 한국어 한두 문장으로 쓰십시오."""

# 검색 결과(문서 원문은 영어)에 정답 근거가 있었는지 판단. 실패 문항에만 호출.
CONTEXT_PROMPT = """아래는 RAG 시스템이 질문에 답하기 위해 검색한 문서 발췌입니다(영어일 수 있음).

[질문]
{question}

[기대 정답]
{expected}

[검색된 발췌]
{context}

검색된 발췌만으로 기대 정답의 핵심 내용을 뒷받침할 수 있습니까?
일부만 있으면 false 로 하고, reason 에 무엇이 빠졌는지 한국어 한 문장으로 쓰세요."""

MAX_CONTEXT_CHARS = 20000


def score_from_elements(covered, missing, contradicted, capped: bool) -> int:
    """요소 분류 결과로 점수 계산. 모순이 있거나 맞힌 게 없으면 0, 누락이 있으면 1."""
    if contradicted or not covered:
        return 0
    if missing or capped:
        return 1
    return 2


def build_judge(model_name: str):
    from langchain.chat_models import init_chat_model
    from pydantic import BaseModel, Field

    # 필드 순서대로 생성되므로, 요소 분류를 먼저 쓰고 판정은 마지막에 쓰게 한다.
    class Verdict(BaseModel):
        covered: list[str] = Field(description="'요소 ← 답변 인용: ...' 형식. 답변에 들어 있는 핵심 요소")
        missing: list[str] = Field(description="답변에 없는 핵심 요소")
        contradicted: list[str] = Field(description="답변이 반대로 말하거나 다른 값을 단정한 요소")
        capped_by_rule: bool = Field(
            description="[채점 조건]의 '최대 1점'/'0점' 조건에 해당하면 true. 조건이 (없음)이면 false")
        hallucination: bool
        reason: str

    llm = init_chat_model(model_name, temperature=0)
    structured = llm.with_structured_output(Verdict)

    class Evidence(BaseModel):
        has_evidence: bool
        reason: str

    ctx_checker = llm.with_structured_output(Evidence)

    def judge(question, expected, answer, notes=""):
        v = structured.invoke(JUDGE_PROMPT.format(
            question=question, expected=expected, answer=answer,
            notes=notes.strip() or "(없음)"))
        # 채점 조건이 없는 문항에서 채점 모델이 임의로 상한을 거는 경우가 있어 코드에서 막는다
        capped = v.capped_by_rule and bool(notes.strip())
        score = score_from_elements(v.covered, v.missing, v.contradicted, capped)
        detail = {"covered": v.covered, "missing": v.missing,
                  "contradicted": v.contradicted, "capped": capped}
        return score, v.hallucination, v.reason, detail

    def check_context(question, expected, context):
        v = ctx_checker.invoke(CONTEXT_PROMPT.format(
            question=question, expected=expected, context=context[:MAX_CONTEXT_CHARS]))
        return v.has_evidence, v.reason

    return judge, check_context


# ───────────────────────── 메인 ─────────────────────────
def is_pass(r) -> bool:
    return r["status"] in ("PASS", "KW_PASS")


def run_one(it, judge, check_context):
    """문항 하나를 에이전트에 보내고 채점한 결과 row 를 돌려준다."""
    row = {k: it.get(k, "") for k in ("id", "category", "difficulty", "question",
                                      "expected_answer", "grading_notes", "source_pages")}
    t0 = time.time()
    try:
        result = rag_agent.invoke({"messages": [{"role": "user", "content": it["question"]}]})
        answer, context, n_tools = extract(result)
    except Exception as e:  # 한 문항 실패로 전체가 멈추지 않게
        row.update(status="ERROR", answer=f"{type(e).__name__}: {e}",
                   latency_s=round(time.time() - t0, 1), diagnosis=str(e))
        return row
    row["latency_s"] = round(time.time() - t0, 1)
    row["answer"] = answer
    row["tool_calls"] = n_tools

    # 1) 키워드
    missing, forbidden = check_keywords(answer, it["must_include"], it["must_not_include"])
    kw_pass = not missing and not forbidden
    row.update(keyword_pass=kw_pass, missing="; ".join(missing), forbidden="; ".join(forbidden))

    # 2) LLM 채점
    if judge:
        try:
            score, hallu, reason, detail = judge(it["question"], it["expected_answer"], answer,
                                                it.get("grading_notes", ""))
            row["judge_detail"] = json.dumps(detail, ensure_ascii=False)
        except Exception as e:
            score, hallu, reason = None, None, f"채점 실패: {e}"
        row.update(judge_score=score, hallucination=hallu, judge_reason=reason)
        status = {2: "PASS", 1: "PARTIAL", 0: "FAIL"}.get(score, "KW_" + ("PASS" if kw_pass else "FAIL"))
    else:
        status = "PASS" if kw_pass else "FAIL"
    row["status"] = status

    # 3) 실패 원인 추정: 검색 결과에 근거가 있었나 (LLM 채점 시에만 판단)
    if is_pass(row):
        diag = ""
    elif n_tools == 0:
        diag = "검색 도구를 호출하지 않음"
    elif it["category"] == "환각함정":
        diag = "문서에 없는 내용을 답함(환각 의심)"
    elif check_context:
        try:
            has_ev, ev_reason = check_context(it["question"], it["expected_answer"], context)
            row["context_has_evidence"] = has_ev
            diag = ("생성 실패: 근거는 검색됐지만 답변에 반영 안 됨" if has_ev
                    else f"검색 실패: {ev_reason}")
        except Exception as e:
            diag = f"검색 진단 실패: {e}"
    else:
        diag = "오답 (검색/생성 구분은 --judge 필요)"
    row["diagnosis"] = diag
    return row


def summarize(group, judge_on):
    done = [r for r in group if r["status"] != "ERROR"]
    passed = sum(is_pass(r) for r in done)
    scores = [r["judge_score"] for r in done if isinstance(r.get("judge_score"), int)]
    hallu = sum(r.get("hallucination") is True for r in done)
    lat = sorted(r["latency_s"] for r in done)
    return {
        "실행": len(group),
        "통과": f"{passed}/{len(done)} ({passed / len(done):.0%})" if done else "-",
        "평균점수": f"{sum(scores) / len(scores):.2f}/2" if scores else "-",
        "환각": hallu if judge_on else "-",
        "오류": len(group) - len(done),
        # 가끔 튀는 API 지연에 휘둘리지 않도록 중앙값
        "지연(중앙)": f"{lat[len(lat) // 2]:.1f}s" if lat else "-",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--testset", default=str(HERE / "rag_testset.jsonl"))
    ap.add_argument("--judge", help="LLM 채점 모델 (예: openai:gpt-4o-mini, openai:gpt-4.1)")
    ap.add_argument("--ids", nargs="*", help="특정 문항만 (예: Q01 Q27)")
    ap.add_argument("--category", nargs="*", help="특정 유형만 (예: 사실 환각함정)")
    ap.add_argument("--limit", type=int, help="앞에서부터 N문항만")
    ap.add_argument("--repeat", type=int, default=1,
                    help="각 문항을 N번 실행 (답변이 실행마다 달라지는 정도를 확인)")
    ap.add_argument("--sleep", type=float, default=0.0, help="실행 사이 대기(초), rate limit 대비")
    ap.add_argument("--outdir", default=str(HERE / "results"))
    args = ap.parse_args()

    items = [json.loads(l) for l in open(args.testset, encoding="utf-8") if l.strip()]
    if args.ids:
        items = [i for i in items if i["id"] in set(args.ids)]
    if args.category:
        items = [i for i in items if i["category"] in set(args.category)]
    if args.limit:
        items = items[: args.limit]
    if not items:
        sys.exit("선택된 문항이 없습니다.")

    judge, check_context = build_judge(args.judge) if args.judge else (None, None)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = outdir / f"eval_{stamp}.csv"

    fields = ["id", "run", "category", "difficulty", "status", "judge_score", "hallucination",
              "judge_reason", "judge_detail", "keyword_pass", "missing", "forbidden",
              "tool_calls", "context_has_evidence", "diagnosis", "latency_s", "question",
              "answer", "expected_answer", "grading_notes", "source_pages"]
    f = open(csv_path, "w", newline="", encoding="utf-8-sig")
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()

    runs = [(rep, it) for rep in range(1, args.repeat + 1) for it in items]
    rows = []
    rep_note = f" × {args.repeat}회" if args.repeat > 1 else ""
    print(f"{len(items)}문항{rep_note} 평가 시작  (LLM 채점: {args.judge or '끔'})\n")

    for n, (rep, it) in enumerate(runs, 1):
        row = run_one(it, judge, check_context)
        row["run"] = rep
        w.writerow(row); f.flush(); rows.append(row)

        extra = f"  score={row.get('judge_score')}" if judge and row["status"] != "ERROR" else ""
        tag = f"#{rep} " if args.repeat > 1 else ""
        print(f"[{n:>3}/{len(runs)}] {tag}{it['id']} {row['status']:<8}{extra}  "
              f"{row.get('latency_s', '-')}s  {row.get('diagnosis', '')}")
        if args.sleep:
            time.sleep(args.sleep)

    f.close()

    # ───── 요약 ─────
    by_cat = defaultdict(list)
    for r in rows:
        by_cat[r["category"]].append(r)
    summary = {"전체": summarize(rows, bool(judge)),
               **{c: summarize(g, bool(judge)) for c, g in by_cat.items()}}

    print("\n" + "=" * 78)
    print(f"{'유형':<8}" + "".join(f"{k:>12}" for k in summary["전체"]))
    print("-" * 78)
    for cat, s in summary.items():
        print(f"{cat:<8}" + "".join(f"{str(v):>12}" for v in s.values()))
    print("=" * 78)

    by_id = defaultdict(list)
    for r in rows:
        by_id[r["id"]].append(r)

    # 반복 실행 시: 문항별 통과 횟수. 전부 실패 = 약점, 일부 실패 = 불안정
    if args.repeat > 1:
        weak = [(i, rs) for i, rs in by_id.items() if not any(is_pass(r) for r in rs)]
        flaky = [(i, rs) for i, rs in by_id.items()
                 if any(is_pass(r) for r in rs) and not all(is_pass(r) for r in rs)]
        if weak:
            print(f"\n매번 실패 (진짜 약점)")
            for i, rs in weak:
                print(f"  {i} [{rs[0]['category']}] 0/{len(rs)}: {rs[-1].get('diagnosis') or rs[-1].get('judge_reason')}")
        if flaky:
            print(f"\n실행마다 다름 (불안정)")
            for i, rs in flaky:
                print(f"  {i} [{rs[0]['category']}] {sum(is_pass(r) for r in rs)}/{len(rs)} 통과")
    else:
        fails = [r for r in rows if not is_pass(r)]
        if fails:
            print("\n확인이 필요한 문항")
            for r in fails:
                why = r.get("diagnosis") or r.get("judge_reason") or r.get("missing") or r.get("answer", "")[:80]
                print(f"  {r['id']} [{r['category']}] {r['status']}: {why}")

    # 채점 모델과 키워드 검사가 엇갈린 경우 → 사람이 확인할 목록
    if judge:
        review = []
        for r in rows:
            if r["status"] == "ERROR" or r.get("judge_score") is None:
                continue
            if is_pass(r) and not r.get("keyword_pass"):
                review.append((r, f"채점 통과, 키워드 누락({r.get('missing') or r.get('forbidden')}) → 표현 차이인지 확인"))
            elif not is_pass(r) and r.get("keyword_pass"):
                review.append((r, "키워드는 통과, 채점 감점 → 채점 오류인지 확인"))
            if r.get("hallucination") is True:
                review.append((r, "환각 판정 → 실제로 문서와 다른 내용인지 확인"))
        if review:
            print("\n수동 검토 목록 (채점 모델 판정을 그대로 믿기 전에 CSV 에서 답변 확인)")
            for r, why in review:
                tag = f"#{r['run']} " if args.repeat > 1 else ""
                print(f"  {tag}{r['id']} {r['status']}: {why}")

    (outdir / f"eval_{stamp}_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n상세 결과: {csv_path}")


if __name__ == "__main__":
    main()