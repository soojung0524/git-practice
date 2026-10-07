"""실제 OpenAI를 호출해 narrative summary를 검증하는 smoke test (pytest와 분리).

저장된 output/findings/*.pkl을 재사용한다. OPENAI_API_KEY가 없으면 호출하지 않고 종료한다.

사용:
    python scripts/smoke_narrative_summary.py
    python scripts/smoke_narrative_summary.py --findings output/findings/gaia.pkl \
        --anchor-finding-type network_usage_anomaly --anchor-service dbservice1
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(PROJECT_ROOT / ".env")

from correlation import correlate_scenario, focus_on, select_incidents  # noqa: E402
from report import (  # noqa: E402
    LlmNarrativeSummaryProvider,
    attach_narrative_summary,
    build_incident_report,
    build_summary_prompt,
    to_json_dict,
)
from scenario import make_analysis_scenario, project_findings  # noqa: E402
from src.models.finding_store import load_findings  # noqa: E402

_NUMBER_RE = re.compile(r"\d[\d,]*\.?\d*")
_CAUSAL_PHRASES = ("원인이다", "원인입니다", "때문에 발생", "때문입니다", "root cause는")


def _collect_numbers(text: str) -> set[str]:
    return {m.group().replace(",", "") for m in _NUMBER_RE.finditer(text)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", default="output/findings/russellmitchell.pkl")
    parser.add_argument("--investigation-id", default="narrative-smoke")
    parser.add_argument("--anchor-finding-type", default=None)
    parser.add_argument("--anchor-service", default=None)
    parser.add_argument("--real", action="store_true")
    args = parser.parse_args(argv)

    if not os.getenv("OPENAI_API_KEY"):
        print("[중단] OPENAI_API_KEY가 없어 호출하지 않는다.")
        return 1

    findings_path = Path(args.findings)
    if not findings_path.is_file():
        print(f"[중단] Finding 파일이 없다: {findings_path}")
        return 1

    findings = list(load_findings(findings_path))
    print(f"[1/5] Finding {len(findings):,}건 적재 ({findings_path})")

    projection = correlation = selection = None
    if not args.real:
        candidates = [
            f
            for f in findings
            if (args.anchor_finding_type is None or f.finding_type == args.anchor_finding_type)
            and (args.anchor_service is None or f.service == args.anchor_service)
        ]
        if not candidates:
            print("[중단] anchor 조건에 맞는 Finding이 없다.")
            return 1
        anchor = min(candidates, key=lambda f: (f.start_time, f.finding_id))
        scenario = make_analysis_scenario(
            "narrative-window",
            anchors={anchor.dataset: anchor.start_time},
            duration=timedelta(minutes=20),
            lead=timedelta(minutes=10),
        )
        projection = project_findings(findings, scenario, on_missing_window="skip")
        correlation = correlate_scenario(projection)
        selection = select_incidents(correlation, focus_on([anchor]))
        print(f"[2/5] anchor: {anchor.finding_id}")
    else:
        print("[2/5] real mode")

    report = build_incident_report(
        investigation_id=args.investigation_id,
        findings=findings,
        agent_results={},
        scenario_projection=projection,
        correlation_result=correlation,
        incident_selection=selection,
    )
    prompt = build_summary_prompt(report)
    print(f"[3/5] 결정론적 보고서 완성: findings {report.findings.total_count} / "
          f"프롬프트 {len(prompt):,}자")
    print(f"      limitations notes {len(report.limitations.notes)}개")

    print("[4/5] 실제 OpenAI 호출")
    provider = LlmNarrativeSummaryProvider()
    try:
        with_summary = attach_narrative_summary(report, provider)
    except Exception as exc:
        print(f"      실패: {type(exc).__name__}: {exc}")
        return 1

    summary = with_summary.narrative_summary
    print(f"      provider : {summary.provider_name}")
    print(f"      model    : {summary.model}")
    print(f"      길이     : {len(summary.text):,}자")

    print("\n[5/5] 검증")
    payload = to_json_dict(report)
    report_text = json.dumps(payload, ensure_ascii=False)

    # (a) 요약에 나온 숫자가 보고서 JSON에 있는지
    summary_numbers = _collect_numbers(summary.text)
    report_numbers = _collect_numbers(report_text)
    invented = sorted(n for n in summary_numbers if n not in report_numbers)
    print(f"      요약 숫자 {len(summary_numbers)}개 중 보고서에 없는 값: "
          f"{invented if invented else '없음'}")

    # (b) 인과 단정 표현
    causal = [p for p in _CAUSAL_PHRASES if p in summary.text]
    print(f"      인과 단정 표현: {causal if causal else '없음'}")

    # (c) limitations 반영 여부
    limitation_terms = ("한계", "주의", "구현", "이상이 없다", "확정", "0건", "제외")
    reflected = [t for t in limitation_terms if t in summary.text]
    print(f"      limitations 관련 표현: {reflected}")

    # (d) narrative_summary 저장 확인
    print(f"      narrative_summary 저장: {with_summary.narrative_summary is not None}")
    print(f"      원본 보고서 불변       : {report.narrative_summary is None}")
    print(f"      프롬프트 == 보고서 JSON: {summary.prompt == prompt}")

    print("\n" + "-" * 78)
    print(summary.text)
    print("-" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
