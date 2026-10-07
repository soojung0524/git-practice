"""실제 RAG Agent를 호출하는 smoke test (pytest와 분리).

기본 pytest에 넣지 않는다. 실제 OpenAI/Supabase를 호출하므로 API key와 Supabase가
없는 환경에서는 호출하지 않고 명확하게 종료한다.

저장된 output/findings/gaia.pkl을 재사용해 detector 30분 재실행을 피한다.

사용:
    python scripts/smoke_security_guidance.py
    python scripts/smoke_security_guidance.py --dry-run     # RAG 호출 없이 질문만 출력
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(PROJECT_ROOT / ".env")

from correlation import correlate_scenario, focus_on, select_incidents  # noqa: E402
from guidance import (  # noqa: E402
    RagSecurityGuidanceProvider,
    build_security_guidance_question,
)
from scenario import make_analysis_scenario, project_findings  # noqa: E402
from src.models.finding_store import load_findings  # noqa: E402

FINDINGS_PATH = PROJECT_ROOT / "output" / "findings" / "gaia.pkl"
REQUIRED_ENV = ("OPENAI_API_KEY", "SUPABASE_URL", "SUPABASE_KEY")


def _check_environment() -> list[str]:
    return [name for name in REQUIRED_ENV if not os.getenv(name)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="RAG를 호출하지 않고 생성된 질문만 출력한다(환경변수 불필요)",
    )
    parser.add_argument("--findings", default=str(FINDINGS_PATH))
    args = parser.parse_args(argv)

    findings_path = Path(args.findings)
    if not findings_path.is_file():
        print(f"[중단] Finding 파일이 없다: {findings_path}")
        print("  먼저 다음을 실행할 것:")
        print("    python scripts/build_findings.py --events output/aligned/gaia.pkl \\")
        print("        --out output/findings/gaia.pkl")
        return 1

    print(f"[1/5] Finding 적재: {findings_path}")
    findings = list(load_findings(findings_path))
    print(f"      {len(findings):,}건")

    # anchor: dbservice1의 network_usage_anomaly 중 가장 이른 것
    candidates = [
        f
        for f in findings
        if f.finding_type == "network_usage_anomaly" and f.service == "dbservice1"
    ]
    if not candidates:
        print("[중단] dbservice1 network_usage_anomaly Finding이 없다.")
        return 1
    anchor = min(candidates, key=lambda f: (f.start_time, f.finding_id))
    print(f"\n[2/5] anchor 선정")
    print(f"      finding_id : {anchor.finding_id}")
    print(f"      시각       : {anchor.start_time} ~ {anchor.end_time}")
    print(f"      service    : {anchor.service} / severity: {anchor.severity}")

    scenario = make_analysis_scenario(
        "net-smoke",
        anchors={"gaia": anchor.start_time},
        duration=timedelta(minutes=20),
        lead=timedelta(minutes=10),
    )
    projection = project_findings(findings, scenario, on_missing_window="skip")
    result = correlate_scenario(projection)
    selection = select_incidents(result, focus_on([anchor]))

    print(f"\n[3/5] projection / correlation / selection")
    print(f"      projection Finding      : {len(projection)}")
    print(f"      candidate incident      : {len(result.incidents)} "
          f"(multi {len(result.multi_finding_incidents)}, "
          f"single {len(result.single_finding_incidents)})")
    print(f"      focused incident        : {len(selection.focused_incident_ids)}")
    print(f"      unmatched anchor        : {selection.unmatched_anchor_finding_ids}")

    if not selection.focused_incident_ids:
        print("[중단] focused incident가 없다. anchor가 Window 안에 있는지 확인할 것.")
        return 1

    focused_id = selection.focused_incident_ids[0]
    focused = result.incident_by_id(focused_id)
    print(f"\n      focused incident : {focused_id}")
    print(f"        finding_ids    : {focused.finding_ids}")
    print(f"        services       : {focused.impact.affected_services}")
    print(f"        finding types  : {focused.impact.finding_type_counts}")

    excluded = [
        i.incident_id for i in result.incidents if i.incident_id != focused_id
    ]
    print(f"      질문에서 제외된 incident {len(excluded)}건:")
    for incident_id in excluded:
        other = result.incident_by_id(incident_id)
        print(f"        {incident_id} findings={other.finding_count} "
              f"services={other.impact.affected_services}")

    question = build_security_guidance_question(focused)
    print(f"\n[4/5] 생성된 질문 ({len(question):,}자)")
    print("-" * 78)
    print(question)
    print("-" * 78)

    # 질문에 다른 incident가 섞이지 않았는지 확인
    leaked = [i for i in excluded if i in question]
    print(f"\n      다른 incident id 누출 : {leaked or '없음'}")
    other_services = {
        s
        for i in excluded
        for s in result.incident_by_id(i).impact.affected_services
    } - set(focused.impact.affected_services)
    leaked_services = sorted(s for s in other_services if s in question)
    print(f"      다른 service 누출     : {leaked_services or '없음'}")

    if args.dry_run:
        print("\n[5/5] --dry-run: RAG를 호출하지 않고 종료한다.")
        return 0

    missing = _check_environment()
    if missing:
        print(f"\n[중단] 환경변수가 없어 RAG를 호출하지 않는다: {missing}")
        print("  .env에 해당 값을 설정한 뒤 다시 실행할 것.")
        print("  (질문 생성까지만 확인하려면 --dry-run)")
        return 1

    print("\n[5/5] 실제 rag_agent 호출")
    provider = RagSecurityGuidanceProvider()
    try:
        response = provider.generate(question)
    except Exception as exc:
        print(f"      실패: {type(exc).__name__}: {exc}")
        return 1

    print(f"      provider : {response.provider_name}")
    print(f"      model    : {response.model}")
    print(f"      길이     : {len(response.response):,}자")
    print(f"      [Page 인용 포함 : {'[Page' in response.response}")
    print("-" * 78)
    print(response.response)
    print("-" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
