"""저장된 Finding으로 IncidentReport JSON을 만든다.

detector를 다시 돌리지 않고 output/findings/*.pkl을 재사용한다(GAIA 전체 재실행은 약 64분).
LLM을 호출하지 않는다 - 결정론적 보고서만 만든다.

사용 예:

    # GAIA: dbservice1 network anomaly를 anchor로 한 focused incident 보고서
    python scripts/build_incident_report.py \
        --findings output/findings/gaia.pkl \
        --anchor-finding-type network_usage_anomaly --anchor-service dbservice1

    # russellmitchell: real mode 전체 보고서
    python scripts/build_incident_report.py \
        --findings output/findings/russellmitchell.pkl --real
"""

from __future__ import annotations

import argparse
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
    attach_narrative_summary,
    build_incident_report,
    default_report_path,
    save_json,
    to_json,
)
from scenario import make_analysis_scenario, project_findings  # noqa: E402
from src.models.finding_store import load_findings  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", required=True)
    parser.add_argument("--investigation-id", default="report-demo")
    parser.add_argument("--real", action="store_true", help="scenario 없이 real mode 보고서")
    parser.add_argument("--anchor-finding-type", default=None)
    parser.add_argument("--anchor-service", default=None)
    parser.add_argument("--window-minutes", type=int, default=20)
    parser.add_argument("--lead-minutes", type=int, default=10)
    parser.add_argument("--out", default=None)
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument(
        "--narrative", action="store_true", help="실제 OpenAI로 자연어 요약을 붙인다"
    )
    parser.add_argument(
        "--guidance", action="store_true", help="실제 RAG Agent로 security guidance를 만든다"
    )
    args = parser.parse_args(argv)

    findings_path = Path(args.findings)
    if not findings_path.is_file():
        print(f"[중단] Finding 파일이 없다: {findings_path}")
        return 1

    findings = list(load_findings(findings_path))
    print(f"[1/4] Finding 적재: {len(findings):,}건 ({findings_path})")

    # 실제 Agent 결과가 없으므로(저장된 것은 Finding뿐) agent_results는 비워 둔다.
    # 가짜 AgentResult를 만들지 않는다 - agent_statistics는 실제 실행 결과만 담는다.
    agent_results: dict[str, object] = {}

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
        print(f"[2/4] anchor: {anchor.finding_id}")
        print(f"       {anchor.finding_type} / {anchor.service} / {anchor.start_time}")

        scenario = make_analysis_scenario(
            "report-window",
            anchors={anchor.dataset: anchor.start_time},
            duration=timedelta(minutes=args.window_minutes),
            lead=timedelta(minutes=args.lead_minutes),
        )
        projection = project_findings(findings, scenario, on_missing_window="skip")
        correlation = correlate_scenario(projection)
        selection = select_incidents(correlation, focus_on([anchor]))
        print(f"[3/4] projection {len(projection)} / incident {len(correlation.incidents)} "
              f"(multi {len(correlation.multi_finding_incidents)}) / "
              f"focused {len(selection.focused_incident_ids)}")
    else:
        print("[2/4] real mode (scenario 없음)")
        print("[3/4] projection/correlation 건너뜀")

    guidance_result = None
    if args.guidance:
        if selection is None or not selection.focused_incident_ids:
            print("      [guidance 건너뜀] focused incident가 없다")
        else:
            import os

            missing = [
                name
                for name in ("OPENAI_API_KEY", "SUPABASE_URL", "SUPABASE_KEY")
                if not os.getenv(name)
            ]
            if missing:
                print(f"      [guidance 건너뜀] 환경변수 없음: {missing}")
            else:
                from guidance import (
                    IncidentSecurityGuidance,
                    RagSecurityGuidanceProvider,
                    SecurityGuidanceResult,
                    build_security_guidance_question,
                )

                provider = RagSecurityGuidanceProvider()
                items, failed = [], []
                for incident_id in selection.focused_incident_ids:
                    incident = correlation.incident_by_id(incident_id)
                    question = build_security_guidance_question(incident)
                    try:
                        response = provider.generate(question)
                    except Exception as exc:
                        print(f"      [guidance 실패] {type(exc).__name__}: {exc}")
                        failed.append(incident_id)
                        continue
                    items.append(
                        IncidentSecurityGuidance(
                            incident_id=incident_id,
                            question=question,
                            response=response.response,
                            provider_name=response.provider_name,
                            model=response.model,
                        )
                    )
                    print(f"      [guidance 성공] {incident_id} / {len(response.response):,}자 "
                          f"/ [Page 포함 {'[Page' in response.response}")
                if items or failed:
                    guidance_result = SecurityGuidanceResult(
                        focused_incident_ids=selection.focused_incident_ids,
                        guidance=tuple(items),
                        failed_incident_ids=tuple(failed),
                    )

    report = build_incident_report(
        investigation_id=args.investigation_id,
        findings=findings,
        agent_results=agent_results,
        scenario_projection=projection,
        correlation_result=correlation,
        incident_selection=selection,
        security_guidance=guidance_result,
    )

    if args.narrative:
        from report import LlmNarrativeSummaryProvider

        try:
            report = attach_narrative_summary(report, LlmNarrativeSummaryProvider())
            print(f"      [narrative 성공] {len(report.narrative_summary.text):,}자 "
                  f"/ model={report.narrative_summary.model}")
        except Exception as exc:
            print(f"      [narrative 실패] {type(exc).__name__}: {exc}")

    out_path = Path(args.out) if args.out else default_report_path(report)
    saved = save_json(report, out_path)
    size_kb = saved.stat().st_size / 1024

    print(f"[4/4] 저장: {saved}  ({size_kb:,.1f} KB)")
    print(f"       report_id        : {report.report_id}")
    print(f"       generated_from   : {report.generated_from}")
    print(f"       scenario_id      : {report.scenario_id}")
    print(f"       incident_id      : {report.incident_id}")
    print(f"       findings         : {report.findings.total_count} "
          f"(JSON 포함 {report.findings.items.included_count}, "
          f"truncated={report.findings.items.truncated})")
    print(f"       severity_counts  : {report.findings.severity_counts}")
    print(f"       timeline         : {report.timeline.total_count} "
          f"(포함 {report.timeline.included_count})")
    print(f"       evidence         : {report.evidence.total_evidence_count} "
          f"(포함 {report.evidence.included_evidence_count})")
    print(f"       hypotheses       : {len(report.hypotheses)}")
    print(f"       guidance         : {'있음' if report.security_guidance else '없음'}")
    print(f"       narrative_summary: {'있음' if report.narrative_summary else '없음 (LLM 미호출)'}")
    state = report.agent_statistics.operational_state
    print(f"       operational_state: normal={state.normal_count} warning={state.warning_count} "
          f"failure={state.failure_count} unknown={state.unknown_count}")
    print(f"       truncated_sections      : {report.limitations.truncated_sections}")
    print(f"       non_finite_metric_fields: {report.limitations.non_finite_metric_fields.total_count}건")
    print(f"       excluded_from_window    : {report.limitations.excluded_from_window_finding_ids.total_count}건 "
          f"(JSON 포함 {report.limitations.excluded_from_window_finding_ids.included_count})")
    print(f"       limitations notes       : {len(report.limitations.notes)}개")
    for note in report.limitations.notes:
        print(f"         - {note[:110]}")

    if args.print_json:
        print("\n" + to_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
