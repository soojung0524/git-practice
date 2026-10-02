from orchestration.graph import run_investigation
from src.models.event_store import load_events


EVENT_PATH = "output/events_undated.pkl"

state = run_investigation(
    event_source=lambda: load_events(
        "output/gaia_metric_events.pkl"
    ),
    investigation_id="gaia-demo-001",
    dataset="gaia",
)

# state = run_investigation(
#     event_source=lambda: load_events(EVENT_PATH),
#     investigation_id="real-finding-test",
#     dataset="russellmitchell",
# )


print("=== Routed Agents ===")
print(state["routed_agents"])


print("\n=== Agent Results ===")

for key in (
    "application_result",
    "server_result",
    "network_result",
    "authentication_result",
    "security_result",
):
    result = state[key]

    if result is None:
        print(f"{key}: not executed")
        continue

    print(
        f"{key}: "
        f"status={result.status}, "
        f"input={result.input_item_count}, "
        f"findings={len(result.findings)}"
    )


print("\n=== Final Findings ===")

for i, finding in enumerate(state["findings"], start=1):
    print(f"\n[{i}]")
    print("finding_id :", finding.finding_id)
    print("dataset    :", finding.dataset)
    print("type       :", finding.finding_type)
    print("category   :", finding.category)
    print("severity   :", finding.severity)
    print("start_time :", finding.start_time)
    print("end_time   :", finding.end_time)
    print("host       :", finding.host)
    print("service    :", finding.service)
    print("summary    :", finding.summary)
    print("detector   :", finding.detector)
    print("metrics    :", finding.metrics)

    print("evidence:")
    for evidence in finding.evidence[:5]:
        print(
            "  -",
            evidence.source_file,
            f"line={evidence.line_number}",
            f"time={evidence.timestamp}",
            f"event_id={evidence.event_id}",
        )


print("\n=== Security Findings ===")

security_result = state["security_result"]

if security_result is not None:
    for finding in security_result.findings:
        print(
            finding.finding_type,
            "|",
            finding.severity,
            "|",
            finding.summary,
        )


print("\n=== Errors ===")
print(state["errors"])