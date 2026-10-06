"""데이터셋을 분석해 Finding을 pkl로 저장한다.

aligned pkl을 읽고 Orchestrator workflow를 돌려 deduplicate된 Finding을 저장한다.
GAIA 전체는 실측 약 30분이 걸리므로, 한 번 저장해 두면 이후 scenario/correlation 실험을
수 초 만에 반복할 수 있다.

사용 예:

    python scripts/build_findings.py \
        --events output/aligned/gaia.pkl \
        --out output/findings/gaia.pkl \
        --investigation-id gaia-findings

    python scripts/build_findings.py \
        --events output/aligned/russellmitchell.pkl \
        --out output/findings/russellmitchell.pkl
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from orchestration import run_investigation  # noqa: E402
from src.models.event_store import load_events  # noqa: E402
from src.models.finding_store import load_findings, save_findings  # noqa: E402


def build(*, events_path: Path, out_path: Path, investigation_id: str) -> int:
    started = time.time()
    print(f"[1/3] workflow 실행: {events_path}", flush=True)
    state = run_investigation(
        event_source=lambda: load_events(events_path),
        investigation_id=investigation_id,
    )
    findings = state["findings"]
    elapsed = time.time() - started
    print(f"      Finding {len(findings):,}건 ({elapsed:.0f}s)", flush=True)
    print(f"      routed_agents : {state['routed_agents']}")
    print(f"      errors        : {state['errors'] or '{}'}")

    print(f"[2/3] 저장: {out_path}", flush=True)
    saved = save_findings(findings, out_path)
    size_mb = out_path.stat().st_size / 1e6

    print("[3/3] 다시 읽어 검증", flush=True)
    reloaded = list(load_findings(out_path))

    assert len(reloaded) == saved, f"개수 불일치: {len(reloaded)} != {saved}"
    assert [f.finding_id for f in reloaded] == [f.finding_id for f in findings]
    assert [f.severity for f in reloaded] == [f.severity for f in findings]
    assert [f.start_time for f in reloaded] == [f.start_time for f in findings]
    assert [len(f.evidence) for f in reloaded] == [len(f.evidence) for f in findings]

    print(f"\n저장 완료: {out_path}")
    print(f"  Finding        : {saved:,}")
    print(f"  파일 크기      : {size_mb:,.2f} MB")
    print(f"  전체 소요      : {time.time() - started:.0f}s")
    print(f"  finding_type   : {dict(Counter(f.finding_type for f in reloaded))}")
    print(f"  category       : {dict(Counter(f.category for f in reloaded))}")
    print(f"  severity       : {dict(Counter(f.severity for f in reloaded))}")
    print(f"  dataset        : {dict(Counter(f.dataset for f in reloaded))}")
    print(f"  service (상위) : {dict(Counter(f.service for f in reloaded).most_common(10))}")
    print("  재적재 검증    : finding_id / severity / start_time / evidence 수 일치 확인")
    return saved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True, help="입력 event pkl 경로")
    parser.add_argument("--out", required=True, help="저장할 finding pkl 경로")
    parser.add_argument("--investigation-id", default="findings-build")
    args = parser.parse_args(argv)

    build(
        events_path=Path(args.events),
        out_path=Path(args.out),
        investigation_id=args.investigation_id,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
