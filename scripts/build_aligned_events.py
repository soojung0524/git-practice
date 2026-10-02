"""데이터셋을 파싱해 상대시간을 붙인 뒤 pkl로 저장한다.

원본 timestamp를 유지하고 T+0 기준 상대초를 extra에 함께 보존한다.
Ground Truth(labels/, run/)는 읽지 않는다.

사용 예:

    python scripts/build_aligned_events.py russellmitchell \
        --root "../Data/russellmitchell" \
        --window-start 2022-01-21T00:00:00Z \
        --window-end   2022-01-25T00:00:00Z \
        --scenario-id scenario-001 \
        --out output/aligned/russellmitchell.pkl

    python scripts/build_aligned_events.py gaia \
        --root "../Data/GAIA-DataSet-main/MicroSS" \
        --window-start 2021-07-01T00:00:00Z \
        --window-end   2021-09-01T00:00:00Z \
        --scenario-id scenario-001 \
        --out output/aligned/gaia.pkl

전체를 메모리에 모으지 않고 흘려보내며 저장한다(GAIA는 1천만 건 이상이다).
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scenario import AnalysisWindow, align_events  # noqa: E402
from src.loader import iter_raw_lines, iter_raw_rows  # noqa: E402
from src.models.event_store import save_events  # noqa: E402
from src.parser import parse_lines  # noqa: E402

DATASETS = ("russellmitchell", "gaia")


def _parse_moment(text: str) -> datetime:
    """ISO 8601 문자열을 datetime으로. 'Z'도 허용한다."""
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _raw_lines(dataset: str, root: str):
    if dataset == "russellmitchell":
        return iter_raw_lines(root)
    return iter_raw_rows(root)


def build(
    *,
    dataset: str,
    root: str,
    out_path: Path,
    window: AnalysisWindow,
    progress_every: int = 500_000,
) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    started = time.time()
    counters = {"n": 0, "no_timestamp": 0, "before_window": 0}

    def tracked(events):
        for event in events:
            counters["n"] += 1
            if event.timestamp is None:
                counters["no_timestamp"] += 1
            elif event.timestamp < window.window_start:
                counters["before_window"] += 1
            if counters["n"] % progress_every == 0:
                elapsed = time.time() - started
                print(f"  ... {counters['n']:,} events ({elapsed:.0f}s)", flush=True)
            yield event

    parsed = parse_lines(_raw_lines(dataset, root))
    aligned = align_events(tracked(parsed), window)
    saved = save_events(aligned, out_path)

    elapsed = time.time() - started
    size_mb = out_path.stat().st_size / 1e6
    print(f"\n[{dataset}] 저장 완료: {out_path}")
    print(f"  events          : {saved:,}")
    print(f"  소요            : {elapsed:.1f}s")
    print(f"  파일 크기       : {size_mb:,.1f} MB")
    print(f"  window_start    : {window.window_start.isoformat()} (= T+0)")
    print(f"  window_end      : {window.window_end.isoformat() if window.window_end else None}")
    print(f"  window 길이     : {window.duration_seconds}")
    print(f"  mode            : {window.mode}")
    print(f"  scenario_id     : {window.scenario_id}")
    print(f"  timestamp 없음  : {counters['no_timestamp']:,} (상대초는 None으로 보존)")
    print(f"  T+0 이전 이벤트 : {counters['before_window']:,} (상대초가 음수로 보존)")
    return saved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", choices=DATASETS)
    parser.add_argument("--root", required=True, help="데이터셋 루트 경로")
    parser.add_argument("--out", required=True, help="저장할 pkl 경로")
    parser.add_argument(
        "--window-start", required=True, help="T+0. ISO 8601 (예: 2022-01-21T00:00:00Z)"
    )
    parser.add_argument(
        "--window-end",
        default=None,
        help="Window 끝. scenario mode의 long-span 분모로 쓰이므로 지정 권장",
    )
    parser.add_argument(
        "--scenario-id",
        default=None,
        help="여러 dataset을 묶을 때 명시한다. 생략하면 real mode(dataset boundary 유지)",
    )
    args = parser.parse_args(argv)

    window = AnalysisWindow(
        window_start=_parse_moment(args.window_start),
        window_end=_parse_moment(args.window_end) if args.window_end else None,
        scenario_id=args.scenario_id,
    )
    build(
        dataset=args.dataset,
        root=args.root,
        out_path=Path(args.out),
        window=window,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
