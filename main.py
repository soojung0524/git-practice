"""로그 데이터 분석 기반 구축 - 1단계 데모 진입점.

dataset_root(러셀미첼 데이터셋 루트, 즉 dataset.yaml/gather/labels가 있는 디렉터리)의
지원 대상 로그를 읽어 NormalizedEvent로 변환하고 구조적 요약을 출력한다.
공격 탐지나 보안 판단은 수행하지 않는다.
"""

from __future__ import annotations

import argparse
import os
from itertools import islice
from pathlib import Path

from src.loader import iter_raw_lines
from src.models import dated_path, stream_to_dated_files, stream_to_file
from src.parser import parse_lines
from src.skills import summarize_events

PROJECT_ROOT = Path(__file__).resolve().parent


def resolve_dataset_root(cli_value: str | None) -> Path:
    """데이터셋 루트 경로를 결정한다 (코드에 절대경로를 하드코딩하지 않는다).

    우선순위: --dataset-root 인자 > LOG_AGENT_DATASET_ROOT 환경변수 > <프로젝트 루트>/data
    """
    if cli_value:
        return Path(cli_value)
    env_value = os.environ.get("LOG_AGENT_DATASET_ROOT")
    if env_value:
        return Path(env_value)
    return PROJECT_ROOT / "data"


def main() -> None:
    arg_parser = argparse.ArgumentParser(description="russellmitchell 로그를 정규화하여 요약한다.")
    arg_parser.add_argument(
        "--dataset-root",
        help=(
            "러셀미첼 데이터셋 루트 경로 (미지정 시 LOG_AGENT_DATASET_ROOT 환경변수, "
            "그다음 ./data 순으로 사용)"
        ),
    )
    arg_parser.add_argument(
        "--output",
        help=(
            "정규화된 이벤트를 저장할 파일 경로. 확장자가 .pkl/.pickle이면 pickle로, "
            "그 외에는 JSON Lines로 저장한다"
        ),
    )
    arg_parser.add_argument(
        "--split-by-date",
        action="store_true",
        help=(
            "--output을 하나의 파일 대신 UTC 날짜별 파일로 나눠 저장한다 "
            "(events.pkl -> events_2022-01-21.pkl ...). timestamp가 없는 이벤트는 "
            "events_undated.pkl로 모은다"
        ),
    )
    arg_parser.add_argument(
        "--max-events", type=int, default=None, help="처리할 최대 이벤트 수 (기본값: 제한 없음)"
    )
    args = arg_parser.parse_args()

    if args.split_by_date and not args.output:
        arg_parser.error("--split-by-date 는 --output 과 함께 사용해야 합니다.")

    dataset_root = resolve_dataset_root(args.dataset_root)
    events = parse_lines(iter_raw_lines(dataset_root))
    if args.max_events is not None:
        events = islice(events, args.max_events)
    if args.output:
        if args.split_by_date:
            events = stream_to_dated_files(events, args.output)
        else:
            events = stream_to_file(events, args.output)

    summary = summarize_events(events)

    print(f"데이터셋 경로: {dataset_root}")
    if args.output and not args.split_by_date:
        print(f"저장 경로: {args.output}")
    print(f"총 이벤트 수: {summary.total_events}")
    print(f"형식별: {dict(summary.by_source_type)}")
    print(f"호스트별: {dict(summary.by_host)}")
    print(f"이벤트 종류별 (상위 10개): {summary.by_event_type.most_common(10)}")
    print(f"사용자별 (상위 10개): {summary.by_user.most_common(10)}")
    print(f"시간 범위: {summary.earliest_timestamp} ~ {summary.latest_timestamp}")
    print("날짜별(UTC):")
    for key in sorted(summary.by_date):
        count = summary.by_date[key]
        if args.output and args.split_by_date:
            path = dated_path(args.output, key)
            size_mb = path.stat().st_size / (1024 * 1024)
            print(f"  {key:12} {count:>9,}  -> {path} ({size_mb:,.1f} MB)")
        else:
            print(f"  {key:12} {count:>9,}")


if __name__ == "__main__":
    main()
