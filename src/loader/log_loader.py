"""russellmitchell 데이터셋의 gather/<host>/logs 아래에서 지원 대상 로그 파일을 찾아
원본 라인을 순회하는 LogLoader.

어떤 파일이 지원 대상인지는 src.parser.registry.LOG_FILE_TYPES 를 기준으로 판단한다.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from src.models import RawLogLine
from src.parser import LOG_FILE_TYPES


def find_log_files(dataset_root: str | Path) -> Iterator[tuple[str, str, Path]]:
    """dataset_root/gather/<host>/logs 아래에서 지원 대상 로그 파일을 찾는다.

    (host, source_type, file_path) 를 생성한다.
    """
    gather_dir = Path(dataset_root) / "gather"
    if not gather_dir.is_dir():
        raise FileNotFoundError(
            f"'{gather_dir}' 를 찾을 수 없습니다. dataset_root가 russellmitchell 데이터셋의 "
            "루트(그 안에 gather/, labels/ 등이 있는 위치)를 가리키는지 확인하세요."
        )

    for host_dir in sorted(p for p in gather_dir.iterdir() if p.is_dir()):
        logs_dir = host_dir / "logs"
        if not logs_dir.is_dir():
            continue
        host = host_dir.name
        for pattern, source_type, _ in LOG_FILE_TYPES:
            for file_path in sorted(logs_dir.glob(pattern)):
                if file_path.is_file():
                    yield host, source_type, file_path


def iter_raw_lines(dataset_root: str | Path) -> Iterator[RawLogLine]:
    """지원 대상 로그 파일들을 순회하며 RawLogLine을 생성한다.

    빈 줄은 건너뛴다. 파일 인코딩은 UTF-8로 가정하며, 디코딩 불가능한 바이트는 대체 문자로 치환한다.
    """
    root = Path(dataset_root)
    for host, source_type, file_path in find_log_files(root):
        source_path = file_path.relative_to(root).as_posix()
        with file_path.open(encoding="utf-8", errors="replace") as f:
            for line_number, line in enumerate(f, start=1):
                text = line.rstrip("\n").rstrip("\r")
                if not text:
                    continue
                yield RawLogLine(
                    host=host,
                    source_type=source_type,
                    source_path=source_path,
                    line_number=line_number,
                    raw=text,
                )
