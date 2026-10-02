"""GAIA(MicroSS) 데이터셋의 metric/trace/business 디렉터리를 탐색해
Parser가 처리할 수 있는 RawLogLine을 생성하는 Loader.

기존 russellmitchell용 log_loader.py는 그대로 두고, GAIA 전용으로 별도 추가했다.
russellmitchell의 호스트별 로그 디렉터리 구조(gather/<host>/logs/...)와 달리,
GAIA MicroSS는 gaia_root 바로 아래에 metric/, trace/, business/ 가 평평하게
존재한다(실제 데이터셋을 직접 확인해 결정했다 — 호스트별 하위 폴더가 없다).

주의: GitHub 원본 배포본에서 metric/trace/business 디렉터리는 분할 zip
(business_split.z01 ... + business_split.zip 등)으로 되어 있다. 이 Loader는
이미 압축이 풀린 CSV 상태를 전제로 한다. 압축 해제는 Loader의 책임이 아니다
(Bandizip, 7-Zip 등 분할 zip을 지원하는 도구로 사전에 압축을 풀어야 한다).

run/ 디렉터리(anomaly injection 기록 / 시스템 로그와 뒤섞여 있는 ground truth)는
의도적으로 다루지 않는다. 일반 탐지 파이프라인에 섞이면 Agent가 정답을 미리 보고
판단하는 꼴이 되기 때문이다. 향후 평가(Evaluation) 단계에서만 별도로 읽어야 한다.

CSV 형식별로 실제 파일을 열어 확인한 유의점:
- metric/*.csv 는 "timestamp,value" 2컬럼의 단순 텍스트라 한 줄 = 한 레코드다.
- trace/*.csv, business/*.csv 는 message 필드가 큰따옴표로 감싸인 채 그 안에
  줄바꿈이 그대로 들어있는 행이 있어(로그 메시지 끝의 개행이 CSV 필드 값에
  포함됨), 텍스트 줄 단위로 읽으면 레코드가 중간에 끊긴다. 그래서 csv.DictReader로
  논리적 행 단위로 읽는다.
- business/*.csv 의 헤더는 파일마다 다르다. 2021-07 파일은
  "datetime,service,message"(3컬럼)이고, 2021-08 파일은 "id,datetime,service,message"
  또는 ",datetime,service,message"(4컬럼, 첫 컬럼명이 빈 문자열인 인덱스 컬럼)다.
  DictReader로 읽으면 컬럼 순서/개수 차이와 무관하게 컬럼 이름으로 접근할 수 있다.

이런 이유로 trace/business는 RawLogLine.raw에 원본 텍스트 줄이 아니라, DictReader가
읽은 한 행을 JSON 문자열로 그대로 직렬화해 담는다(정보 손실 없이 모든 컬럼 값을
보존한다). line_number도 텍스트 줄 번호가 아니라 헤더를 제외한 데이터 행 번호(1부터
시작)다 — russellmitchell 로그처럼 "1줄 = 1레코드"가 성립하지 않기 때문에 부득이한
차이이며, 각 GAIA 파서 docstring에도 같은 설명을 남겼다.

host(=service) 결정 방법도 형식마다 다르다.
- trace/business는 행 자체에 service/service_name 컬럼이 있어 그 값을 그대로 쓴다.
- metric은 행에 서비스 정보가 없고 파일명에만 있다. 파일명에서 서비스명을 뽑는
  로직은 gaia_metric 파서가 이미 갖고 있어(parse_filename), 여기서는 그 함수를
  재사용해 host만 채운다 — 같은 정규식을 두 곳에 중복 구현하지 않기 위함이다.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterator
from pathlib import Path

from src.models import RawLogLine
from src.parser import GAIA_FILE_TYPES
from src.parser import gaia_metric


def find_gaia_files(gaia_root: str | Path) -> Iterator[tuple[str, Path]]:
    """gaia_root 바로 아래 metric/, trace/, business/ 에서 지원 대상 CSV를 찾는다.

    (source_type, file_path) 를 생성한다. run/ 은 의도적으로 대상에서 제외한다
    (모듈 docstring 참고).
    """
    root = Path(gaia_root)
    if not root.is_dir():
        raise FileNotFoundError(
            f"'{root}' 를 찾을 수 없습니다. gaia_root가 GAIA MicroSS 데이터셋을 "
            "압축 해제한 위치(그 안에 metric/, trace/, business/ 가 있는 위치)를 "
            "가리키는지 확인하세요. business/trace/metric 은 분할 zip으로 배포되므로 "
            "먼저 압축을 풀어야 한다."
        )

    for pattern, source_type, _ in GAIA_FILE_TYPES:
        for file_path in sorted(root.glob(pattern)):
            if file_path.is_file():
                yield source_type, file_path


def _iter_metric_lines(file_path: Path) -> Iterator[tuple[int, str]]:
    with file_path.open(encoding="utf-8", errors="replace") as f:
        next(f, None)  # header ("timestamp,value")
        for line_number, line in enumerate(f, start=1):
            text = line.rstrip("\n").rstrip("\r")
            if text:
                yield line_number, text


def _iter_csv_rows_as_json(file_path: Path) -> Iterator[tuple[int, str, dict]]:
    with file_path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for line_number, row in enumerate(reader, start=1):
            yield line_number, json.dumps(row, ensure_ascii=False), row


def iter_raw_rows(gaia_root: str | Path) -> Iterator[RawLogLine]:
    """metric/trace/business CSV를 순회하며 RawLogLine을 생성한다."""
    root = Path(gaia_root)
    for source_type, file_path in find_gaia_files(root):
        source_path = file_path.relative_to(root).as_posix()

        if source_type == gaia_metric.SOURCE_TYPE:
            filename_info = gaia_metric.parse_filename(file_path.stem)
            host = filename_info["service"] if filename_info else file_path.stem
            for line_number, raw_text in _iter_metric_lines(file_path):
                yield RawLogLine(
                    host=host,
                    source_type=source_type,
                    source_path=source_path,
                    line_number=line_number,
                    raw=raw_text,
                )
        else:
            for line_number, raw_json, row in _iter_csv_rows_as_json(file_path):
                host = row.get("service_name") or row.get("service") or file_path.stem
                yield RawLogLine(
                    host=host,
                    source_type=source_type,
                    source_path=source_path,
                    line_number=line_number,
                    raw=raw_json,
                )
