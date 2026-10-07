"""IncidentReport를 JSON으로 직렬화한다.

규칙:
  - UTF-8, ensure_ascii=False  (한국어가 \\uXXXX로 깨지지 않게)
  - sort_keys=True             (같은 입력 -> 바이트 동일 JSON)
  - allow_nan=False            (NaN/Infinity는 JSON 표준이 아니다 -> 오류로 드러낸다)
  - datetime -> ISO 8601 문자열 (tzinfo 유지)
  - tuple -> list, frozenset -> 정렬된 list
  - float는 반올림하지 않는다 (metrics 값이 왜곡되면 안 된다)
  - None인 필드도 키를 유지한다 (키 유무로 "없음"과 "미실행"이 갈리지 않게)

비밀값을 담지 않는다 - 어떤 report 모델에도 API key/URL 필드가 없다.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import date, datetime
from pathlib import Path
from typing import Any

from .models import IncidentReport


def _convert(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _convert(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _convert(item) for key, item in value.items()}
    if isinstance(value, frozenset | set):
        return [_convert(item) for item in sorted(value, key=str)]
    if isinstance(value, tuple | list):
        return [_convert(item) for item in value]
    return value


def to_json_dict(report: IncidentReport) -> dict[str, Any]:
    """보고서를 JSON 직렬화 가능한 dict로 바꾼다."""
    converted = _convert(report)
    if not isinstance(converted, dict):  # pragma: no cover - 방어적
        raise TypeError("IncidentReport 변환 결과가 dict가 아니다")
    return converted


def to_json(report: IncidentReport, *, indent: int | None = 2) -> str:
    return json.dumps(
        to_json_dict(report),
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
        indent=indent,
    )


def save_json(report: IncidentReport, path: str | Path, *, indent: int | None = 2) -> Path:
    """보고서를 UTF-8 JSON 파일로 저장하고 경로를 돌려준다."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(to_json(report, indent=indent), encoding="utf-8")
    return target


def default_report_path(report: IncidentReport, *, base_dir: str | Path = "output/reports") -> Path:
    """output/reports/<report_id>.json.

    report_id에 ':'가 들어 있어 Windows 파일명으로 쓸 수 없으므로 '_'로 바꾼다.
    """
    safe = report.report_id.replace(":", "_")
    return Path(base_dir) / f"{safe}.json"
