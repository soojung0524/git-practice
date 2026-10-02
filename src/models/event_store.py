"""NormalizedEvent를 파일로 저장하고 다시 읽어오는 기능.

전체 데이터셋을 파싱하는 데 20초 정도가 걸리므로, 이후 단계에서 매번 다시 파싱하지 않도록
정규화 결과를 저장해 두고 재사용한다.

두 가지 형식을 지원하며 확장자로 구분한다.
    .pkl / .pickle : NormalizedEvent 객체를 그대로 보존한다. 빠르고 datetime도 변환 없이
                     복원되지만, 파이썬 전용이고 신뢰할 수 없는 파일을 읽으면 안 된다.
    그 외 (.jsonl) : 사람이 읽을 수 있고 다른 도구와도 호환된다. timestamp는 ISO 8601
                     문자열로 저장했다가 복원 시 datetime으로 되돌린다.

두 형식 모두 전체를 한 번에 리스트로 담지 않고 흘려보내며 기록한다. 68만 건을 리스트로
만들면 메모리를 크게 쓰기 때문에 저장과 적재 모두 스트리밍으로 처리한다.

pickle은 이벤트를 한 건씩 dump하면 객체마다 클래스 참조가 반복 기록되어 파일이 커지고
느려진다. 그래서 일정 개수씩 묶어서 dump한다.
전체 데이터셋(680,166건) 실측 — 건별 518MB/13.7초 → 배치 297MB/5.3초.
"""

from __future__ import annotations

import json
import pickle
from collections.abc import Iterable, Iterator
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import IO

from .normalized_event import NormalizedEvent

PICKLE_SUFFIXES = (".pkl", ".pickle")

# 한 번에 묶어서 dump할 이벤트 수. 1,000과 10,000을 비교했을 때 1,000이 더 빨랐다.
PICKLE_BATCH_SIZE = 1000

# timestamp가 없는 이벤트(apache_error_unstructured 등)를 모을 파일 이름의 날짜 자리.
UNDATED_KEY = "undated"


def _is_pickle_path(path: str | Path) -> bool:
    return Path(path).suffix.lower() in PICKLE_SUFFIXES


def _to_json_dict(event: NormalizedEvent) -> dict:
    data = asdict(event)
    data["timestamp"] = event.timestamp.isoformat() if event.timestamp else None
    return data


def _from_json_dict(data: dict) -> NormalizedEvent:
    timestamp = data["timestamp"]
    data["timestamp"] = datetime.fromisoformat(timestamp) if timestamp else None
    return NormalizedEvent(**data)


def _stream_to_pickle(
    events: Iterable[NormalizedEvent], target: Path
) -> Iterator[NormalizedEvent]:
    with target.open("wb") as f:
        batch: list[NormalizedEvent] = []
        try:
            for event in events:
                batch.append(event)
                if len(batch) >= PICKLE_BATCH_SIZE:
                    pickle.dump(batch, f, protocol=pickle.HIGHEST_PROTOCOL)
                    batch = []
                yield event
        finally:
            # 소비자가 중간에 순회를 멈춰도 이미 넘긴 이벤트는 기록되어야 한다.
            if batch:
                pickle.dump(batch, f, protocol=pickle.HIGHEST_PROTOCOL)


def _stream_to_jsonl(
    events: Iterable[NormalizedEvent], target: Path
) -> Iterator[NormalizedEvent]:
    with target.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(_to_json_dict(event), ensure_ascii=False) + "\n")
            yield event


def stream_to_file(events: Iterable[NormalizedEvent], path: str | Path) -> Iterator[NormalizedEvent]:
    """이벤트를 파일에 기록하면서 그대로 흘려보낸다.

    저장과 집계를 한 번의 순회로 함께 처리하기 위한 통과형 제너레이터다.
    """
    target = Path(path)
    if _is_pickle_path(target):
        return _stream_to_pickle(events, target)
    return _stream_to_jsonl(events, target)


def save_events(events: Iterable[NormalizedEvent], path: str | Path) -> int:
    """이벤트를 파일로 저장하고 저장한 건수를 돌려준다."""
    return sum(1 for _ in stream_to_file(events, path))


def date_key(event: NormalizedEvent) -> str:
    """이벤트가 속할 날짜 키(UTC 기준 YYYY-MM-DD)를 돌려준다."""
    if event.timestamp is None:
        return UNDATED_KEY
    return event.timestamp.astimezone(timezone.utc).date().isoformat()


def dated_path(base_path: str | Path, key: str) -> Path:
    """`output/events.pkl` + `2022-01-21` -> `output/events_2022-01-21.pkl`"""
    base = Path(base_path)
    return base.with_name(f"{base.stem}_{key}{base.suffix}")


def stream_to_dated_files(
    events: Iterable[NormalizedEvent], base_path: str | Path
) -> Iterator[NormalizedEvent]:
    """이벤트를 UTC 날짜별 파일로 나눠 기록하면서 그대로 흘려보낸다.

    이벤트는 호스트별 파일 순서로 들어오기 때문에 날짜순으로 정렬되어 있지 않다.
    따라서 날짜별 파일 핸들을 동시에 열어 두고 각 이벤트를 해당 파일로 보낸다.
    timestamp가 없는 이벤트는 버리지 않고 `_undated` 파일에 모은다.
    """
    base = Path(base_path)
    if base.parent != Path(""):
        base.parent.mkdir(parents=True, exist_ok=True)
    is_pickle = _is_pickle_path(base)

    handles: dict[str, IO] = {}
    batches: dict[str, list[NormalizedEvent]] = {}
    try:
        for event in events:
            key = date_key(event)
            handle = handles.get(key)
            if handle is None:
                path = dated_path(base, key)
                handle = path.open("wb") if is_pickle else path.open("w", encoding="utf-8")
                handles[key] = handle
                batches[key] = []

            if is_pickle:
                batch = batches[key]
                batch.append(event)
                if len(batch) >= PICKLE_BATCH_SIZE:
                    pickle.dump(batch, handle, protocol=pickle.HIGHEST_PROTOCOL)
                    batches[key] = []
            else:
                handle.write(json.dumps(_to_json_dict(event), ensure_ascii=False) + "\n")
            yield event
    finally:
        for key, handle in handles.items():
            if batches.get(key):
                pickle.dump(batches[key], handle, protocol=pickle.HIGHEST_PROTOCOL)
            handle.close()


def save_events_by_date(events: Iterable[NormalizedEvent], base_path: str | Path) -> int:
    """이벤트를 날짜별 파일로 나눠 저장하고 저장한 총 건수를 돌려준다."""
    return sum(1 for _ in stream_to_dated_files(events, base_path))


def load_events(path: str | Path) -> Iterator[NormalizedEvent]:
    """저장해 둔 파일에서 NormalizedEvent를 하나씩 읽어온다."""
    source = Path(path)
    if _is_pickle_path(source):
        with source.open("rb") as f:
            while True:
                try:
                    batch = pickle.load(f)
                except EOFError:
                    return
                yield from batch
    else:
        with source.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield _from_json_dict(json.loads(line))
