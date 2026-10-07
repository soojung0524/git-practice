"""Finding을 파일로 저장하고 다시 읽어오는 기능.

event_store.py가 NormalizedEvent를 저장하는 것과 같은 역할을 Finding에 대해 한다.

왜 필요한가: GAIA 전체 Finding을 얻으려면 aligned pkl(7.6GB, 1,058만 건)을 읽고 detector
5종을 모두 돌려야 해서 실측 1,778초(29.6분)가 걸린다. 결과 Finding은 7,277건으로 수 MB에
불과하므로, 저장해 두면 이후 correlation/scenario 실험을 수 초 만에 반복할 수 있다.

Event와 달리 Finding은 수가 적어(만 단위) 배치 dump가 필요하지 않다. 다만 저장과 적재
모두 스트리밍으로 처리해 호출부가 list를 따로 만들지 않아도 되게 한다.

pickle은 파이썬 전용이고 신뢰할 수 없는 파일을 읽으면 안 된다. 직접 만든 파일만 읽는다.
"""

from __future__ import annotations

import pickle
from collections.abc import Iterable, Iterator
from pathlib import Path

from .finding import Finding

# 한 번에 묶어서 dump할 Finding 수. event_store와 같은 방식을 쓴다.
PICKLE_BATCH_SIZE = 1000


def save_findings(findings: Iterable[Finding], path: str | Path) -> int:
    """Finding을 pkl로 저장하고 저장한 개수를 돌려준다.

    입력을 list로 모으지 않고 흘려보내며 기록한다.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    saved = 0
    batch: list[Finding] = []
    with target.open("wb") as handle:
        for finding in findings:
            batch.append(finding)
            saved += 1
            if len(batch) >= PICKLE_BATCH_SIZE:
                pickle.dump(batch, handle)
                batch = []
        if batch:
            pickle.dump(batch, handle)
    return saved


def load_findings(path: str | Path) -> Iterator[Finding]:
    """저장한 pkl에서 Finding을 하나씩 읽어 돌려준다."""
    source = Path(path)
    with source.open("rb") as handle:
        while True:
            try:
                batch = pickle.load(handle)
            except EOFError:
                return
            yield from batch
