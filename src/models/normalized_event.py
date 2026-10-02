from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .raw_log_line import RawLogLine


@dataclass
class NormalizedEvent:
    """서로 다른 형식의 로그를 Agent가 공통으로 다룰 수 있도록 정규화한 이벤트.

    공통 필드는 모든 지원 로그 형식에 실제로 존재하는 정보만 담고,
    형식별로만 존재하는 정보는 extra에 보존한다.
    """

    event_id: str
    source_type: str
    host: str
    source_path: str
    line_number: int
    timestamp: datetime | None
    raw: str
    # 어느 데이터셋에서 온 이벤트인지. russellmitchell과 GAIA처럼 서로 독립된 환경에서
    # 수집된 데이터셋을 같은 파이프라인에 태울 때, timestamp만으로 이벤트를 엮어
    # 하나의 Incident로 오인하지 않도록 명시적으로 구분하기 위한 필드다.
    # 기존 러셀미첼 파서는 전혀 손대지 않아도 되도록 기본값을 "russellmitchell"로 둔다.
    dataset: str = "russellmitchell"
    process: str | None = None
    pid: int | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    event_type: str | None = None
    message: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def make_event_id(raw: RawLogLine) -> str:
    """이벤트를 유일하게 식별하는 문자열을 만든다.

    host와 source_type만 쓰면 로테이션 파일끼리 충돌한다. auth.log와 auth.log.1은
    host·source_type이 같은데 줄 번호가 각각 1부터 다시 시작하기 때문이다.
    파일 경로와 줄 번호 조합은 데이터셋 전체에서 유일하며, labels/ 의 정답 파일이
    같은 상대 경로 + 줄 번호로 매겨져 있어 그대로 조인 키로 쓸 수 있다.
    """
    return f"{raw.source_path}:{raw.line_number}"
