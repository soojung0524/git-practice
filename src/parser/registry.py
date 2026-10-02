"""로그/데이터 파일 경로 패턴을 어떤 파서가 담당하는지 매핑한다.

이 테이블이 지원 대상 형식의 단일 기준(source of truth)이며, 각 데이터셋 전용
loader가 어떤 파일을 읽을지 결정할 때 이 테이블을 사용한다.

LOG_FILE_TYPES는 russellmitchell 데이터셋(gather/<host>/logs/ 아래 구조)용이고,
GAIA_FILE_TYPES는 GAIA MicroSS 데이터셋(gaia_root 바로 아래 metric/trace/business
평면 구조)용이다. 두 데이터셋은 디렉터리 구조가 달라 glob 패턴 테이블을 분리했지만,
get_parser()/parse_lines()는 source_type만으로 동작하는 공통 함수라 양쪽 데이터셋
모두 그대로 재사용한다.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator

from src.models import NormalizedEvent, RawLogLine

from . import (
    apache_access,
    apache_error,
    auditd,
    dnsmasq,
    gaia_log,
    gaia_metric,
    gaia_trace,
    openvpn,
    syslog_auth,
)

ParseFunc = Callable[[RawLogLine], "NormalizedEvent | None"]

# (호스트 logs/ 디렉터리 기준 상대 glob 패턴, source_type, parse 함수)
LOG_FILE_TYPES: tuple[tuple[str, str, ParseFunc], ...] = (
    ("auth.log*", syslog_auth.SOURCE_TYPE, syslog_auth.parse),
    ("dnsmasq.log", dnsmasq.SOURCE_TYPE, dnsmasq.parse),
    ("audit/audit.log", auditd.SOURCE_TYPE, auditd.parse),
    ("apache2/*access.log*", apache_access.SOURCE_TYPE, apache_access.parse),
    ("apache2/*error.log*", apache_error.SOURCE_TYPE, apache_error.parse),
    ("openvpn.log", openvpn.SOURCE_TYPE, openvpn.parse),
)

# (gaia_root 기준 상대 glob 패턴, source_type, parse 함수)
# run/ (anomaly injection / ground truth)은 의도적으로 포함하지 않는다 — 작업 7 참고.
GAIA_FILE_TYPES: tuple[tuple[str, str, ParseFunc], ...] = (
    ("metric/*.csv", gaia_metric.SOURCE_TYPE, gaia_metric.parse),
    ("trace/*.csv", gaia_trace.SOURCE_TYPE, gaia_trace.parse),
    ("business/*.csv", gaia_log.SOURCE_TYPE, gaia_log.parse),
)

_PARSERS_BY_SOURCE_TYPE: dict[str, ParseFunc] = {
    source_type: parse_func
    for _, source_type, parse_func in (*LOG_FILE_TYPES, *GAIA_FILE_TYPES)
}


def get_parser(source_type: str) -> ParseFunc | None:
    return _PARSERS_BY_SOURCE_TYPE.get(source_type)


def parse_lines(raw_lines: Iterable[RawLogLine]) -> Iterator[NormalizedEvent]:
    """RawLogLine을 순서대로 받아, source_type에 맞는 parser로 NormalizedEvent를 생성한다.

    해당 형식을 담당하는 parser가 없거나 파싱에 실패한 라인은 건너뛴다.
    """
    for raw in raw_lines:
        parser_fn = get_parser(raw.source_type)
        if parser_fn is None:
            continue
        event = parser_fn(raw)
        if event is not None:
            yield event
