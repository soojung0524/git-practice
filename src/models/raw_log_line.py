from dataclasses import dataclass


@dataclass(frozen=True)
class RawLogLine:
    """LogLoader가 원본 로그 파일에서 한 줄을 읽어 만드는 파싱 이전 단계 레코드."""

    host: str
    source_type: str
    source_path: str
    line_number: int
    raw: str
