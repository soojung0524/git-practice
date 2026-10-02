"""Security Analysis Skill wrapper - 단순 selector.

detector를 실행하지 않는다. 이미 만들어진 Finding 중 category == "security"인 것만
그대로 골라 반환한다. severity/category/metrics/evidence를 수정하지 않고, 새로운 보안
판단도 추가하지 않는다.
"""

from __future__ import annotations

from collections.abc import Iterable

from src.models import Finding

SKILL_NAME = "security_analysis"

# detector를 직접 실행하지 않는다. 입력 Finding은 다른 Skill(현재는 application_analysis의
# find_scan_pattern)이 이미 만들어 둔 것이다.
DETECTORS: tuple[str, ...] = ()

# 이 Skill은 NormalizedEvent를 입력으로 받지 않는다.
SOURCE_TYPES: tuple[str, ...] = ()

SECURITY_CATEGORY = "security"


def select_security_findings(findings: Iterable[Finding]) -> list[Finding]:
    """category == "security"인 Finding만 입력 순서 그대로 골라 반환한다."""
    return [finding for finding in findings if finding.category == SECURITY_CATEGORY]


def run_security_analysis(findings: Iterable[Finding]) -> list[Finding]:
    """이미 생성된 Finding 중 보안 관련 Finding만 선별한다.

    현재 category == "security"로 만들어지는 Finding은 find_scan_pattern의
    repeated_source_ip_scan 하나뿐이다(application_analysis Skill이 생성한다).

    이 함수는 selector다 - 재분류, 재판정, 병합, 정렬 변경을 하지 않는다.
    """
    return select_security_findings(findings)
