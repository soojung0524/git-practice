"""Finding을 scenario 시간축에 투영한다.

입력은 Finding과 ScenarioDefinition뿐이다. Event pkl을 다시 읽지 않는다(GAIA aligned
pkl은 7.6GB다). Ground Truth도 사용하지 않는다.

원본 Finding은 수정하지 않는다. clip 결과는 ScenarioFinding의 effective_* 필드에만
담기고, Finding.start_time/end_time은 그대로 남는다.
"""

from __future__ import annotations

from collections.abc import Iterable

from src.models import Finding

from .models import (
    ScenarioDatasetWindow,
    ScenarioDefinition,
    ScenarioFinding,
    ScenarioProjection,
)

ON_MISSING_ERROR = "error"
ON_MISSING_SKIP = "skip"
_ON_MISSING_CHOICES = (ON_MISSING_ERROR, ON_MISSING_SKIP)


class MissingDatasetWindowError(ValueError):
    """Finding.dataset에 해당하는 Window가 ScenarioDefinition에 없다.

    Window를 추측해서 만들지 않는다. 일부 dataset만 투영하려는 정당한 경우를 위해
    on_missing_window="skip"을 명시적으로 줄 수 있다.
    """


class NaiveDatetimeError(ValueError):
    """Finding의 시간에 timezone이 없다.

    Finding 모델은 tz-aware를 강제하지 않는다(모든 parser가 UTC를 붙이지만 모델 차원의
    보장은 없다). naive와 aware를 뺄 때 나는 모호한 TypeError 대신 원인이 분명한 오류를
    낸다.
    """


def _require_aware(finding: Finding) -> None:
    if finding.start_time.tzinfo is None or finding.end_time.tzinfo is None:
        raise NaiveDatetimeError(
            f"{finding.finding_id}: start_time/end_time에 timezone이 없다"
        )


def _project_one(
    finding: Finding, window: ScenarioDatasetWindow, scenario_id: str
) -> ScenarioFinding | None:
    """Window와 겹치지 않으면 None을 돌려준다(제외 대상)."""
    if not window.contains_interval(finding.start_time, finding.end_time):
        return None

    effective_start = max(finding.start_time, window.window_start)
    effective_end = min(finding.end_time, window.window_end)
    was_clipped = (
        effective_start != finding.start_time or effective_end != finding.end_time
    )

    return ScenarioFinding(
        scenario_id=scenario_id,
        finding=finding,
        relative_start_seconds=window.relative_seconds(finding.start_time),
        relative_end_seconds=window.relative_seconds(finding.end_time),
        effective_start_time=effective_start,
        effective_end_time=effective_end,
        relative_effective_start_seconds=window.relative_seconds(effective_start),
        relative_effective_end_seconds=window.relative_seconds(effective_end),
        was_clipped=was_clipped,
        window_start=window.window_start,
        window_end=window.window_end,
        window_length_seconds=window.window_length_seconds,
    )


def project_findings(
    findings: Iterable[Finding],
    scenario: ScenarioDefinition,
    *,
    on_missing_window: str = ON_MISSING_ERROR,
) -> ScenarioProjection:
    """Finding들을 scenario의 dataset Window 기준 상대시간으로 투영한다.

    on_missing_window
        "error"(기본) - Finding.dataset의 Window가 없으면 MissingDatasetWindowError
        "skip"         - 그 Finding을 건너뛰고 skipped_missing_window에 기록

    정렬은 relative_start_seconds -> relative_end_seconds -> finding_id 순이며, 입력
    순서와 무관하게 같은 결과가 나온다.
    """
    if on_missing_window not in _ON_MISSING_CHOICES:
        raise ValueError(
            f"on_missing_window는 {_ON_MISSING_CHOICES} 중 하나여야 한다: {on_missing_window!r}"
        )

    projected: list[ScenarioFinding] = []
    excluded: list[str] = []
    skipped: list[str] = []

    for finding in findings:
        window = scenario.window_for(finding.dataset)
        if window is None:
            if on_missing_window == ON_MISSING_ERROR:
                raise MissingDatasetWindowError(
                    f"scenario {scenario.scenario_id!r}에 dataset {finding.dataset!r}의 "
                    f"Window가 없다 (finding_id={finding.finding_id!r}). "
                    f"정의된 dataset: {list(scenario.datasets)}"
                )
            skipped.append(finding.finding_id)
            continue

        _require_aware(finding)
        scenario_finding = _project_one(finding, window, scenario.scenario_id)
        if scenario_finding is None:
            excluded.append(finding.finding_id)
            continue
        projected.append(scenario_finding)

    projected.sort(key=ScenarioFinding.sort_key)
    clipped_count = sum(1 for item in projected if item.was_clipped)

    notes: list[str] = []
    if excluded:
        notes.append(
            f"Window와 겹치지 않아 제외한 Finding {len(excluded)}건 "
            "(원본 Finding은 변경하지 않았다)"
        )
    if skipped:
        notes.append(
            f"scenario에 Window가 없어 건너뛴 Finding {len(skipped)}건 "
            "(on_missing_window='skip')"
        )
    if clipped_count:
        notes.append(
            f"Window 경계를 걸쳐 effective interval을 clip한 Finding {clipped_count}건 "
            "(원본 시간은 relative_start/end_seconds에 그대로 남아 있다)"
        )

    return ScenarioProjection(
        scenario_id=scenario.scenario_id,
        findings=tuple(projected),
        excluded_out_of_window=tuple(sorted(excluded)),
        skipped_missing_window=tuple(sorted(skipped)),
        clipped_count=clipped_count,
        notes=tuple(notes),
    )
