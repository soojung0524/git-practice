"""Incident Report.

결정론적 Report Builder가 모든 사실을 만들고, LLM은 그 보고서를 읽어 자연어 요약만
쓴다. LLM 없이도 보고서는 완성된다.

  Agent 통계 / Findings / Timeline / Correlation / Hypothesis / Impact / Evidence /
  Security Guidance / Errors·Limitations   -> JSON
  (선택) LLM narrative summary

의존 방향: report -> guidance, correlation, scenario, src.models
orchestration을 import하지 않는다.
"""

from .builder import (
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_LIMITATION_IDS,
    DEFAULT_MAX_EVIDENCE_PER_FINDING,
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_TIMELINE_ROWS,
    build_incident_report,
    make_report_id,
)
from .models import (
    DETERMINISTIC_SECTIONS,
    GUIDANCE_SOURCE_NOTE,
    NON_DETERMINISTIC_FIELDS,
    MODE_REAL,
    MODE_SCENARIO,
    OPERATIONAL_STATE_POLICY,
    SCHEMA_VERSION,
    AgentStatistic,
    AgentStatisticsSection,
    AmbiguousIncidentError,
    CorrelationEdgeRow,
    CorrelationSection,
    EvidenceGroup,
    EvidenceRow,
    EvidenceSection,
    FindingRow,
    FindingsSection,
    GuidanceRow,
    GuidanceSection,
    HypothesisRow,
    ImpactSection,
    IncidentReport,
    LimitationsSection,
    NarrativeSummary,
    OperationalStateCounts,
    TimelineRow,
    TruncatedList,
)
from .serialize import default_report_path, save_json, to_json, to_json_dict
from .summary import (
    PROVIDER_NAME_LLM,
    SYSTEM_PROMPT,
    LlmNarrativeSummaryProvider,
    NarrativeSummaryProvider,
    attach_narrative_summary,
    build_summary_prompt,
)

__all__ = [
    "SCHEMA_VERSION",
    "DETERMINISTIC_SECTIONS",
    "NON_DETERMINISTIC_FIELDS",
    "MODE_REAL",
    "MODE_SCENARIO",
    "OPERATIONAL_STATE_POLICY",
    "GUIDANCE_SOURCE_NOTE",
    "IncidentReport",
    "AgentStatistic",
    "AgentStatisticsSection",
    "OperationalStateCounts",
    "FindingRow",
    "FindingsSection",
    "TimelineRow",
    "CorrelationEdgeRow",
    "CorrelationSection",
    "HypothesisRow",
    "ImpactSection",
    "EvidenceRow",
    "EvidenceGroup",
    "EvidenceSection",
    "GuidanceRow",
    "GuidanceSection",
    "LimitationsSection",
    "NarrativeSummary",
    "TruncatedList",
    "AmbiguousIncidentError",
    "build_incident_report",
    "make_report_id",
    "DEFAULT_MAX_FINDINGS",
    "DEFAULT_MAX_EVIDENCE_PER_FINDING",
    "DEFAULT_MAX_TIMELINE_ROWS",
    "DEFAULT_MAX_EDGES",
    "DEFAULT_MAX_LIMITATION_IDS",
    "to_json_dict",
    "to_json",
    "save_json",
    "default_report_path",
    "NarrativeSummaryProvider",
    "LlmNarrativeSummaryProvider",
    "attach_narrative_summary",
    "build_summary_prompt",
    "PROVIDER_NAME_LLM",
    "SYSTEM_PROMPT",
]
