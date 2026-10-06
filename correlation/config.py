"""Evidence Correlation 상수.

코드 여기저기에 숨겨 넣지 않고 한 곳에 모은다.
"""

from __future__ import annotations

# 두 Finding이 "시간적으로 근접"하다고 볼 최대 간격(초).
# 근거: detector들이 스스로 "같은 episode"로 합치는 최대 간격이 300초다
# (gaia_metric_anomaly._MAX_EPISODE_GAP_SECONDS = 300). 서로 다른 Finding 사이에도 같은
# 기준을 쓰는 것이 일관된다. scenario mode에서는 relative seconds 기준 300초를 그대로
# 쓴다(단위가 초로 같다).
NEAR_IN_TIME_SECONDS = 300.0

# ScenarioFinding.span_ratio가 이 값 이상이면 long-span으로 본다.
# span_ratio의 분모는 scenario Window 길이다(ScenarioFinding.span_ratio 참고).
LONG_SPAN_RATIO = 0.5

# --- relation 종류 ---
RELATION_SAME_HOST = "same_host"
RELATION_SAME_SERVICE = "same_service"
RELATION_SHARED_ENTITY = "shared_entity"
RELATION_SHARED_EVIDENCE = "shared_evidence"
RELATION_TEMPORAL_OVERLAP = "temporal_overlap"
RELATION_TEMPORAL_NEAR = "temporal_near"
RELATION_TEMPORAL_WEAK_LONG_SPAN = "temporal_weak_long_span"

# --- temporal relation ---
TEMPORAL_OVERLAPS = "overlaps"
TEMPORAL_PRECEDES = "precedes"

# grouping 근거로 쓸 수 있는 identity relation.
# same_service는 의도적으로 제외한다 - russellmitchell의 service="apache2"는 instance
# identifier가 아니라 상수 라벨이라(Finding 10건 전부 동일), 이걸 근거로 쓰면 무관한
# Finding이 하나의 incident로 합쳐진다. relation으로는 기록한다.
GROUPING_IDENTITY_RELATIONS = (
    RELATION_SAME_HOST,
    RELATION_SHARED_ENTITY,
    RELATION_SHARED_EVIDENCE,
)

# --- graph ---
NODE_FINDING = "finding"
NODE_HOST = "host"
NODE_SERVICE = "service"
NODE_IP = "ip"
NODE_USER = "user"

EDGE_OBSERVED_ON = "observed_on"
EDGE_AFFECTS = "affects"
EDGE_INVOLVES = "involves"
EDGE_PRECEDED = "preceded"
EDGE_CORRELATED_WITH = "correlated_with"

# entities 키 -> graph 노드 타입. 여기 없는 키는 노드를 만들지 않는다
# (관측되지 않은 관계를 추측하지 않는다). 현재 detector가 실제로 내보내는 키는
# host / ip / service 3종이며, user는 아직 어떤 detector도 내보내지 않는다.
ENTITY_KEY_NODE_TYPES = {
    "host": NODE_HOST,
    "service": NODE_SERVICE,
    "ip": NODE_IP,
    "user": NODE_USER,
}
