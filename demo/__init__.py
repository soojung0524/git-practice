"""시연용 demo pack 설정 패키지.

분석 로직을 담지 않는다. production pipeline(agents / correlation / scenario / report /
guidance / rag)은 이 패키지를 import하지 않으며, 의존 방향은 한쪽이다:

    scripts/build_demo_replay.py -> demo -> (설정값만)
"""

from demo.scenarios import (
    SCENARIOS,
    SCENARIOS_BY_KEY,
    DemoScenario,
    StepSpec,
    get_scenario,
    make_steps,
)

__all__ = [
    "SCENARIOS",
    "SCENARIOS_BY_KEY",
    "DemoScenario",
    "StepSpec",
    "get_scenario",
    "make_steps",
]
