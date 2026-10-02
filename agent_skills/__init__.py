"""Agent Skill 인터페이스 계층.

의존 방향은 agent_skills -> src.skills 한쪽뿐이다. src/ 아래 코드는 agent_skills를
import하지 않으며, src/skills는 Agent 없이도 단독 실행 가능한 순수 분석 라이브러리로
유지한다.
"""
