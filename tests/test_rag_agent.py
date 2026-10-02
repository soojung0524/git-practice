import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from src.agents.rag_agent import rag_agent


query = """
케이스 첨부파일은 언제 삭제되나요?
"""

print("Agent 실행 중...")

result = rag_agent.invoke({
    "messages": [
        {
            "role": "user",
            "content": query,
        }
    ]
})

print("\n==============================")
print("Agent 답변")
print("==============================\n")

print(result["messages"][-1].content)

for m in result["messages"]:
    if m.type == "ai" and getattr(m, "tool_calls", None):
        print("검색어:", [tc["args"] for tc in m.tool_calls])
    if m.type == "tool":
        print("검색 결과에 'seven days' 포함:", "seven days" in str(m.content))
        print(str(m.content)[:500], "\n---")