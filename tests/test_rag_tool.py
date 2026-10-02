import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from src.tools.rag_tool import search_runbook


query = """
AWS 계정에서 비정상적인 로그인과 의심스러운 접근이
발견되었습니다. 보안 사고가 의심되는 상황에서
어떤 대응 절차를 수행해야 하나요?
"""

result = search_runbook.invoke(query)

print("\n==============================")
print("검색 결과")
print("==============================\n")

print(result)