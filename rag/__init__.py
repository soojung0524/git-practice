"""기존 팀원이 작성한 RAG 구현 (AWS Security Incident Response User Guide 기반).

여기서는 아무것도 import하지 않는다. rag_tool/rag_agent를 import하면 그 시점에
.env 로드, Supabase 클라이언트 생성, OpenAIEmbeddings/ChatOpenAI 생성이 일어나기
때문이다. 필요한 쪽에서 직접 lazy import한다.

    from rag.rag_agent import rag_agent     # 호출 직전에만

ingest_pdf는 offline 전용 스크립트다. investigation runtime에서 import하지 않는다.
"""
