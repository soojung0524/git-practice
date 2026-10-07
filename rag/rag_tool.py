# src/tools/rag_tool.py

import os

from dotenv import load_dotenv
from langchain_core.tools import tool
from langchain_openai import OpenAIEmbeddings
from supabase import create_client


load_dotenv()


# =========================
# Supabase 설정
# =========================

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError(
        "SUPABASE_URL 또는 SUPABASE_KEY가 .env에 설정되어 있지 않습니다."
    )

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


# =========================
# OpenAI Embedding
# =========================

embeddings = OpenAIEmbeddings(model="text-embedding-3-small")


# =========================
# 검색 파라미터
# =========================
# text-embedding-3-small 은 관련 문장끼리도 유사도가 0.3~0.5 정도로 낮게 나온다.
# 0.5 로 자르면 정답 청크가 자주 버려지므로, 임계값은 아주 낮게 두고
# 항상 상위 N개를 돌려준 뒤 관련성 판단은 LLM 에 맡긴다.
MATCH_THRESHOLD = float(os.getenv("RAG_MATCH_THRESHOLD", "0.0"))
MATCH_COUNT = int(os.getenv("RAG_MATCH_COUNT", "10"))

# hybrid: 벡터 + 키워드 (Supabase 에 hybrid_search 함수가 있어야 함)
# vector: 기존 match_documents 만 사용
SEARCH_MODE = os.getenv("RAG_SEARCH_MODE", "hybrid").lower()

_hybrid_unavailable = False  # hybrid_search 호출이 실패하면 이후엔 벡터 검색만 사용


def _format_doc(doc: dict) -> str:
    meta = doc.get("metadata") or {}

    page = doc.get("page", "unknown")
    # DB 의 page 는 PyMuPDF 기준 0부터 시작 → PDF 페이지 번호로 +1
    if isinstance(page, int):
        page = page + 1

    header = [f"Page {page}"]
    if meta.get("printed_page"):
        header.append(f"문서 표기 p.{meta['printed_page']}")
    if meta.get("section"):
        header.append(f"섹션: {meta['section']}")
    if doc.get("similarity") is not None:
        header.append(f"유사도 {doc['similarity']:.2f}")
    if doc.get("keyword_rank") is not None:
        header.append("키워드 일치")

    return f"[{' | '.join(header)}]\n{doc.get('content', '')}"


def _vector_search(query_embedding) -> list[dict]:
    response = supabase.rpc(
        "match_documents",
        {
            "query_embedding": query_embedding,
            "match_threshold": MATCH_THRESHOLD,
            "match_count": MATCH_COUNT,
        },
    ).execute()
    return response.data or []


def _hybrid_search(query: str, query_embedding) -> list[dict]:
    response = supabase.rpc(
        "hybrid_search",
        {
            "query_text": query,
            "query_embedding": query_embedding,
            "match_count": MATCH_COUNT,
        },
    ).execute()
    return response.data or []


def search(query: str) -> list[dict]:
    """도구 밖(테스트 코드 등)에서도 쓸 수 있는 검색 함수."""
    global _hybrid_unavailable

    query_embedding = embeddings.embed_query(query)

    if SEARCH_MODE == "hybrid" and not _hybrid_unavailable:
        try:
            documents = _hybrid_search(query, query_embedding)
            if documents:
                return documents
        except Exception as e:
            # 함수가 아직 없거나 권한 문제 → 경고 한 번 출력 후 벡터 검색으로 계속
            _hybrid_unavailable = True
            print(f"[rag_tool] hybrid_search 실패, 벡터 검색으로 전환합니다: {e}")

    return _vector_search(query_embedding)


# =========================
# RAG 검색 Tool
# =========================

@tool
def search_runbook(query: str) -> str:
    """AWS Security Incident Response User Guide(영문 문서)에서 관련 내용을 검색한다.

    query 작성 규칙:
    - 문서가 영어이므로 반드시 영어 핵심 키워드로 작성한다.
      예) "case attachments deleted after closed", "contain IAM principal"
    - "매뉴얼", "runbook", 문서명 같은 일반어는 넣지 않는다.
    - 주제가 여러 개면 주제별로 따로 검색한다.

    결과는 관련도가 높은 순으로 최대 여러 개가 반환된다.
    의미 검색과 키워드 검색을 함께 쓰므로, 정확한 용어(정책 이름, API 이름,
    기능 이름 등)를 알면 query 에 그대로 넣으면 더 잘 찾는다.
    관련도가 높아도 질문과 무관한 결과일 수 있으니 내용을 직접 확인해서 사용한다.
    각 결과 앞의 [Page N] 을 근거 페이지로 인용한다.
    """
    documents = search(query)

    if not documents:
        return "검색 결과가 없습니다."

    return "\n\n--------------------\n\n".join(_format_doc(d) for d in documents)