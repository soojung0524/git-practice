# src/tools/ingest_pdf.py
#
# 변경 사항
# 1) 합자(ﬁ, ﬂ 등) 정규화: PyMuPDF 가 "findings" 를 "ﬁndings" 로 뽑아 검색 품질을 떨어뜨림
# 2) 반복 머리글/바닥글 제거: 모든 페이지의 "AWS Security Incident Response User Guide",
#    "… Version August 27, 2026 94" 줄이 청크마다 섞여 임베딩을 흐림
# 3) 섹션 제목을 청크 앞에 붙임: PDF 책갈피(TOC)로 페이지의 섹션을 찾아
#    "[Section: Managing Cases > Attachments]" 처럼 붙이면 짧은 Note 문장도 잘 잡힘
# 4) 청크 크기 1000 → 700 (겹침 120): 한 청크에 여러 주제가 섞이는 것을 줄임
# 5) 문서 표기 페이지 번호(printed_page)와 섹션을 metadata 에 저장
# 6) 다시 실행해도 중복 저장되지 않도록 같은 source 의 기존 행을 먼저 삭제

import os
import re
import unicodedata

import pymupdf
from dotenv import load_dotenv
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from supabase import create_client


# =========================
# 환경변수 / 클라이언트
# =========================

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError(
        "SUPABASE_URL 또는 SUPABASE_KEY가 .env에 설정되어 있지 않습니다."
    )

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

embeddings = OpenAIEmbeddings(model="text-embedding-3-small")


# =========================
# 설정
# =========================

PDF_PATH = "data/raw/아마존보안대응.pdf"
SOURCE = "아마존보안대응.pdf"

DOC_TITLE = "AWS Security Incident Response User Guide"
# 바닥글 예: "Tags Version August 27, 2026 94"
FOOTER_RE = re.compile(r"Version [A-Z][a-z]+ \d{1,2}, \d{4}\s*(\d+|[ivxlc]+)?\s*$")
PAGE_NUM_RE = re.compile(r"^\s*(\d+|[ivxlc]+)\s*$")

text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=700,
    chunk_overlap=120,
    separators=["\n\n", "\n", ". ", " ", ""],
)


# =========================
# 텍스트 정리
# =========================

def clean_page_text(text: str):
    """합자 정규화 + 머리글/바닥글 제거. (정리된 텍스트, 문서 표기 페이지) 반환."""
    text = unicodedata.normalize("NFKC", text)

    lines = text.splitlines()
    kept = []
    printed_page = None
    skip_next_number = False

    for line in lines:
        s = line.strip()

        if s == DOC_TITLE:
            continue

        m = FOOTER_RE.search(s)
        if m:
            if m.group(1):
                printed_page = m.group(1)
            else:
                skip_next_number = True  # 페이지 번호가 다음 줄로 떨어진 경우
            continue

        if skip_next_number and PAGE_NUM_RE.match(s):
            printed_page = s
            skip_next_number = False
            continue
        skip_next_number = False

        kept.append(line)

    cleaned = re.sub(r"\n{3,}", "\n\n", "\n".join(kept)).strip()
    return cleaned, printed_page


def build_section_map(doc) -> dict[int, str]:
    """PDF 책갈피로 페이지(0부터) → 섹션 경로 문자열을 만든다.

    한 페이지에서 새 섹션이 여러 개 시작하면 모두 이어 붙인다.
    예: {100: "User tasks > Managing Cases > Attachments; Tags"}
    책갈피가 없는 PDF 면 빈 dict.
    """
    toc = doc.get_toc(simple=True)  # [[level, title, page(1부터)], ...]
    if not toc:
        return {}

    starts: dict[int, list[str]] = {}
    path: list[str] = []
    current_at_page: dict[int, str] = {}

    for level, title, page in toc:
        title = unicodedata.normalize("NFKC", title).strip()
        path = path[: level - 1] + [title]
        p = page - 1
        starts.setdefault(p, []).append(" > ".join(path))
        current_at_page[p] = " > ".join(path)

    section_map = {}
    current = ""
    for p in range(len(doc)):
        if p in starts:
            names = [s.split(" > ")[-1] for s in starts[p]]
            if current:
                # 페이지 윗부분은 앞 페이지에서 시작한 섹션이 이어지는 경우가 많으므로
                # 이어지는 섹션(전체 경로) + 이 페이지에서 새로 시작하는 섹션 이름
                section_map[p] = "; ".join([current] + names)
            else:
                section_map[p] = "; ".join([starts[p][0]] + names[1:])
            current = current_at_page[p]
        else:
            section_map[p] = current
    return section_map


# =========================
# PDF → Chunk
# =========================

def load_pdf_chunks():
    print("PDF loading...")
    doc = pymupdf.open(PDF_PATH)
    print(f"Loaded pages: {len(doc)}")

    section_map = build_section_map(doc)
    if not section_map:
        print("PDF 책갈피가 없어 섹션 정보 없이 진행합니다.")

    chunks = []
    for page_index, page in enumerate(doc):
        text, printed_page = clean_page_text(page.get_text("text"))
        if not text:
            continue

        section = section_map.get(page_index, "")
        prefix = f"[Section: {section}]\n" if section else ""

        for chunk in text_splitter.split_text(text):
            chunks.append({
                "content": prefix + chunk,
                "page": page_index,  # 0부터 (검색 도구에서 +1)
                "section": section,
                "printed_page": printed_page,
            })

    doc.close()
    print(f"Created chunks: {len(chunks)}")
    return chunks


# =========================
# Embedding 생성
# =========================

def create_embeddings(chunks):
    print("Creating embeddings...")
    vectors = embeddings.embed_documents([c["content"] for c in chunks])
    print(f"Created embeddings: {len(vectors)}")
    return vectors


# =========================
# Supabase 저장
# =========================

def count_existing() -> int:
    res = (
        supabase.table("documents")
        .select("id", count="exact")
        .eq("metadata->>source", SOURCE)
        .limit(1)
        .execute()
    )
    return res.count or 0


def delete_existing():
    """같은 문서로 이미 저장된 행을 지워 재실행 시 중복을 막는다.

    삭제가 RLS 정책 등으로 막히면 에러 없이 0건으로 끝나기 때문에,
    삭제 후 남은 행 수를 다시 세어 남아 있으면 저장을 중단한다.
    """
    before = count_existing()
    if before == 0:
        print("기존 행 없음")
        return

    supabase.table("documents").delete().eq("metadata->>source", SOURCE).execute()
    after = count_existing()
    print(f"기존 행 삭제: {before - after}/{before}개")

    if after > 0:
        raise SystemExit(
            f"\n기존 행 {after}개가 삭제되지 않았습니다 (RLS 정책이 삭제를 막는 것으로 보입니다).\n"
            "중복 저장을 막기 위해 중단합니다. Supabase SQL Editor 에서\n"
            "    truncate table documents;\n"
            "를 실행한 뒤 이 스크립트를 다시 실행하세요."
        )


def save_to_supabase(chunks, vectors):
    print("Saving to Supabase...")

    rows = [
        {
            "content": c["content"],
            "page": c["page"],
            "embedding": v,
            "metadata": {
                "source": SOURCE,
                "section": c["section"],
                "printed_page": c["printed_page"],
            },
        }
        for c, v in zip(chunks, vectors)
    ]

    batch_size = 50
    for i in range(0, len(rows), batch_size):
        supabase.table("documents").insert(rows[i:i + batch_size]).execute()
        print(f"Inserted {min(i + batch_size, len(rows))}/{len(rows)}")

    print("Supabase 저장 완료!")


# =========================
# 실행
# =========================

def main():
    chunks = load_pdf_chunks()
    if not chunks:
        print("PDF에서 텍스트를 찾지 못했습니다.")
        return

    # 청크 예시 확인용: 첨부파일 삭제 문장이 들어간 청크 출력
    for c in chunks:
        if "seven days after a case" in c["content"]:
            print("\n[확인] 첨부파일 삭제 문장 청크 (page index", c["page"], ")")
            print(c["content"][:400], "\n")
            break

    vectors = create_embeddings(chunks)
    delete_existing()
    save_to_supabase(chunks, vectors)

    print("=================================")
    print("PDF ingestion 완료")
    print("=================================")


if __name__ == "__main__":
    main()