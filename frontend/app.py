"""AWS 보안 사고 대응 대시보드 (Streamlit).

실행 (프로젝트 루트에서):
    uv run streamlit run frontend/app.py
"""

from __future__ import annotations

import sys
from datetime import datetime, time
from pathlib import Path

import pandas as pd
import streamlit as st

# 이 파일과 같은 폴더의 services.py, ui.py 를 어떤 위치에서 실행해도 찾을 수 있게
sys.path.insert(0, str(Path(__file__).resolve().parent))
import services as svc  # noqa: E402
import ui  # noqa: E402

st.set_page_config(page_title="AWS 보안 사고 대응", page_icon="🛡️", layout="wide")

_ver = tuple(int(x) for x in st.__version__.split(".")[:2])
if _ver < (1, 44):
    st.error(f"Streamlit 1.44 이상이 필요합니다 (지금 {st.__version__}). `uv add \"streamlit>=1.44\"` 후 다시 실행하세요.")
    st.stop()

st.markdown(ui.CSS, unsafe_allow_html=True)

# ───────────────────────── 상태 ─────────────────────────
ss = st.session_state
ss.setdefault("result", None)        # 지금 보고 있는 분석 결과 (services.serialize_state 형식)
ss.setdefault("history", [])         # 이번 세션에서 실행·불러온 결과들
ss.setdefault("detail_id", None)     # 상세 화면에 띄울 finding_id
ss.setdefault("chat", [])
ss.setdefault("draft_question", "")
ss.setdefault("notes_error", {})     # finding_id -> 오류 메시지 (자동 재시도 막기)

SUBTITLE = "의심되는 보안 사고 상황을 분석하고, AWS 공식 보안 대응 매뉴얼을 기반으로 대응 절차를 안내합니다."
RISK_OPTIONS = list(svc.SEVERITY_ORDER)


def now_text() -> str:
    return datetime.now().strftime("%Y.%m.%d %H:%M")


def html(s: str) -> None:
    st.markdown(s, unsafe_allow_html=True)


def set_result(result: dict) -> None:
    result.setdefault("notes", {})
    ss.result = result
    ss.detail_id = None
    ss.history = [r for r in ss.history if r.get("investigation_id") != result.get("investigation_id")]
    ss.history.insert(0, result)


def open_detail(finding_id: str) -> None:
    ss.detail_id = finding_id
    ss.pop("records_table", None)
    st.switch_page(PAGES["records"])


@st.cache_data(ttl=60, show_spinner=False)
def cached_status() -> tuple[bool, str]:
    return svc.system_status()


# ───────────────────────── 보안상 주의사항 ─────────────────────────
def get_notes(result: dict, finding: dict, auto: bool = True, spinner: bool = False) -> dict | None:
    """탐지 결과의 보안상 주의사항. 없으면 보안 매뉴얼을 검색해 만들고 결과에 저장한다.

    결과 JSON 을 저장하면 주의사항도 함께 저장되므로, 발표 때는 네트워크 없이 보여줄 수 있다.
    """
    notes = result.setdefault("notes", {})
    fid = finding["finding_id"]
    if fid in notes:
        return notes[fid]
    if not auto or fid in ss.notes_error:
        return None
    try:
        if spinner:
            with st.spinner("보안 매뉴얼에서 주의사항을 찾는 중…"):
                notes[fid] = svc.security_notes(finding)
        else:
            notes[fid] = svc.security_notes(finding)
        return notes[fid]
    except Exception as e:
        ss.notes_error[fid] = str(e)
        return None


def cached_notes(result: dict, finding: dict | None) -> dict | None:
    """이미 만들어 둔 주의사항만 꺼낸다(새로 만들지 않음)."""
    if finding is None:
        return None
    return (result.get("notes") or {}).get(finding["finding_id"])


WAITING = '<p class="sx-muted">⏳ 보안 매뉴얼에서 찾는 중… 다른 내용은 먼저 보실 수 있습니다.</p>'
FAILED = '<p class="sx-muted">보안 매뉴얼에서 내용을 가져오지 못했습니다.</p>'


def notes_failed(finding: dict, key: str) -> None:
    err = ss.notes_error.get(finding["finding_id"])
    if err:
        st.warning(f"보안상 주의사항을 가져오지 못했습니다: {err}")
        if st.button("다시 시도", key=key):
            ss.notes_error.pop(finding["finding_id"], None)
            st.rerun()


def notes_preview(notes: dict | None, limit: int = 5, width: int = 70) -> list[str]:
    """카드용 짧은 목록. 항목마다 첫 문장(최대 width 자)만 보여주고, 전체는 상세 화면에서."""
    if not notes:
        return []
    sec = notes["sections"]
    items = (sec.get("procedure") or sec.get("actions") or sec.get("summary") or [])[:limit]
    out = []
    for text in items:
        first = text.split(". ")[0].rstrip(".")
        out.append(first if len(first) <= width else first[:width].rstrip() + "…")
    return out


def timeline_items(result: dict, current_id: str | None = None, limit: int | None = 6) -> list[dict]:
    found = sorted(result["findings"], key=lambda f: str(f.get("start_time") or ""))
    days = {str(f.get("start_time") or "")[:10] for f in found}
    many_days = len(days) > 1
    items = []
    for f in found:
        start = svc.fmt_time(f.get("start_time"))
        tm = start[5:] if many_days else start[11:]
        sub = " · ".join(x for x in (f.get("host"), ui.RISK.get(f["severity"], ("",))[0]) if x)
        items.append({"time": tm, "title": f["summary"], "sub": sub, "current": f["finding_id"] == current_id})
    if limit and len(items) > limit:
        # 현재 항목이 잘리지 않도록, 현재 항목 주변을 보여준다
        idx = next((i for i, it in enumerate(items) if it["current"]), 0)
        start = max(0, min(idx - limit // 2, len(items) - limit))
        items = items[start:start + limit]
    return items


# ───────────────────────── 화면: 홈 ─────────────────────────
def page_home() -> None:
    html(ui.page_header("AWS 보안 사고 대응 대시보드", SUBTITLE, now_text()))
    result = ss.result
    if not result:
        html(ui.card("분석 결과가 없습니다", "search",
                     ui.paragraphs(["사고 분석 화면에서 이벤트 파일을 골라 분석을 실행하거나, 저장해 둔 결과 JSON 을 불러오세요.",
                                    "문서 보기 화면에서는 분석 없이도 보안 매뉴얼에 바로 질문할 수 있습니다."])))
        c1, c2, _ = st.columns([1, 1, 3])
        if c1.button("사고 분석으로", type="primary", use_container_width=True):
            st.switch_page(PAGES["analyze"])
        if c2.button("문서 보기로", use_container_width=True):
            st.switch_page(PAGES["docs"])
        return

    top = svc.headline_finding(result)
    if top is None:
        html(ui.banner(category="이상 없음", title="탐지된 이상 징후가 없습니다",
                       desc=f"이벤트 {result.get('event_count') or '-'}건을 분석했습니다.",
                       occurred="-", updated=svc.fmt_time(result.get("created_at")), severity=None))
    else:
        interp = result.get("interpretation")
        desc = interp.get("overall_summary") if isinstance(interp, dict) else None
        if not isinstance(desc, str):
            others = len(result["findings"]) - 1
            where = f"{top['host']}에서 " if top.get("host") else ""
            desc = (f"{svc.fmt_time(top.get('start_time'))}, {where}{top['finding_type']} 이(가) 탐지되었습니다. "
                    + (f"같은 분석에서 다른 이상 징후 {others}건이 함께 탐지되었습니다." if others else ""))
        html(ui.banner(category=svc.CATEGORY_KO.get(top["category"], top["category"]), title=top["summary"],
                       desc=desc, occurred=svc.fmt_time(top.get("start_time")),
                       updated=svc.fmt_time(result.get("created_at")), severity=top["severity"]))

    left, right = st.columns([2, 1.05], gap="medium")
    with left:
        a, b = st.columns(2, gap="medium")
        with a:
            html(ui.status_card("서버 상황", "server", svc.area_status(result, "Server")))
        with b:
            html(ui.status_card("네트워크 상황", "network", svc.area_status(result, "Network")))

        c, d = st.columns(2, gap="medium")
        with c:
            if top is None:
                body = ui.bullets(["탐지된 이상 징후가 없습니다."])
            else:
                rest = [f for f in svc.sorted_findings(result) if f["finding_id"] != top["finding_id"]]
                items = svc.finding_bullets(top)[:4]
                if rest:
                    counts = pd.Series([f["severity"] for f in rest]).value_counts()
                    parts = [f"{ui.RISK[s][0]} {counts[s]}" for s in svc.SEVERITY_ORDER if s in counts]
                    items.append(f"함께 탐지된 이상 징후 {len(rest)}건 ({', '.join(parts)})")
                body = ui.sub("조사 내용") + ui.bullets(items)
            html(ui.card("Log 조사 내용", "terminal", body))
        with d:
            notes_slot = st.empty()  # 주의사항은 화면을 다 그린 뒤 마지막에 채운다
        if top is not None and st.button("사건 상세보기 →", key="home_detail", type="primary",
                                         use_container_width=True):
            open_detail(top["finding_id"])

    with right:
        html(ui.timeline(timeline_items(result, top["finding_id"] if top else None)))
        if len(result["findings"]) > 6 and st.button("전체보기 →", key="tl_all", use_container_width=True):
            ss.detail_id = None
            st.switch_page(PAGES["records"])
        refs_slot = st.empty()

    def fill(n: dict | None, waiting: bool = False) -> None:
        if top is None:
            body = ui.bullets(["대응이 필요한 사항이 없습니다."])
        elif n:
            body = ui.sub("관련 대응 절차", "list") + ui.bullets(notes_preview(n))
        else:
            body = WAITING if waiting else FAILED
        notes_slot.markdown(ui.card("보안상 주의사항", "book", body), unsafe_allow_html=True)
        refs_slot.markdown(ui.refs((n or {}).get("refs") or []), unsafe_allow_html=True)

    notes = cached_notes(result, top)
    waiting = top is not None and notes is None and top["finding_id"] not in ss.notes_error
    fill(notes, waiting=waiting)          # 1) 모든 카드를 먼저 보여주고
    if waiting:
        notes = get_notes(result, top)    # 2) 마지막에 매뉴얼을 검색해
        fill(notes)                       # 3) 빈 자리를 채운다
    if top is not None:
        with d:
            notes_failed(top, "retry_home")


# ───────────────────────── 화면: 사고 분석 ─────────────────────────
def page_analyze() -> None:
    html(ui.page_header("사고 분석", "로그 이벤트 파일과 분석 범위를 정해 분석을 실행합니다.", now_text()))
    form_col, side_col = st.columns([1.4, 1], gap="large")

    with form_col:
        files = svc.list_event_files()
        with st.form("run"):
            if files:
                event_path = st.selectbox("이벤트 파일 (output/)", files)
            else:
                event_path = st.text_input("이벤트 파일 경로", "output/events.pkl",
                                           help="output/ 아래에서 .pkl 파일을 찾지 못해 직접 입력합니다.")
            c1, c2 = st.columns(2)
            dataset = c1.selectbox("데이터셋", ["gaia", "russellmitchell", "(지정 안 함)"])
            inv_id = c2.text_input("사건 ID", placeholder="비우면 자동 생성")
            c3, c4 = st.columns(2)
            host = c3.text_input("호스트", placeholder="전체")
            service = c4.text_input("서비스", placeholder="전체")
            source_types = st.text_input("로그 종류", placeholder="쉼표로 구분, 비우면 전체 (예: apache_access, auditd)")
            use_range = st.checkbox("기간 지정")
            d1, d2, d3, d4 = st.columns(4)
            start_d = d1.date_input("시작일", value=None)
            start_t = d2.time_input("시작 시각", value=time(0, 0))
            end_d = d3.date_input("종료일", value=None)
            end_t = d4.time_input("종료 시각", value=time(23, 59))
            interpret = st.checkbox("LLM 해석 포함", help="OpenAI API 를 호출하므로 시간과 비용이 듭니다.")
            submitted = st.form_submit_button("분석 시작", type="primary", use_container_width=True)

        done = False
        if submitted:
            with st.status("분석 중…", expanded=True) as status:
                try:
                    result = svc.run_analysis(
                        event_path=event_path,
                        investigation_id=inv_id or None,
                        dataset=None if dataset == "(지정 안 함)" else dataset,
                        host=host, service=service,
                        start_time=datetime.combine(start_d, start_t) if use_range and start_d else None,
                        end_time=datetime.combine(end_d, end_t) if use_range and end_d else None,
                        source_types=[s.strip() for s in source_types.split(",") if s.strip()],
                        interpret=interpret,
                        on_progress=lambda node: st.write(f"✓ {svc.node_label(node)}"),
                    )
                    set_result(result)
                    status.update(label=f"완료: 탐지 {len(result['findings'])}건", state="complete")
                    done = True
                except Exception as e:
                    status.update(label="분석 실패", state="error")
                    st.exception(e)
        if done:
            st.switch_page(PAGES["home"])  # 분석이 끝나면 대시보드로

    with side_col:
        html(ui.card("저장한 결과 불러오기", "file",
                     ui.paragraphs(["분석을 다시 실행하지 않고 결과를 볼 수 있습니다. 발표 데모에 유용합니다."])))
        uploaded = st.file_uploader("결과 JSON", type="json", label_visibility="collapsed")
        if uploaded is not None and st.button("불러오기", use_container_width=True):
            try:
                set_result(svc.result_from_json(uploaded.getvalue().decode("utf-8")))
                st.switch_page(PAGES["home"])
            except Exception as e:
                st.error(f"불러오기 실패: {e}")

        if ss.history:
            st.markdown("**이번 세션의 분석**")
            labels = {i: f"{r.get('investigation_id')} · 탐지 {len(r['findings'])}건 · {svc.fmt_time(r.get('created_at'))}"
                      for i, r in enumerate(ss.history)}
            cur = next((i for i, r in enumerate(ss.history) if r is ss.result), 0)
            pick = st.radio("분석 선택", list(labels), index=cur, format_func=labels.get, label_visibility="collapsed")
            if ss.history[pick] is not ss.result:
                ss.result = ss.history[pick]
                ss.detail_id = None
                st.rerun()


# ───────────────────────── 화면: 분석 기록 (목록 + 사건 상세) ─────────────────────────
def page_records() -> None:
    result = ss.result
    if not result:
        html(ui.page_header("분석 기록", "탐지된 이상 징후 목록과 사건 상세를 봅니다.", now_text()))
        st.info("분석 결과가 없습니다. 사고 분석 화면에서 분석을 실행하거나 결과를 불러오세요.")
        return
    finding = next((f for f in result["findings"] if f["finding_id"] == ss.detail_id), None)
    if finding is not None:
        render_detail(result, finding)
    else:
        render_list(result)


def render_list(result: dict) -> None:
    html(ui.page_header("분석 기록", "탐지된 이상 징후 목록입니다. 행을 누르면 사건 상세로 이동합니다.", now_text()))
    found = svc.sorted_findings(result)
    counts = pd.Series([f["severity"] for f in found]).value_counts() if found else {}
    chip_items = [("전체", f"{len(found)}건")]
    chip_items += [(ui.RISK[s][0], f"{counts[s]}건") for s in svc.SEVERITY_ORDER if s in counts]
    if result.get("event_count"):
        chip_items.append(("분석 이벤트", f"{result['event_count']:,}건"))
    html(ui.chips(chip_items))

    if result.get("errors"):
        with st.expander(f"분석 중 오류 {len(result['errors'])}건"):
            for name, msg in result["errors"].items():
                st.error(f"**{svc.AREA_LABELS.get(name.capitalize(), name)}**: {msg}")

    if not found:
        st.success("탐지된 이상 징후가 없습니다.")
        return

    f1, f2, f3, f4 = st.columns([1, 1, 1, 2])
    sel_sev = f1.multiselect("위험 단계", RISK_OPTIONS, format_func=lambda s: ui.RISK[s][0])
    sel_cat = f2.multiselect("분류", sorted({f["category"] for f in found}),
                             format_func=lambda c: svc.CATEGORY_KO.get(c, c))
    sel_host = f3.multiselect("호스트", sorted({f["host"] for f in found if f.get("host")}))
    keyword = f4.text_input("검색", placeholder="요약·유형에서 찾기")

    view = [f for f in found
            if (not sel_sev or f["severity"] in sel_sev)
            and (not sel_cat or f["category"] in sel_cat)
            and (not sel_host or f.get("host") in sel_host)
            and (not keyword or keyword.lower() in f"{f['summary']} {f['finding_type']}".lower())]
    st.caption(f"{len(view)} / {len(found)}건")
    if not view:
        return

    table = pd.DataFrame([{
        "위험 단계": ui.RISK[f["severity"]][0],
        "분류": svc.CATEGORY_KO.get(f["category"], f["category"]),
        "요약": f["summary"],
        "호스트": f.get("host") or "-",
        "발생 일시": svc.fmt_time(f.get("start_time")),
        "근거 수": (f.get("metrics") or {}).get("evidence_count", len(f.get("evidence") or [])),
    } for f in view])
    event = st.dataframe(table, hide_index=True, use_container_width=True, on_select="rerun",
                         selection_mode="single-row", key="records_table",
                         column_config={"요약": st.column_config.TextColumn(width="large")})
    rows = event.selection.rows if event and event.selection else []
    if rows:
        ss.detail_id = view[rows[0]]["finding_id"]
        st.rerun()

    with st.expander("분석 영역별 실행 현황"):
        rows_ = []
        for name, a in result["agents"].items():
            label = svc.AREA_LABELS.get(name, name)
            if a is None:
                failed = any(name.lower() in k.lower() for k in result.get("errors") or {})
                rows_.append({"분석 영역": label, "상태": "오류" if failed else "실행 안 함", "입력 이벤트": None, "탐지": None})
            else:
                rows_.append({"분석 영역": label, "상태": a["status"], "입력 이벤트": a["input_item_count"],
                              "탐지": a["finding_count"]})
        st.dataframe(pd.DataFrame(rows_), hide_index=True, use_container_width=True)


def render_detail(result: dict, finding: dict) -> None:
    if st.button("← 목록으로 돌아가기", type="tertiary"):
        ss.detail_id = None
        ss.pop("records_table", None)  # 표 선택을 지워야 상세가 다시 열리지 않는다
        st.rerun()

    html(ui.detail_title(finding["severity"], finding["summary"], [
        ("발생 일시", svc.fmt_time(finding.get("start_time"))),
        ("마지막 업데이트", svc.fmt_time(result.get("created_at"))),
        ("사건 ID", result.get("investigation_id") or "-"),
    ]))

    # 보안상 주의사항은 매뉴얼 검색에 시간이 걸리므로 여기서 기다리지 않는다.
    # 이미 만들어 둔 것이 있으면 바로 쓰고, 없으면 가운데 열에서 만든 뒤 카드를 채운다.
    notes = (result.get("notes") or {}).get(finding["finding_id"])
    bullets = svc.finding_bullets(finding)

    c1, c2, c3, c4 = st.columns(4, gap="small")
    with c1:
        html(ui.status_card("서버 상황", "server", svc.area_status(result, "Server")))
    with c2:
        html(ui.status_card("네트워크 상황", "network", svc.area_status(result, "Network")))
    with c3:
        html(ui.card("Log 조사", "terminal", ui.bullets(bullets[:3]), ui.done_badge("조사 완료")))
    with c4:
        notes_slot = st.empty()

    def fill_notes_card(n: dict | None, waiting: bool = False) -> None:
        if n:
            notes_slot.markdown(ui.card("보안상 주의사항", "book", ui.bullets(notes_preview(n, 3)),
                                        ui.done_badge("분석 완료")), unsafe_allow_html=True)
        else:
            text = "보안 매뉴얼에서 찾는 중…" if waiting else "가져오지 못했습니다."
            notes_slot.markdown(ui.card("보안상 주의사항", "book", f'<p class="sx-muted">{text}</p>'),
                                unsafe_allow_html=True)

    fill_notes_card(notes, waiting=notes is None)

    left, mid, right = st.columns([1.25, 1.15, 0.85], gap="medium")

    # ── Log 조사 내용 ──
    with left:
        html(ui.card("Log 조사 내용", "terminal", ui.sub("조사 내용") + ui.bullets(bullets)))
        evidence = finding.get("evidence") or []
        if evidence:
            st.markdown("**주요 로그 원문**")
            idx = 0
            if len(evidence) > 1:
                idx = st.selectbox("근거", range(len(evidence)), label_visibility="collapsed",
                                   format_func=lambda i: f"{evidence[i]['source_file']} : {evidence[i]['line_number']}줄")
            ev = evidence[idx]
            try:
                lines = svc.read_source_line(ev["source_file"], int(ev["line_number"]))
                target = int(ev["line_number"]) + (1 if str(ev["source_file"]).lower().endswith(".csv") else 0)
                st.code("\n".join(f"{'▶' if n == target else ' '} {n:>7}  {text}" for n, text in lines), language=None)
            except (FileNotFoundError, ValueError, OSError):
                st.caption(f"원본 파일을 열 수 없어 근거 정보만 표시합니다: {ev['source_file']}")
                st.json(ev, expanded=True)

        extra = []
        hit = find_interpretation(result.get("interpretation"), finding["finding_id"])
        if isinstance(hit, dict):
            extra += [v for v in hit.values() if isinstance(v, str) and len(v) > 20 and v != finding["finding_id"]]
        related = svc.related_findings(result, finding)
        if related:
            extra.append(f"같은 호스트 또는 같은 IP·계정에서 함께 탐지된 이상 징후가 {len(related)}건 있습니다.")
        html(ui.card("추가 조사 결과", "check",
                     ui.bullets(extra) if extra else '<p class="sx-muted">추가로 확인된 연관 이상 징후가 없습니다.</p>'))
        for f in related[:5]:
            label = f"[{ui.RISK[f['severity']][0]}] {f['summary']}"
            if st.button(label, key=f"rel_{f['finding_id']}", use_container_width=True):
                ss.detail_id = f["finding_id"]
                st.rerun()

    # ── 보안상 주의사항 ──
    with mid:
        mid_slot = st.empty()

    # ── 참고 문서 · 타임라인 ──
    with right:
        refs_slot = st.empty()
        html(ui.timeline(timeline_items(result, finding["finding_id"])))

    def fill_mid(n: dict | None, waiting: bool = False) -> None:
        if n:
            sec = n["sections"]
            body = ""
            if sec.get("summary"):
                body += ui.sub("분석 내용", "search") + ui.paragraphs(sec["summary"])
            if sec.get("procedure"):
                body += ui.sub("관련 대응 절차", "list") + ui.steps(sec["procedure"])
            if sec.get("checks"):
                body += ui.callout("warn", "확인해야 할 사항", sec["checks"])
            if sec.get("actions"):
                body += ui.callout("ok", "권장 대응 방향", sec["actions"])
            card = ui.card("보안상 주의사항", "book", body, ui.done_badge("분석 완료"))
        else:
            card = ui.card("보안상 주의사항", "book", WAITING if waiting else FAILED)
        mid_slot.markdown(card, unsafe_allow_html=True)
        refs_slot.markdown(ui.refs((n or {}).get("refs") or []), unsafe_allow_html=True)
        fill_notes_card(n, waiting=waiting)

    waiting = notes is None and finding["finding_id"] not in ss.notes_error
    fill_mid(notes, waiting=waiting)          # 1) 화면 전체를 먼저 보여주고
    if waiting:
        notes = get_notes(result, finding)    # 2) 마지막에 매뉴얼을 검색해
        fill_mid(notes)                       # 3) 빈 자리를 채운다

    with mid:
        if notes:
            if st.button("이 사건으로 이어서 질문하기 →", use_container_width=True):
                ss.draft_question = notes["question"]
                st.switch_page(PAGES["docs"])
        else:
            notes_failed(finding, "retry_detail")


def find_interpretation(interp, finding_id: str):
    """LLM 해석 결과에서 이 finding_id 를 가리키는 부분을 찾는다(구조를 모르므로 전체를 훑는다)."""
    if isinstance(interp, dict):
        if any(v == finding_id for k, v in interp.items() if "finding_id" in k):
            return interp
        for v in interp.values():
            hit = find_interpretation(v, finding_id)
            if hit is not None:
                return hit
    elif isinstance(interp, list):
        for v in interp:
            hit = find_interpretation(v, finding_id)
            if hit is not None:
                return hit
    return None


# ───────────────────────── 화면: 문서 보기 ─────────────────────────
def page_docs() -> None:
    html(ui.page_header("문서 보기", "AWS Security Incident Response User Guide 를 근거로 답합니다.", now_text()))

    for m in ss.chat:
        with st.chat_message(m["role"]):
            st.markdown(m["content"])
            if m["role"] == "assistant" and m.get("refs"):
                html(ui.refs(m["refs"]))

    def send(question: str) -> None:
        ss.chat.append({"role": "user", "content": question})
        history = [{"role": m["role"], "content": m["content"]} for m in ss.chat]
        with st.chat_message("user"):
            st.markdown(question)
        with st.chat_message("assistant"):
            with st.spinner("보안 매뉴얼을 검색하는 중…"):
                try:
                    out = svc.ask_rag(history)
                except Exception as e:
                    ss.chat.pop()
                    st.error(f"답변을 받지 못했습니다: {e}")
                    return
        ss.chat.append({"role": "assistant", "content": out["answer"], "refs": out.get("refs") or []})
        st.rerun()

    if ss.draft_question:
        with st.container(border=True):
            st.markdown("**사건 내용으로 만든 질문** (고쳐서 보낼 수 있습니다)")
            draft = st.text_area("질문", ss.draft_question, height=200, label_visibility="collapsed")
            b1, b2, _ = st.columns([1, 1, 4])
            if b1.button("보내기", type="primary", use_container_width=True):
                ss.draft_question = ""
                send(draft)
            if b2.button("취소", use_container_width=True):
                ss.draft_question = ""
                st.rerun()

    if ss.chat and st.button("대화 지우기"):
        ss.chat = []
        st.rerun()

    if q := st.chat_input("예: Access Key 가 노출된 것 같아요. 어떤 순서로 대응하나요?"):
        send(q)


# ───────────────────────── 화면: 설정 ─────────────────────────
def page_settings() -> None:
    html(ui.page_header("설정", "결과 저장과 연결 상태를 확인합니다.", now_text()))
    c1, c2 = st.columns(2, gap="large")
    with c1:
        st.markdown("**결과 저장**")
        if ss.result:
            n_notes = len(ss.result.get("notes") or {})
            st.caption(f"보안상 주의사항 {n_notes}건이 함께 저장됩니다. 발표 때 네트워크 없이 보여줄 수 있습니다.")
            st.download_button("결과 JSON 저장", svc.result_to_json(ss.result),
                               file_name=f"investigation_{ss.result.get('investigation_id') or 'result'}.json",
                               mime="application/json", type="primary")
        else:
            st.caption("저장할 분석 결과가 없습니다.")
    with c2:
        st.markdown("**연결 상태**")
        cached_status.clear()
        ok, msg = cached_status()
        (st.success if ok else st.warning)(msg)
        if st.button("세션 초기화"):
            for k in list(ss.keys()):
                del ss[k]
            st.rerun()


# ───────────────────────── 내비게이션 ─────────────────────────
PAGES = {
    "home": st.Page(page_home, title="홈", icon=":material/home:", url_path="home", default=True),
    "analyze": st.Page(page_analyze, title="사고 분석", icon=":material/search:", url_path="analyze"),
    "records": st.Page(page_records, title="분석 기록", icon=":material/description:", url_path="records"),
    "docs": st.Page(page_docs, title="문서 보기", icon=":material/menu_book:", url_path="docs"),
    "settings": st.Page(page_settings, title="설정", icon=":material/settings:", url_path="settings"),
}
current = st.navigation(list(PAGES.values()), position="hidden")

with st.sidebar:
    html(ui.brand())
    for page in PAGES.values():
        if page.title == current.title:
            with st.container(key="navactive"):
                st.page_link(page)
        else:
            st.page_link(page)
    ok, msg = cached_status()
    html(ui.system_status(ok, msg, now_text()))

current.run()
