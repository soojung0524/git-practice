"""화면 조각(HTML)과 스타일. 값만 받아 HTML 문자열을 돌려주는 순수 함수들이다.

Streamlit 의 markdown 은 들여쓰기된 HTML 을 코드 블록으로 바꿔 버리므로,
모든 조각은 줄바꿈 없는 한 줄 문자열로 만든다(_h 함수).
"""

from __future__ import annotations

import html

E = html.escape

# ───────────────────────── 색 ─────────────────────────
BLUE = "#2563eb"
RISK = {  # 위험 단계: 라벨, 단계 번호, 글자색, 배경색
    "critical": ("긴급", 5, "#ffffff", "#dc2626"),
    "high": ("높음", 4, "#ffffff", "#ea580c"),
    "medium": ("주의", 3, "#1f2937", "#fbbf24"),
    "low": ("낮음", 2, "#1f2937", "#e5e7eb"),
    "none": ("정상", 1, "#ffffff", "#16a34a"),
}
STATUS = {  # 상태 카드 항목: 글자, 아이콘 색
    "ok": ("정상", "#16a34a"),
    "warn": ("경고", "#f59e0b"),
    "bad": ("장애", "#dc2626"),
}

# ───────────────────────── 아이콘 (선 아이콘, currentColor) ─────────────────────────
_ICON_PATHS = {
    "shield": '<path d="M12 3l7 3v6c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/>',
    "server": '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/>'
              '<path d="M7 7.5h.01M7 16.5h.01"/>',
    "network": '<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/>'
               '<path d="M12 7.5v4M12 11.5l-5.2 5.4M12 11.5l5.2 5.4"/>',
    "terminal": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>',
    "book": '<path d="M4 5a2 2 0 012-2h13v16H6a2 2 0 00-2 2V5z"/><path d="M8 7h7M8 11h7"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "file": '<path d="M14 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V9z"/><path d="M14 3v6h6M8 13h8M8 17h6"/>',
    "alert": '<path d="M12 3.5l9 16H3l9-16z"/><path d="M12 10v4M12 17h.01"/>',
    "check": '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
    "search": '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/>',
    "list": '<path d="M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01"/>',
}


def icon(name: str, size: int = 18, color: str = "currentColor") -> str:
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" '
            f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            f'{_ICON_PATHS[name]}</svg>')


def _h(*parts: str) -> str:
    return "".join(p.replace("\n", " ") for p in parts)


# ───────────────────────── 스타일 ─────────────────────────
CSS = _h("""<style>
.block-container{padding-top:4.5rem;max-width:1500px}
section[data-testid="stSidebar"]{background:#0b1736}
section[data-testid="stSidebar"] *{color:#d7def0}
section[data-testid="stSidebar"] a[data-testid="stPageLink-NavLink"]{border-radius:8px;padding:.35rem .7rem;margin:1px 0}
section[data-testid="stSidebar"] a[data-testid="stPageLink-NavLink"]:hover{background:rgba(255,255,255,.08)}
section[data-testid="stSidebar"] .st-key-navactive a{background:#2563eb !important}
section[data-testid="stSidebar"] .st-key-navactive a *{color:#fff !important;font-weight:600}
.sx-brand{display:flex;gap:10px;align-items:center;padding:4px 2px 18px 2px}
.sx-brand .t1{font-weight:700;font-size:.95rem;color:#fff !important}
.sx-brand .t2{font-size:.72rem;opacity:.75}
.sx-sys{display:flex;gap:8px;align-items:flex-start;font-size:.8rem;margin-top:28px;padding-top:14px;border-top:1px solid rgba(255,255,255,.12)}
.sx-dot{width:9px;height:9px;border-radius:50%;margin-top:5px;flex:none}
.sx-head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:18px}
.sx-head .l{display:flex;gap:14px;align-items:center;min-width:0}
.sx-head .h1{font-size:1.55rem;font-weight:800;line-height:1.35;margin:0;padding:0;color:#0f172a;word-break:keep-all}
.sx-head p{margin:2px 0 0 0;color:#475569;font-size:.88rem}
.sx-head .r{color:#334155;font-size:.85rem;white-space:nowrap;padding-top:6px}
.sx-card{background:#fff;border:1px solid #e5e9f2;border-radius:12px;padding:16px 18px;margin-bottom:12px;box-shadow:0 1px 2px rgba(15,23,42,.04)}
.sx-ct{display:flex;align-items:center;gap:8px;font-weight:700;color:#0f172a;font-size:.95rem;margin-bottom:12px}
.sx-ct .ic{color:#2563eb;display:flex}
.sx-ct .badge{margin-left:auto}
.sx-sub{display:flex;align-items:center;gap:6px;font-weight:700;font-size:.84rem;color:#1e293b;margin:12px 0 6px}
.sx-card ul.sx-ul,.sx-call ul.sx-ul{margin:0;padding-left:1.1rem}.sx-card ul.sx-ul li,.sx-call ul.sx-ul li{color:#334155;font-size:.84rem;line-height:1.65;margin:0 0 2px;padding:0}
.sx-card ul.sx-ul li::marker{color:#2563eb}
.sx-card p.sx-p{color:#334155;font-size:.85rem;line-height:1.65;margin:0 0 6px}
.sx-card p.sx-muted,p.sx-muted,.sx-muted{color:#64748b;font-size:.8rem}
.sx-stats{display:flex;gap:6px}
.sx-stat{flex:1;padding:2px 4px}
.sx-stat .lb{display:flex;align-items:center;gap:5px;font-size:.78rem;color:#475569}
.sx-stat .n{font-size:1.45rem;font-weight:800;color:#0f172a;margin-top:2px}
.sx-mark{width:15px;height:15px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;color:#fff;font-size:10px;font-weight:800;line-height:1}
.sx-banner{display:flex;gap:16px;align-items:flex-start;background:#fff5f5;border:1px solid #fecaca;border-radius:12px;padding:18px 20px;margin-bottom:14px}
.sx-banner.ok{background:#f0fdf4;border-color:#bbf7d0}
.sx-banner .ico{width:44px;height:44px;border-radius:50%;background:#dc2626;color:#fff;display:flex;align-items:center;justify-content:center;flex:none}
.sx-banner.ok .ico{background:#16a34a}
.sx-banner .main{flex:1;min-width:0}
.sx-banner .cat{color:#dc2626;font-weight:700;font-size:.8rem}
.sx-banner.ok .cat{color:#15803d}
.sx-banner .ttl{font-size:1.2rem;font-weight:800;line-height:1.4;color:#0f172a;margin:2px 0 6px;word-break:keep-all;overflow-wrap:anywhere}
.sx-banner .desc{color:#475569;font-size:.85rem;line-height:1.6}
.sx-meta{display:flex;gap:26px;flex:none}
.sx-meta .k{font-size:.74rem;color:#64748b}
.sx-meta .v{font-size:.86rem;font-weight:700;color:#0f172a;margin-top:4px;white-space:nowrap}
.sx-risk{display:inline-flex;flex-direction:column;align-items:center;gap:4px}
.sx-risk .k{font-size:.72rem;color:#64748b}
.sx-rbig{flex:none;width:150px;border-radius:12px;padding:12px 14px 12px;text-align:center;color:#fff;box-shadow:0 2px 8px rgba(15,23,42,.12)}.sx-rbig .k{font-size:.74rem;font-weight:600;opacity:.92;letter-spacing:.02em}.sx-rbig .lv{font-size:2.3rem;font-weight:800;line-height:1.05;margin-top:4px}.sx-rbig .lv small{font-size:.95rem;font-weight:700;margin-left:2px;opacity:.9}.sx-rbig .lb{font-size:1.05rem;font-weight:800;margin-top:2px}.sx-rbig .gauge{display:flex;gap:3px;margin-top:9px}.sx-rbig .gauge i{flex:1;height:6px;border-radius:3px;background:rgba(255,255,255,.35)}.sx-rbig .gauge i.on{background:#fff}.sx-banner .sx-rbig{align-self:center}.sx-dtop{display:flex;gap:20px;align-items:center;justify-content:space-between;margin-bottom:14px}.sx-dtop .l{min-width:0;flex:1}.sx-pill{display:inline-block;border-radius:6px;padding:3px 10px;font-size:.8rem;font-weight:700;white-space:nowrap}
.sx-done{white-space:nowrap;display:inline-flex;align-items:center;gap:4px;background:#ecfdf5;color:#15803d;border-radius:6px;padding:2px 8px;font-size:.74rem;font-weight:700}
.sx-tl{position:relative;margin-left:4px}
.sx-tl .it{display:flex;gap:12px;position:relative;padding-bottom:14px}
.sx-tl .it:not(:last-child)::before{content:"";position:absolute;left:5px;top:14px;bottom:0;border-left:2px solid #dbe4f3}
.sx-tl .dt{width:12px;height:12px;border-radius:50%;background:#2563eb;margin-top:4px;flex:none;box-shadow:0 0 0 3px #dbeafe}
.sx-tl .it.cur .dt{background:#dc2626;box-shadow:0 0 0 3px #fee2e2}
.sx-tl .tm{font-size:.78rem;color:#475569;width:46px;flex:none;padding-top:1px}
.sx-tl .tt{font-size:.82rem;font-weight:600;color:#0f172a}
.sx-tl .ts{font-size:.74rem;color:#64748b;margin-top:1px}
.sx-refs{display:flex;flex-direction:column;gap:6px}
.sx-ref{display:flex;gap:10px;align-items:center;font-size:.8rem;color:#334155}
.sx-ref .pg{background:#eff4ff;color:#1d4ed8;font-weight:700;border-radius:6px;padding:3px 8px;flex:none;min-width:66px;white-space:nowrap;text-align:center}
.sx-steps{display:flex;flex-direction:column;gap:8px;margin:6px 0 4px}
.sx-step{display:flex;gap:10px;font-size:.84rem;color:#1e293b;line-height:1.5}
.sx-step .no{width:22px;height:22px;border-radius:50%;background:#2563eb;color:#fff;font-size:.74rem;font-weight:700;display:flex;align-items:center;justify-content:center;flex:none}
.sx-call{border-radius:10px;padding:12px 14px;margin:12px 0 4px}
.sx-call.warn{background:#fffbeb;border:1px solid #fde68a}
.sx-call.ok{background:#f0fdf4;border:1px solid #bbf7d0}
.sx-call.info{background:#f8fafc;border:1px solid #e2e8f0}
.sx-call .h{display:flex;gap:6px;align-items:center;font-weight:700;font-size:.84rem;margin-bottom:4px}
.sx-call.warn .h{color:#b45309}
.sx-call.ok .h{color:#15803d}
.sx-call.info .h{color:#334155}
.sx-chips{display:flex;flex-wrap:wrap;gap:8px;margin:2px 0 12px}
.sx-chip{background:#fff;border:1px solid #e5e9f2;border-radius:999px;padding:4px 12px;font-size:.8rem;color:#334155}
.sx-chip b{color:#0f172a}
.sx-title{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.sx-title .tx{font-size:1.35rem;font-weight:800;line-height:1.4;color:#0f172a;word-break:keep-all;overflow-wrap:anywhere}
.sx-mrow{display:flex;gap:22px;flex-wrap:wrap;color:#475569;font-size:.82rem;margin:8px 0 16px}
.sx-mrow b{color:#0f172a;font-weight:600;margin-left:6px}
</style>""")


# ───────────────────────── 공통 조각 ─────────────────────────
def risk_pill(severity: str | None) -> str:
    label, _, fg, bg = RISK.get(severity or "none", RISK["none"])
    return f'<span class="sx-pill" style="background:{bg};color:{fg}">{label}</span>'


def risk_box(severity: str | None) -> str:
    """크게 보여주는 위험 단계 블록: 단계 숫자, 라벨, 5칸 게이지."""
    label, level, fg, bg = RISK.get(severity or "none", RISK["none"])
    gauge = "".join(f'<i class="{"on" if i <= level else ""}"></i>' for i in range(1, 6))
    # 밝은 배경(주의·낮음)은 글자와 게이지를 어둡게
    dark = fg != "#ffffff"
    style = f"background:{bg};color:{fg}"
    if dark:
        gauge = gauge.replace('class="on"', 'class="on" style="background:#1f2937"').replace(
            'class=""', 'class="" style="background:rgba(31,41,55,.18)"')
    return _h(f'<div class="sx-rbig" style="{style}"><div class="k">위험 단계</div>'
              f'<div class="lv">{level}<small>/5</small></div><div class="lb">{E(label)}</div>'
              f'<div class="gauge">{gauge}</div></div>')


def done_badge(text: str) -> str:
    return f'<span class="sx-done">✓ {E(text)}</span>'


def card(title: str, ic: str, body: str, badge: str = "") -> str:
    b = f'<span class="badge">{badge}</span>' if badge else ""
    return _h(f'<div class="sx-card"><div class="sx-ct"><span class="ic">{icon(ic)}</span>{E(title)}{b}</div>{body}</div>')


def bullets(items: list[str]) -> str:
    if not items:
        return '<p class="sx-muted">내용 없음</p>'
    return "<ul class='sx-ul'>" + "".join(f"<li>{E(i)}</li>" for i in items) + "</ul>"


def sub(title: str, ic: str = "search") -> str:
    return f'<div class="sx-sub">{icon(ic, 15, BLUE)}{E(title)}</div>'


def paragraphs(items: list[str]) -> str:
    return "".join(f'<p class="sx-p">{E(i)}</p>' for i in items)


# ───────────────────────── 사이드바 ─────────────────────────
def brand() -> str:
    return _h(f'<div class="sx-brand">{icon("shield", 30, "#60a5fa")}<div><div class="t1">AWS Security Response</div>'
              f'<div class="t2">AI 기반 AWS 보안 사고 대응</div></div></div>')


def system_status(ok: bool, message: str, when: str) -> str:
    color = "#22c55e" if ok else "#f59e0b"
    return _h(f'<div class="sx-sys"><span class="sx-dot" style="background:{color}"></span>'
              f'<div><div>{E(message)}</div><div style="opacity:.6;font-size:.72rem">{E(when)}</div></div></div>')


# ───────────────────────── 홈 ─────────────────────────
def page_header(title: str, subtitle: str, right: str = "") -> str:
    return _h(f'<div class="sx-head"><div class="l">{icon("shield", 46, BLUE)}<div><div class="h1">{E(title)}</div>'
              f'<p>{E(subtitle)}</p></div></div><div class="r">{E(right)}</div></div>')


def banner(*, category: str, title: str, desc: str, occurred: str, updated: str, severity: str | None) -> str:
    ok = severity is None
    return _h(
        f'<div class="sx-banner{" ok" if ok else ""}"><div class="ico">{icon("check" if ok else "alert", 24, "#fff")}</div>'
        f'<div class="main"><div class="cat">{E(category)}</div><div class="ttl">{E(title)}</div>'
        f'<div class="desc">{E(desc)}</div></div>'
        f'<div class="sx-meta"><div><div class="k">발생 일시</div><div class="v">{E(occurred)}</div></div>'
        f'<div><div class="k">마지막 업데이트</div><div class="v">{E(updated)}</div></div></div>'
        f'{risk_box(severity)}</div>')


def status_card(title: str, ic: str, counts: dict[str, int] | None, note: str = "") -> str:
    """counts = {"ok":n, "warn":n, "bad":n}. None 이면 해당 영역을 분석하지 않은 것."""
    if counts is None:
        body = f'<p class="sx-muted">{E(note or "이번 분석에서 실행되지 않았습니다.")}</p>'
    else:
        cells = []
        for key in ("ok", "warn", "bad"):
            label, color = STATUS[key]
            mark = {"ok": "✓", "warn": "!", "bad": "×"}[key]
            cells.append(f'<div class="sx-stat"><div class="lb"><span class="sx-mark" style="background:{color}">{mark}</span>'
                         f'{label}</div><div class="n">{counts.get(key, 0)}</div></div>')
        body = f'<div class="sx-stats">{"".join(cells)}</div>'
        if note:
            body += f'<p class="sx-muted" style="margin:8px 0 0">{E(note)}</p>'
    return card(title, ic, body)


def timeline(items: list[dict], title: str = "타임라인") -> str:
    """items: [{"time","title","sub","current"}]"""
    if not items:
        return card(title, "clock", '<p class="sx-muted">표시할 항목이 없습니다.</p>')
    rows = "".join(
        f'<div class="it{" cur" if it.get("current") else ""}"><span class="dt"></span>'
        f'<span class="tm">{E(it["time"])}</span><div><div class="tt">{E(it["title"])}</div>'
        f'<div class="ts">{E(it.get("sub", ""))}</div></div></div>'
        for it in items)
    return card(title, "clock", f'<div class="sx-tl">{rows}</div>')


def refs(rows: list[dict], note: str = "AWS Security Incident Response User Guide") -> str:
    if not rows:
        body = '<p class="sx-muted">보안상 주의사항을 만들면 참고한 페이지가 여기에 표시됩니다.</p>'
    else:
        items = "".join(
            f'<div class="sx-ref"><span class="pg">Page {E(str(r["page"]))}</span>'
            f'<span>{E(r.get("section") or "")}</span></div>' for r in rows)
        body = f'<p class="sx-muted" style="margin:-4px 0 10px">{E(note)}</p><div class="sx-refs">{items}</div>'
    return card("참고 문서 및 페이지", "file", body)


def steps(items: list[str]) -> str:
    return '<div class="sx-steps">' + "".join(
        f'<div class="sx-step"><span class="no">{i}</span><span>{E(t)}</span></div>'
        for i, t in enumerate(items, 1)) + "</div>"


def callout(kind: str, title: str, items: list[str]) -> str:
    ic = {"warn": "alert", "ok": "shield", "info": "list"}[kind]
    return _h(f'<div class="sx-call {kind}"><div class="h">{icon(ic, 16)}{E(title)}</div>{bullets(items)}</div>')


def chips(items: list[tuple[str, str]]) -> str:
    return '<div class="sx-chips">' + "".join(f'<span class="sx-chip">{E(k)} <b>{E(v)}</b></span>' for k, v in items) + "</div>"


def detail_title(severity: str, title: str, meta: list[tuple[str, str]]) -> str:
    m = "".join(f"<span>{E(k)}<b>{E(v)}</b></span>" for k, v in meta)
    return _h(f'<div class="sx-dtop"><div class="l"><div class="sx-title">{risk_pill(severity)}'
              f'<span class="tx">{E(title)}</span></div><div class="sx-mrow" style="margin-bottom:0">{m}</div></div>'
              f'{risk_box(severity)}</div>')
