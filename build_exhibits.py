#!/usr/bin/env python3
"""
Generates one standalone HTML page per "Exhibit" section from index.html,
into exhibits/. Reuses the exact same <style> block (self-contained, no
external CSS deps besides Google Fonts) so visuals match exactly. index.html
itself is NOT modified in structure/content by this script — additive only.

Boundaries are found by text search + brace-depth scanning (not hardcoded
line numbers), so this is safe to re-run after index.html changes elsewhere.
"""
import os
import re

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "index.html")
OUT_DIR = os.path.join(ROOT, "exhibits")
os.makedirs(OUT_DIR, exist_ok=True)

with open(SRC, "r", encoding="utf-8") as f:
    TEXT = f.read()

def find_enclosing_section(text, needle):
    """Given a unique substring `needle`, find the nearest preceding
    '<div class="section"' (with or without extra attrs) and return the
    (start, end) character offsets of that whole <div>...</div> block,
    matched by counting nested <div ...> / </div> tags."""
    idx = text.index(needle)
    start = text.rfind('<div class="section"', 0, idx)
    if start == -1:
        raise ValueError("no enclosing .section div found for: " + needle[:60])
    # scan forward from start, counting div open/close tags
    depth = 0
    pos = start
    div_open_re = re.compile(r'<div\b')
    div_close_re = re.compile(r'</div>')
    while True:
        next_open = div_open_re.search(text, pos)
        next_close = div_close_re.search(text, pos)
        if next_close is None:
            raise ValueError("unbalanced divs while scanning from: " + needle[:60])
        if next_open and next_open.start() < next_close.start():
            depth += 1
            pos = next_open.end()
        else:
            depth -= 1
            pos = next_close.end()
            if depth == 0:
                return start, pos
    raise ValueError("unreachable")

def extract_head_meta():
    m = re.search(r'<title>.*?</title>\s*\n', TEXT)
    head_start = TEXT.index("<head>") + len("<head>")
    title_start, title_end = m.start(), m.end()
    stylestart = TEXT.index("<style>")
    meta = TEXT[head_start:title_start] + TEXT[title_end:stylestart]
    return meta.strip("\n")

def extract_style_block():
    s = TEXT.index("<style>") + len("<style>")
    e = TEXT.index("</style>")
    return TEXT[s:e]

def extract_footer():
    s = TEXT.index('<footer class="footer">')
    e = TEXT.index("</footer>") + len("</footer>")
    return TEXT[s:e]

HEAD_META = extract_head_meta()
STYLE_BLOCK = extract_style_block()
FOOTER_HTML = extract_footer()

# (slug, filename, unique needle text inside the section, page_title)
EXHIBITS = [
    ("01", "01-the-problem.html",      "Exhibit 01 — The problem",           "The problem"),
    ("02", "02-how-it-works.html",     "Exhibit 02 — How it works",          "How it works"),
    ("03", "03-cross-checks.html",     "Exhibit 03 — Real-time cross-checks","Real-time cross-checks"),
    ("05", "05-where-it-fits.html",    "Exhibit 05 — Where it fits",         "Where it fits"),
    ("06", "06-what-it-catches.html",  "Exhibit 06 — What it catches",       "What it catches"),
    ("07", "07-under-the-hood.html",   "Exhibit 07 — Under the hood",        "Under the hood"),
    ("08", "08-architecture.html",     "Exhibit 08 — Architecture",          "Architecture"),
    ("09", "09-projected-impact.html", "Exhibit 09 — Projected impact",      "Projected impact"),
    ("10", "10-faq.html",              "Exhibit 10 — Questions officers ask","Questions officers ask"),
    ("11", "11-team.html",             "Exhibit 11 — Team",                  "Team"),
]

TOPBAR = '''<header class="topbar">
  <div class="wrap topbar-inner">
    <a class="brand" href="../index.html" style="text-decoration:none;color:inherit;">
      <svg class="brand-mark" viewBox="0 0 26 26" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <path d="M13 2 L23 6 V13 C23 19 18.5 23 13 24.5 C7.5 23 3 19 3 13 V6 Z" stroke="var(--accent-strong)" stroke-width="1.6" fill="var(--accent-soft)"/>
        <path d="M8.5 13.2 L11.5 16.2 L18 9.5" stroke="var(--accent-strong)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
      </svg>
      VeriScanx<small>SIH&nbsp;2026</small>
    </a>
    <nav class="tabs" role="navigation" aria-label="Sections">
      <a class="tab-btn" href="../index.html" style="text-decoration:none;"><span class="tab-label">Overview</span></a>
      <a class="tab-btn" href="../index.html" style="text-decoration:none;"><span class="tab-label">Live Demo</span></a>
      <a class="tab-btn" href="../index.html" style="text-decoration:none;"><span class="tab-label">Dashboard</span></a>
    </nav>
    <div class="nav-cta-wrap">
      <a class="btn btn-primary btn-sm nav-cta" href="../index.html" style="text-decoration:none;">Try Live Demo</a>
    </div>
  </div>
</header>'''

PAGE_TMPL = '''<!DOCTYPE html>
<html lang="en">
<head>
{head_meta}
<title>Exhibit {slug} — {page_title} — VeriScanx</title>
<style>
{style_block}
.exhibit-crumb{{ font-family:var(--font-mono); font-size:12.5px; color:var(--ink-3); text-decoration:none; display:inline-flex; align-items:center; gap:6px; }}
.exhibit-crumb:hover{{ color:var(--ink); }}
.exhibit-pager{{ display:flex; justify-content:space-between; gap:16px; margin:56px 0 72px; padding-top:24px; border-top:1px solid var(--border); }}
.exhibit-pager a{{ font-family:var(--font-mono); font-size:12.5px; color:var(--ink-2); text-decoration:none; display:flex; align-items:center; gap:6px; }}
.exhibit-pager a:hover{{ color:var(--accent-strong); }}
.exhibit-pager .next{{ margin-left:auto; text-align:right; }}
</style>
</head>
<body>
{topbar}
<main class="wrap" style="padding-top:36px; min-height:60vh;">
  <a class="exhibit-crumb" href="../index.html">&larr; Back to overview</a>
  {section_html}
  <div class="exhibit-pager">
    {prev_link}
    {next_link}
  </div>
</main>
{footer_html}
{extra_js}
</body>
</html>
'''

FAQ_JS = '''<script>
document.querySelectorAll('.faq-item').forEach(function(item){
  var q = item.querySelector('.faq-q');
  if(!q) return;
  q.addEventListener('click', function(){
    var open = item.getAttribute('data-open') === 'true';
    item.setAttribute('data-open', open ? 'false' : 'true');
  });
});
</script>'''

n = len(EXHIBITS)
for i, (slug, fname, needle, title) in enumerate(EXHIBITS):
    start, end = find_enclosing_section(TEXT, needle)
    section_html = TEXT[start:end]
    # Strip the self-referencing "Open as page" link — redundant on its own page.
    section_html = re.sub(r'<a class="exhibit-open-link"[^>]*>.*?</a>', '', section_html)

    if i > 0:
        p_slug, p_fname, _, p_title = EXHIBITS[i-1]
        prev_link = '<a href="{f}">&larr; Exhibit {s} — {t}</a>'.format(f=p_fname, s=p_slug, t=p_title)
    else:
        prev_link = '<a href="../index.html">&larr; Back to overview</a>'
    if i < n - 1:
        n_slug, n_fname, _, n_title = EXHIBITS[i+1]
        next_link = '<a class="next" href="{f}">Exhibit {s} — {t} &rarr;</a>'.format(f=n_fname, s=n_slug, t=n_title)
    else:
        next_link = '<a class="next" href="../index.html">Back to overview &rarr;</a>'

    extra_js = FAQ_JS if slug == "10" else ""

    html = PAGE_TMPL.format(
        head_meta=HEAD_META,
        slug=slug,
        page_title=title,
        style_block=STYLE_BLOCK,
        topbar=TOPBAR,
        section_html=section_html,
        prev_link=prev_link,
        next_link=next_link,
        footer_html=FOOTER_HTML,
        extra_js=extra_js,
    )
    out_path = os.path.join(OUT_DIR, fname)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print("wrote", out_path, len(html), "bytes")

print("\nDone —", n, "exhibit pages written to", OUT_DIR)
