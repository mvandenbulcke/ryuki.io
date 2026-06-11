#!/usr/bin/env python3
"""Render docs/*.md to themed HTML pages served on ryuki.io.

GitHub Pages deploys the docs/ folder as-is (no Jekyll — the site is
uploaded by .github/workflows/static.yml), so the markdown sources are
pre-rendered here. Run from the repo root after editing any docs/*.md:

    python3 scripts/md2docs.py

Outputs one <name>.html per markdown file plus documentation.html (the
index). The markdown files stay the source of truth and keep working on
GitHub's web UI; links to docs/<name>.md are rewritten to <name>.html.
"""
import html as html_mod
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

PAGES = [
    ("getting-started", "Getting Started",
     "Prerequisites, database setup, first build and run."),
    ("architecture", "Architecture",
     "The stack, component diagram, key decisions and network policy."),
    ("configuration", "Configuration",
     "Environment variables, providers and platform configuration."),
    ("entra-app-registration", "Entra App Registration",
     "OIDC / OAuth2 app registration and role setup for Entra ID."),
    ("site-management", "Site Management",
     "UN/LOCODE locations, activation and the admin API."),
]


def inline(text: str) -> str:
    """Inline markdown -> HTML (escape first, then spans)."""
    out = html_mod.escape(text, quote=False)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)

    def link(m):
        label, url = m.group(1), m.group(2)
        url = re.sub(r"^(?:docs/)?([\w-]+)\.md$", r"\1.html", url)
        return f'<a href="{url}">{label}</a>'

    return re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link, out)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def convert(md: str) -> str:
    lines = md.splitlines()
    out, i = [], 0
    in_ul = in_ol = False

    def close_lists():
        nonlocal in_ul, in_ol
        if in_ul:
            out.append("</ul>")
            in_ul = False
        if in_ol:
            out.append("</ol>")
            in_ol = False

    while i < len(lines):
        line = lines[i]

        if line.startswith("```"):
            close_lists()
            lang = line[3:].strip()
            block = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                block.append(lines[i])
                i += 1
            i += 1
            cls = f' class="lang-{lang}"' if lang else ""
            out.append(f"<pre><code{cls}>{html_mod.escape(chr(10).join(block), quote=False)}</code></pre>")
            continue

        if line.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|$", lines[i + 1]):
            close_lists()
            cells = [c.strip() for c in line.strip("|").split("|")]
            out.append("<table><thead><tr>" +
                       "".join(f"<th>{inline(c)}</th>" for c in cells) +
                       "</tr></thead><tbody>")
            i += 2
            while i < len(lines) and lines[i].startswith("|"):
                cells = [c.strip() for c in lines[i].strip("|").split("|")]
                out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cells) + "</tr>")
                i += 1
            out.append("</tbody></table>")
            continue

        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            close_lists()
            level = len(m.group(1))
            text = m.group(2)
            out.append(f'<h{level} id="{slug(text)}">{inline(text)}</h{level}>')
            i += 1
            continue

        if re.match(r"^\s*-\s+", line):
            if not in_ul:
                close_lists()
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{inline(re.sub(r'^\\s*-\\s+', '', line))}</li>")
            i += 1
            continue

        if re.match(r"^\s*\d+\.\s+", line):
            if not in_ol:
                close_lists()
                out.append("<ol>")
                in_ol = True
            out.append(f"<li>{inline(re.sub(r'^\\s*\\d+\\.\\s+', '', line))}</li>")
            i += 1
            continue

        if not line.strip():
            close_lists()
            i += 1
            continue

        close_lists()
        para = [line]
        while i + 1 < len(lines) and lines[i + 1].strip() and not re.match(
                r"^(#{1,4}\s|```|\||\s*-\s|\s*\d+\.\s)", lines[i + 1]):
            i += 1
            para.append(lines[i])
        out.append(f"<p>{inline(' '.join(para))}</p>")
        i += 1

    close_lists()
    return "\n".join(out)


TEMPLATE = """<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — Ryuki</title>
<meta name="description" content="{description}">
<link rel="icon" href="/favicon.ico" sizes="32x32">
<link rel="icon" type="image/svg+xml" href="/assets/favicon.svg">
<link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">
<script>
(function(){{
  var k='ryuki-theme',s=null;
  try{{s=localStorage.getItem(k)}}catch(e){{}}
  var mode=s||'system';
  var theme=mode==='system'
    ?(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light')
    :mode;
  var h=document.documentElement;
  h.setAttribute('data-theme',theme);
  h.setAttribute('data-theme-mode',mode);
}})();
</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --font:'Inter',system-ui,sans-serif;
  --mono:'JetBrains Mono',ui-monospace,monospace;
  --radius:10px;--transition:220ms ease;
}}
:root,[data-theme="light"]{{
  --bg:#ffffff;--bg-secondary:#f6f8fb;--text:#14181f;--text-secondary:#525a6b;
  --border:#e2e6ee;--border-strong:#cdd4e0;
  --accent:#8B0000;--accent-bg:#fdeeee;
  --code-bg:#0f1420;--code-text:#d6deeb;--inline-code:#f3eaea;
  --header-bg:rgba(255,255,255,.86);
}}
[data-theme="dark"]{{
  --bg:#0b0d12;--bg-secondary:#11141b;--text:#e7eaf1;--text-secondary:#9aa2b2;
  --border:#222734;--border-strong:#313848;
  --accent:#e25d5d;--accent-bg:#3a1313;
  --code-bg:#0d1119;--code-text:#d6deeb;--inline-code:#1c1517;
  --header-bg:rgba(11,13,18,.86);
}}
body{{font-family:var(--font);background:var(--bg);color:var(--text);
  transition:background var(--transition),color var(--transition);line-height:1.65}}
::selection{{background:var(--accent);color:#fff}}
.site-header{{position:sticky;top:0;z-index:10;background:var(--header-bg);
  -webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px);border-bottom:1px solid var(--border)}}
.header-inner{{max-width:880px;margin:0 auto;padding:0 1.5rem;height:58px;
  display:flex;align-items:center;justify-content:space-between;gap:1rem}}
.brand{{display:flex;align-items:center;gap:.55rem;font-weight:700;font-size:1.08rem;
  letter-spacing:-.02em;color:var(--text);text-decoration:none}}
.brand img{{width:25px;height:25px}}
.brand .io{{color:var(--accent)}}
.header-nav{{display:flex;align-items:center;gap:.9rem;font-size:.85rem}}
.header-nav a{{color:var(--text-secondary);text-decoration:none;font-weight:500}}
.header-nav a:hover{{color:var(--accent)}}
.theme-btn{{display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;
  border:1px solid var(--border-strong);border-radius:8px;background:transparent;
  color:var(--text-secondary);cursor:pointer;padding:0}}
.theme-btn:hover{{color:var(--accent);border-color:var(--accent)}}
.theme-btn svg{{width:16px;height:16px}}
.theme-btn .icon-sun{{display:none}}
[data-theme="dark"] .theme-btn .icon-sun{{display:block}}
[data-theme="dark"] .theme-btn .icon-moon{{display:none}}
main{{max-width:880px;margin:0 auto;padding:2.6rem 1.5rem 5rem}}
.crumb{{font-size:.82rem;margin-bottom:1.6rem}}
.crumb a{{color:var(--accent);text-decoration:none}}
.crumb a:hover{{text-decoration:underline}}
.crumb span{{color:var(--text-secondary)}}
h1{{font-size:2.1rem;letter-spacing:-.02em;margin-bottom:1.2rem}}
h2{{font-size:1.4rem;letter-spacing:-.01em;margin:2.4rem 0 .8rem;
  padding-top:1.2rem;border-top:1px solid var(--border)}}
h3{{font-size:1.08rem;margin:1.8rem 0 .6rem}}
h4{{font-size:.95rem;margin:1.4rem 0 .5rem}}
p{{margin:.85rem 0;color:var(--text-secondary)}}
p strong{{color:var(--text)}}
li strong{{color:var(--text)}}
a{{color:var(--accent)}}
ul,ol{{margin:.85rem 0 .85rem 1.4rem;color:var(--text-secondary)}}
li{{margin:.35rem 0}}
code{{font-family:var(--mono);font-size:.86em;background:var(--inline-code);
  padding:.12em .38em;border-radius:5px}}
pre{{background:var(--code-bg);color:var(--code-text);border-radius:var(--radius);
  padding:1.1rem 1.2rem;overflow-x:auto;margin:1rem 0;font-size:.84rem;line-height:1.55}}
pre code{{background:none;padding:0;font-size:1em;color:inherit}}
table{{width:100%;border-collapse:collapse;margin:1rem 0;font-size:.9rem}}
th,td{{text-align:left;padding:.55rem .8rem;border:1px solid var(--border)}}
th{{background:var(--bg-secondary)}}
td code{{white-space:nowrap}}
.doc-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));
  gap:1rem;margin-top:1.8rem}}
.doc-card{{display:block;border:1px solid var(--border);border-radius:var(--radius);
  padding:1.15rem 1.25rem;text-decoration:none;
  transition:border-color var(--transition),background var(--transition)}}
.doc-card:hover{{border-color:var(--accent);background:var(--accent-bg)}}
.doc-card h2{{font-size:1.02rem;margin:0 0 .35rem;padding:0;border:0;color:var(--text)}}
.doc-card p{{font-size:.85rem;margin:0;color:var(--text-secondary)}}
.foot-nav{{display:flex;justify-content:space-between;gap:1rem;margin-top:3rem;
  padding-top:1.4rem;border-top:1px solid var(--border);font-size:.88rem}}
.foot-nav a{{text-decoration:none;font-weight:600}}
</style>
</head>
<body>
<header class="site-header">
  <div class="header-inner">
    <a href="/" class="brand"><img src="/assets/logo.svg" alt="Ryuki logo"><span>ryuki<span class="io">.io</span></span></a>
    <nav class="header-nav">
      <a href="/documentation.html">Docs</a>
      <a href="https://github.com/mvandenbulcke/ryuki.io" target="_blank" rel="noopener">GitHub</a>
      <button class="theme-btn" id="theme-toggle" aria-label="Toggle theme" title="Toggle theme">
        <svg class="icon-sun" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
        <svg class="icon-moon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
      </button>
    </nav>
  </div>
</header>
<main>
{crumb}
{content}
{footnav}
</main>
<script>
(function(){{
  var html=document.documentElement;
  var btn=document.getElementById('theme-toggle');
  function prefers(){{return window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'}}
  function resolve(mode){{return mode==='system'||!mode?prefers():mode}}
  function apply(mode){{
    html.setAttribute('data-theme-mode',mode);
    html.setAttribute('data-theme',resolve(mode));
    btn.title='Theme: '+mode;
  }}
  btn.addEventListener('click',function(){{
    var cur=html.getAttribute('data-theme-mode');
    var next=cur==='system'
      ?(resolve('system')==='dark'?'light':'dark')
      :cur==='light'?'dark':'system';
    try{{localStorage.setItem('ryuki-theme',next)}}catch(e){{}}
    apply(next);
  }});
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change',function(){{
    if(html.getAttribute('data-theme-mode')==='system') apply('system');
  }});
}})();
</script>
</body>
</html>
"""


def render(name, title, description, content, crumb, footnav):
    return TEMPLATE.format(title=title, description=description,
                           content=content, crumb=crumb, footnav=footnav)


def main():
    for idx, (name, title, description) in enumerate(PAGES):
        src = DOCS / f"{name}.md"
        if not src.exists():
            sys.exit(f"missing {src}")
        body = convert(src.read_text())
        crumb = '<nav class="crumb"><a href="/documentation.html">Documentation</a> <span>/ ' + title + "</span></nav>"
        prev_page = PAGES[idx - 1] if idx > 0 else None
        next_page = PAGES[idx + 1] if idx + 1 < len(PAGES) else None
        left = f'<a href="/{prev_page[0]}.html">&larr; {prev_page[1]}</a>' if prev_page else "<span></span>"
        right = f'<a href="/{next_page[0]}.html">{next_page[1]} &rarr;</a>' if next_page else "<span></span>"
        footnav = f'<nav class="foot-nav">{left}{right}</nav>'
        (DOCS / f"{name}.html").write_text(
            render(name, title, description, body, crumb, footnav))
        print(f"docs/{name}.html")

    cards = "\n".join(
        f'<a class="doc-card" href="/{name}.html"><h2>{title}</h2><p>{description}</p></a>'
        for name, title, description in PAGES)
    index_content = ("<h1>Documentation</h1>"
                     "<p>Everything you need to run Ryuki — the governed control plane "
                     "for multi-site infrastructure.</p>"
                     f'<div class="doc-grid">{cards}</div>')
    (DOCS / "documentation.html").write_text(
        render("documentation", "Documentation", "Ryuki platform documentation.",
               index_content, "", ""))
    print("docs/documentation.html")


if __name__ == "__main__":
    main()
