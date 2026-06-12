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
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — Ryuki</title>
<meta name="description" content="{description}">
<link rel="icon" href="/favicon.ico" sizes="32x32">
<link rel="icon" type="image/svg+xml" href="/assets/favicon.svg">
<link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">
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
:root{{
  --bg:#0b0d12;--bg-secondary:#11141b;--text:#e7eaf1;--text-secondary:#9aa2b2;
  --border:#222734;--border-strong:#313848;
  --accent:#e25d5d;--accent-bg:#3a1313;--logo-red:#c0392b;--logo-gold:#FFD700;
  --code-bg:#0d1119;--code-text:#d6deeb;--inline-code:#1c1517;
  --header-bg:rgba(11,13,18,.86);
}}
@media (prefers-reduced-motion: no-preference){{html{{scroll-behavior:smooth}}}}
body{{font-family:var(--font);background:var(--bg);color:var(--text);
  transition:background var(--transition),color var(--transition);line-height:1.65}}
::selection{{background:var(--accent);color:#fff}}
.site-header{{position:sticky;top:0;z-index:10;background:var(--header-bg);
  -webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px);border-bottom:1px solid var(--border)}}
.header-inner{{max-width:1140px;margin:0 auto;padding:0 1.5rem;height:58px;
  display:flex;align-items:center;justify-content:space-between;gap:1rem}}
.brand{{display:flex;align-items:center;gap:.55rem;font-weight:700;font-size:1.08rem;
  letter-spacing:-.02em;color:var(--text);text-decoration:none}}
.brand .mark{{width:25px;height:25px}}
.brand .io{{color:var(--accent)}}
.header-nav{{display:flex;align-items:center;gap:.9rem;font-size:.85rem}}
.header-nav a{{color:var(--text-secondary);text-decoration:none;font-weight:500}}
.header-nav a:hover{{color:var(--accent)}}
/* ── Docs shell: sticky left nav + content column ── */
.docs-shell{{max-width:1140px;margin:0 auto;padding:0 1.5rem;
  display:grid;grid-template-columns:240px minmax(0,1fr);gap:2.8rem;align-items:start}}
main{{min-width:0;max-width:820px;padding:2.6rem 0 5rem}}
.docs-sidebar{{position:sticky;top:58px;max-height:calc(100vh - 58px);overflow-y:auto;
  padding:1.9rem 1.2rem 2rem 0;border-right:1px solid var(--border)}}
.sb-label{{display:block;font-size:.68rem;font-weight:700;text-transform:uppercase;
  letter-spacing:.09em;color:var(--text-secondary);text-decoration:none;margin-bottom:.75rem}}
.sb-label:hover{{color:var(--accent)}}
.sb-label.active{{color:var(--accent)}}
.sb-list{{list-style:none;margin:0;padding:0}}
.sb-list>li{{margin:0}}
.sb-link{{display:block;font-size:.85rem;font-weight:500;color:var(--text-secondary);
  text-decoration:none;padding:.36rem .65rem;border-left:2px solid transparent;
  border-radius:0 6px 6px 0;
  transition:color var(--transition),background var(--transition),border-color var(--transition)}}
.sb-link:hover{{color:var(--text);background:var(--bg-secondary)}}
.sb-link.active{{color:var(--accent);font-weight:600;border-left-color:var(--accent);background:var(--accent-bg)}}
.sb-sections{{list-style:none;margin:.2rem 0 .5rem .65rem;padding:0 0 0 .55rem;
  border-left:1px solid var(--border)}}
.sb-sections li{{margin:0}}
.sb-sections a{{display:block;font-size:.78rem;color:var(--text-secondary);text-decoration:none;
  padding:.24rem .55rem;border-radius:5px;
  transition:color var(--transition),background var(--transition)}}
.sb-sections a:hover{{color:var(--text);background:var(--bg-secondary)}}
.sb-sections a.active{{color:var(--accent);font-weight:600}}
.sb-toggle{{display:none}}
@media(max-width:940px){{
  table{{display:block;overflow-x:auto}}
  .docs-shell{{display:block}}
  main{{max-width:760px;margin:0 auto;padding:2rem 0 4rem}}
  .sb-toggle{{display:flex;align-items:center;justify-content:space-between;width:100%;
    background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;
    font-family:var(--font);font-size:.85rem;font-weight:600;color:var(--text);
    padding:.6rem .9rem;margin-top:1rem;cursor:pointer}}
  .sb-toggle svg{{width:14px;height:14px;transition:transform .2s ease}}
  .sb-toggle[aria-expanded="true"] svg{{transform:rotate(180deg)}}
  .docs-sidebar{{display:none;position:static;max-height:none;border-right:0;
    padding:1rem .2rem .6rem;border-bottom:1px solid var(--border)}}
  .docs-sidebar.open{{display:block}}
}}
h1,h2,h3,h4{{scroll-margin-top:74px}}
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
.pre-wrap{{position:relative}}
.copy-code{{position:absolute;top:.5rem;right:.5rem;
  background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);
  color:#aeb7c7;font-family:var(--font);font-size:.68rem;font-weight:600;
  border-radius:6px;padding:.25rem .6rem;cursor:pointer;opacity:0;
  transition:opacity var(--transition),background var(--transition)}}
.pre-wrap:hover .copy-code,.copy-code:focus-visible{{opacity:1}}
@media (hover:none){{.copy-code{{opacity:1}}}}
.copy-code:hover{{background:rgba(255,255,255,.14);color:#fff}}
.copy-code.done{{color:#34c98e;border-color:rgba(52,201,142,.4)}}
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
    <a href="/" class="brand"><svg class="mark" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M 35.5 15.3 A 20 20 0 1 0 50.0 26.2" fill="none" stroke="var(--logo-red)" stroke-width="7.5" stroke-linecap="round"/>
  <path d="M 15.5 18.5 L 6.8 19.7 M 8.6 35.0 L 3.3 42.0 M 15.5 51.5 L 16.7 60.2" fill="none" stroke="var(--logo-red)" stroke-width="2.7" stroke-linecap="round"/>
  <path d="M 35.5 15.3 C 31.5 10.8 27.0 9.3 22.5 10.3" fill="none" stroke="var(--logo-red)" stroke-width="3" stroke-linecap="round"/>
  <path d="M 46.5 24.5 L 43 18.5 L 44.5 14 L 40 9 L 46 10.5 L 50.5 4.5 L 51.5 11.5 L 57 13 L 53.5 17.5 L 53.8 22.5 Z" fill="var(--logo-red)"/>
  <circle cx="48.4" cy="13.2" r="1.6" fill="var(--logo-gold)"/>
  <circle cx="32" cy="35" r="5.8" fill="var(--logo-gold)"/>
</svg><span>ryuki<span class="io">.io</span></span></a>
    <nav class="header-nav">
      <a href="/documentation.html">Docs</a>
      <a href="https://github.com/mvandenbulcke/ryuki.io" target="_blank" rel="noopener">GitHub</a>
    </nav>
  </div>
</header>
<div class="docs-shell">
{sidebar}
<main>
{crumb}
{content}
{footnav}
</main>
</div>
<script>
(function(){{
  /* docs sidebar: mobile accordion toggle */
  var tg=document.getElementById('sb-toggle'),sb=document.getElementById('docs-sidebar');
  if(tg&&sb){{
    tg.addEventListener('click',function(){{
      var open=sb.classList.toggle('open');
      tg.setAttribute('aria-expanded',open?'true':'false');
    }});
  }}

  /* docs sidebar: scroll-spy on the current article's sections */
  var secLinks=Array.prototype.slice.call(document.querySelectorAll('.sb-sections a[href^="#"]'));
  if(secLinks.length&&'IntersectionObserver' in window){{
    var byId={{}};
    var targets=[];
    secLinks.forEach(function(l){{
      var id=decodeURIComponent(l.getAttribute('href').slice(1));
      var el=document.getElementById(id);
      if(el){{byId[id]=l;targets.push(el)}}
    }});
    if(targets.length){{
      var spy=new IntersectionObserver(function(entries){{
        entries.forEach(function(en){{
          if(en.isIntersecting){{
            secLinks.forEach(function(l){{l.classList.remove('active')}});
            byId[en.target.id].classList.add('active');
          }}
        }});
      }},{{rootMargin:'-72px 0px -68% 0px',threshold:0}});
      targets.forEach(function(t){{spy.observe(t)}});
    }}
  }}

  /* copy buttons on code blocks */
  if(navigator.clipboard){{
    Array.prototype.forEach.call(document.querySelectorAll('main pre'),function(pre){{
      var code=pre.textContent;
      var wrap=document.createElement('div');
      wrap.className='pre-wrap';
      pre.parentNode.insertBefore(wrap,pre);
      wrap.appendChild(pre);
      var b=document.createElement('button');
      b.type='button';b.className='copy-code';b.textContent='Copy';
      b.setAttribute('aria-label','Copy code');
      b.addEventListener('click',function(){{
        navigator.clipboard.writeText(code).then(function(){{
          b.textContent='Copied';b.classList.add('done');
          b.setAttribute('aria-label','Copied');
          setTimeout(function(){{
            b.textContent='Copy';b.classList.remove('done');
            b.setAttribute('aria-label','Copy code');
          }},1600);
        }}).catch(function(){{}});
      }});
      wrap.appendChild(b);
    }});
  }}
}})();
</script>
</body>
</html>
"""


def sections(md: str):
    """(slug, title) of every h2 in the markdown, skipping code fences."""
    out, fence = [], False
    for line in md.splitlines():
        if line.startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        m = re.match(r"^##\s+(.*)$", line)
        if m:
            title = m.group(1).strip()
            out.append((slug(title), title))
    return out


CHEVRON = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" '
           'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
           '<polyline points="6 9 12 15 18 9"/></svg>')


def build_sidebar(current: str, sections_map: dict) -> str:
    """Left nav pane: every article, the current one expanded with its h2s."""
    items = []
    for name, title, _ in PAGES:
        if name == current:
            sub = ""
            secs = sections_map.get(name, [])
            if secs:
                sub = ('<ul class="sb-sections">'
                       + "".join(f'<li><a href="#{sid}">{html_mod.escape(stitle, quote=False)}</a></li>'
                                 for sid, stitle in secs)
                       + "</ul>")
            items.append(f'<li><a class="sb-link active" aria-current="page" '
                         f'href="/{name}.html">{title}</a>{sub}</li>')
        else:
            items.append(f'<li><a class="sb-link" href="/{name}.html">{title}</a></li>')
    overview_cls = " active" if current == "documentation" else ""
    return ('<button class="sb-toggle" id="sb-toggle" aria-expanded="false" '
            f'aria-controls="docs-sidebar">Docs navigation {CHEVRON}</button>\n'
            '<aside class="docs-sidebar" id="docs-sidebar"><nav aria-label="Documentation">'
            f'<a class="sb-label{overview_cls}" href="/documentation.html">Documentation</a>'
            '<ul class="sb-list">' + "".join(items) + "</ul></nav></aside>")


def render(name, title, description, content, crumb, footnav, sidebar):
    return TEMPLATE.format(title=title, description=description,
                           content=content, crumb=crumb, footnav=footnav,
                           sidebar=sidebar)


def main():
    sections_map = {}
    for name, _, _ in PAGES:
        src = DOCS / f"{name}.md"
        if not src.exists():
            sys.exit(f"missing {src}")
        sections_map[name] = sections(src.read_text())

    for idx, (name, title, description) in enumerate(PAGES):
        body = convert((DOCS / f"{name}.md").read_text())
        crumb = '<nav class="crumb"><a href="/documentation.html">Documentation</a> <span>/ ' + title + "</span></nav>"
        prev_page = PAGES[idx - 1] if idx > 0 else None
        next_page = PAGES[idx + 1] if idx + 1 < len(PAGES) else None
        left = f'<a href="/{prev_page[0]}.html">&larr; {prev_page[1]}</a>' if prev_page else "<span></span>"
        right = f'<a href="/{next_page[0]}.html">{next_page[1]} &rarr;</a>' if next_page else "<span></span>"
        footnav = f'<nav class="foot-nav">{left}{right}</nav>'
        (DOCS / f"{name}.html").write_text(
            render(name, title, description, body, crumb, footnav,
                   build_sidebar(name, sections_map)))
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
               index_content, "", "", build_sidebar("documentation", sections_map)))
    print("docs/documentation.html")


if __name__ == "__main__":
    main()
