"""
Minimal Markdown -> HTML converter for WASP's own report output.

Not a general CommonMark parser — handles exactly the subset of Markdown
WASP itself generates in report.py / network_scan.py: headings, bold,
links, tables, code fences, blockquotes, horizontal rules, and raw
<details>/<summary> blocks (passed through untouched).
"""

from __future__ import annotations

import html
import re

_INLINE_BOLD = re.compile(r"\*\*(.+?)\*\*")
_INLINE_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_INLINE_CODE = re.compile(r"`([^`]+)`")

_CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 900px;
       margin: 2rem auto; padding: 0 1rem; line-height: 1.5; color: #1a1a1a; }
h1, h2, h3, h4 { border-bottom: 1px solid #ddd; padding-bottom: 0.3em; }
table { border-collapse: collapse; width: 100%; margin: 1em 0; }
th, td { border: 1px solid #ccc; padding: 0.4em 0.6em; text-align: left; }
th { background: #f2f2f2; }
code, pre { background: #f5f5f5; border-radius: 4px; }
pre { padding: 0.8em; overflow-x: auto; }
blockquote { border-left: 3px solid #999; margin: 1em 0; padding: 0.2em 1em; color: #555; }
hr { border: none; border-top: 1px solid #ddd; margin: 1.5em 0; }
"""


def _inline(text: str) -> str:
    text = html.escape(text, quote=False)
    text = _INLINE_CODE.sub(r"<code>\1</code>", text)
    text = _INLINE_BOLD.sub(r"<strong>\1</strong>", text)
    text = _INLINE_LINK.sub(r'<a href="\2">\1</a>', text)
    return text


def md_to_html(md: str, title: str = "WASP Report") -> str:
    """Convert WASP-generated Markdown to a standalone HTML document."""
    out: list[str] = []
    lines = md.split("\n")
    i = 0
    in_code = False
    table_buf: list[str] = []

    def flush_table():
        if not table_buf:
            return
        rows = [r for r in table_buf if not re.match(r"^\|[\s:|-]+\|$", r)]
        out.append("<table>")
        for ri, row in enumerate(rows):
            cells = [c.strip() for c in row.strip("|").split("|")]
            tag = "th" if ri == 0 else "td"
            out.append("<tr>" + "".join(f"<{tag}>{_inline(c)}</{tag}>" for c in cells) + "</tr>")
        out.append("</table>")
        table_buf.clear()

    while i < len(lines):
        line = lines[i]

        if line.startswith("```"):
            flush_table()
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                code_lines.append(lines[i])
                i += 1
            out.append("<pre><code>" + html.escape("\n".join(code_lines)) + "</code></pre>")
            i += 1
            continue

        if line.strip().startswith("<details>") or line.strip().startswith("<summary>") \
                or line.strip().startswith("</details>") or line.strip().startswith("</summary>"):
            flush_table()
            out.append(line)
            i += 1
            continue

        if line.startswith("|"):
            table_buf.append(line)
            i += 1
            continue
        flush_table()

        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            level = len(m.group(1))
            out.append(f"<h{level}>{_inline(m.group(2))}</h{level}>")
            i += 1
            continue

        if line.strip() == "---":
            out.append("<hr>")
            i += 1
            continue

        if line.startswith("> "):
            out.append(f"<blockquote>{_inline(line[2:])}</blockquote>")
            i += 1
            continue

        if line.strip() == "":
            i += 1
            continue

        out.append(f"<p>{_inline(line)}</p>")
        i += 1

    flush_table()

    body = "\n".join(out)
    return (
        f"<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">"
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>"
        f"<body>\n{body}\n</body></html>"
    )


def _self_check():
    md = "# Title\n\n**bold** and [link](http://x) and `code`\n\n" \
         "| a | b |\n|---|---|\n| 1 | 2 |\n\n```\nraw code\n```\n"
    out = md_to_html(md, title="T")
    assert "<h1>Title</h1>" in out
    assert "<strong>bold</strong>" in out
    assert '<a href="http://x">link</a>' in out
    assert "<code>code</code>" in out
    assert "<table>" in out and "<th>a</th>" in out and "<td>1</td>" in out
    assert "<pre><code>raw code</code></pre>" in out


if __name__ == "__main__":
    _self_check()
    print("ok")
