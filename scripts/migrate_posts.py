#!/usr/bin/env python3
"""Convert historical Jekyll research posts into the static site template."""

from __future__ import annotations

import html
import re
import subprocess
from pathlib import Path
from urllib.parse import quote

import markdown as md

ROOT = Path(__file__).resolve().parents[1]
POSTS_DIR = ROOT / "posts"
HISTORIC = "279b096"

# Research posts only (skip theme demos)
SOURCES = [
    ("2021-01-11-Windows-Stack-Buffer-Overflow.md", "windows-stack-buffer-overflow"),
    ("2021-01-26-Flare.md", "flare-on-challenge-1-fidler"),
    ("2021-01-28-Flare-On-2020.md", "flare-on-challenge-2-garbage"),
    ("2021-01-31-Ancillary Function Driver.md", "ancillary-function-driver-ms11-046"),
    ("2021-02-14- Forensics-Challenge_0.md", "forensic-basics-challenge-0"),
    ("2021-02-14- Forensics-Challenge_1.md", "forensic-basics-challenge-1"),
    ("2021-02-22-Emotet-Malware.md", "emotet-malware"),
    ("2021-03-03-Forensic-Challenge-03.md", "forensic-basics-challenge-03"),
    ("2021-03-13-Preventing SSL Pinning Bypass on iOS.md", "preventing-ssl-pinning-bypass-on-ios"),
    ("2021-04-11-Android-API-Limit-Bypass.md", "android-hidden-api-restrictions"),
]

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title} — Yash Omer</title>
  <meta name="description" content="{description}" />
  <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
  <script src="../theme.js"></script>
  <link rel="stylesheet" href="../styles.css" />
</head>
<body>
  <main>
    <div class="content">
      <header class="site-header">
        <p>
          <a href="../index.html" class="brand">yashomer1994.github.io</a><span class="cursor" aria-hidden="true">▮</span>
        </p>
        <nav>
          <a href="../index.html">Home</a>
          <a href="lab-1-model-theft.html">Latest</a>
          <button type="button" class="theme-toggle" id="theme-toggle">Dark</button>
        </nav>
      </header>
      <hr class="header-rule" />

      <p class="meta">{date_display}{categories_html}</p>
      <h1>{title}</h1>

      <div class="post-body">
{body}
      </div>

      <p class="footer-nav"><a href="../index.html">← Home</a></p>
    </div>
  </main>
</body>
</html>
"""


def git_show(path: str) -> str:
    return subprocess.check_output(
        ["git", "show", f"{HISTORIC}:_posts/{path}"],
        cwd=ROOT,
        text=True,
    )


def parse_front_matter(raw: str) -> tuple[dict[str, str], str]:
    if not raw.startswith("---"):
        return {}, raw
    parts = raw.split("---", 2)
    if len(parts) < 3:
        return {}, raw
    meta: dict[str, str] = {}
    for line in parts[1].splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        meta[key] = val  # last wins for duplicate title keys
    return meta, parts[2]


def normalize_markdown(body: str) -> str:
    # Convert odd Jekyll-era heading patterns:
    # ---\n[](#header-1)**Title**\n---
    body = re.sub(
        r"(?m)^---\s*\n(?:\s*\[\]\(#header-\d+\)\s*)?\*\*(.+?)\*\*\s*\n---\s*$",
        r"## \1",
        body,
    )
    body = re.sub(
        r"(?m)^(?:\s*\[\]\(#header-\d+\)\s*)?\*\*(.+?)\*\*\s*\n---\s*$",
        r"## \1",
        body,
    )
    body = re.sub(r"(?m)^\[\]\(#header-\d+\)\s*", "", body)
    body = re.sub(r"(?m)^----+\s*$", "\n", body)
    # Absolute site image URLs -> relative assets
    body = body.replace("https://yashomer1994.github.io/assets/", "../assets/")
    body = body.replace("http://yashomer1994.github.io/assets/", "../assets/")
    return body


def fix_img_src(html_body: str) -> str:
    def repl(match: re.Match[str]) -> str:
        src = match.group(1)
        if src.startswith("../assets/"):
            path = src[len("../assets/") :]
            # URL-encode spaces and special chars in path segments
            encoded = "/".join(quote(seg, safe="") for seg in path.split("/"))
            src = "../assets/" + encoded
        return f'src="{src}"'

    return re.sub(r'src="([^"]+)"', repl, html_body)


def format_date(iso: str) -> str:
    # 2021-01-11 -> January 11, 2021
    try:
        y, m, d = iso.split("-")
        months = [
            "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December",
        ]
        return f"{months[int(m) - 1]} {int(d)}, {y}"
    except Exception:
        return iso


def render_post(filename: str, slug: str) -> dict:
    raw = git_show(filename)
    meta, body = parse_front_matter(raw)
    title = meta.get("title") or slug.replace("-", " ").title()
    date = meta.get("date", "2021-01-01")[:10]
    categories = meta.get("categories", "")
    body_md = normalize_markdown(body)
    body_html = md.markdown(
        body_md,
        extensions=["fenced_code", "tables", "nl2br", "sane_lists"],
    )
    body_html = fix_img_src(body_html)

    cats = ""
    if categories:
        cats = " · " + html.escape(categories)

    page = TEMPLATE.format(
        title=html.escape(title),
        description=html.escape(title),
        date_display=html.escape(format_date(date)),
        categories_html=cats,
        body=body_html,
    )
    out = POSTS_DIR / f"{slug}.html"
    out.write_text(page, encoding="utf-8")
    return {"slug": slug, "title": title, "date": date}


def main() -> None:
    POSTS_DIR.mkdir(exist_ok=True)
    posts = []
    for filename, slug in SOURCES:
        info = render_post(filename, slug)
        posts.append(info)
        print(f"wrote posts/{slug}.html")

    # newest first for index (by date, then title)
    posts.sort(key=lambda p: p["date"], reverse=True)
    manifest = ROOT / "scripts" / "posts_manifest.json"
    import json

    manifest.write_text(json.dumps(posts, indent=2), encoding="utf-8")
    print(f"manifest: {len(posts)} posts")


if __name__ == "__main__":
    main()
