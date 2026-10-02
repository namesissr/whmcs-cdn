"""MkDocs hooks for the Pasargad CDN docs site (mkdocs.yml -> hooks:).

The site is built straight from docs/*.md, which stay where they are (they are also read on GitHub).
These hooks bridge the two worlds without touching those files:

* on_config    GitHub-compatible heading ids (keep combining marks like «ٔ», drop ZWNJ and
               punctuation, spaces -> "-"), so anchors written for GitHub work on the site.
* on_files     adds the site-only pages and assets from docs-site/ (landing page, CSS) and the root
               README.md as the "Getting started" page.
* on_page_markdown
               rewrites links that leave docs/ (../cli/, ../README.md, ../deploy/...) to the file on
               GitHub (repo_url + /blob|tree/<branch>/...), and README's docs/X.md links to X.md, so
               `mkdocs build --strict` passes while the same Markdown keeps working on GitHub.
* on_page_content
               marks every page with its direction: Persian pages render RTL (the theme default),
               English ones (SPEC.md, EDGE.md, ...) are wrapped in dir="ltr".
"""

from __future__ import annotations

import logging
import posixpath
import re
import unicodedata
from pathlib import Path

from mkdocs.structure.files import File

log = logging.getLogger("mkdocs.hooks.pcdn")

SITE_DIR = Path(__file__).resolve().parent
REPO = SITE_DIR.parent
PAGES = SITE_DIR / "pages"
ASSETS = ("stylesheets",)
README_DEST = "getting-started.md"

# [text](target) — not images' srcset, not autolinks; target without spaces
LINK = re.compile(r"(?<!\!)\[(?P<text>[^\]]*)\]\((?P<target>[^)\s]+)(?P<title>\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^(```|~~~)")
ARABIC = re.compile(r"[؀-ۿ]")
LATIN = re.compile(r"[A-Za-z]")


def _repo_blob(config, repo_path: str) -> str:
    base = (config.get("repo_url") or "").rstrip("/")
    branch = config.get("extra", {}).get("repo_branch", "main")
    kind = "tree" if repo_path.endswith("/") or (REPO / repo_path).is_dir() else "blob"
    return f"{base}/{kind}/{branch}/{repo_path.lstrip('/')}"


def github_slugify(value: str, separator: str = "-") -> str:
    """github-slugger: lowercase, keep letters/marks/numbers/space/-/_, then each space -> '-'."""
    value = value.strip().lower()
    kept = "".join(ch for ch in value if unicodedata.category(ch)[0] in "LMN" or ch in " -_")
    return kept.replace(" ", separator)


def on_config(config):
    config["mdx_configs"].setdefault("toc", {})["slugify"] = github_slugify
    return config


def on_files(files, config):
    for path in sorted(PAGES.rglob("*.md")):
        rel = path.relative_to(PAGES).as_posix()
        files.append(File(rel, str(PAGES), config["site_dir"], config["use_directory_urls"]))
    for sub in ASSETS:
        for path in sorted((SITE_DIR / sub).rglob("*")):
            if path.is_file():
                files.append(File(path.relative_to(SITE_DIR).as_posix(), str(SITE_DIR), config["site_dir"],
                                  config["use_directory_urls"]))
    readme = REPO / "README.md"
    if readme.exists():
        files.append(File.generated(config, README_DEST, abs_src_path=str(readme)))
    return files


def _rewrite(markdown: str, page_src: str, config) -> str:
    """Rewrite links outside docs/ to GitHub, outside fenced code blocks."""
    is_readme = page_src == README_DEST
    page_dir = "" if is_readme else "docs"
    out, in_fence = [], False

    def fix(m: re.Match) -> str:
        target = m.group("target")
        if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I) or target.startswith(("#", "?")):
            return m.group(0)
        path, _, anchor = target.partition("#")
        repo_path = posixpath.normpath(posixpath.join(page_dir, path)) if path else ""
        if not path:
            return m.group(0)
        if repo_path.startswith("docs/") and repo_path.endswith(".md") and (REPO / repo_path).exists():
            if not is_readme:
                return m.group(0)  # a normal page-to-page link, mkdocs resolves it
            new = repo_path[len("docs/"):] + (f"#{anchor}" if anchor else "")
        elif repo_path == "README.md" and not is_readme:
            new = README_DEST + (f"#{anchor}" if anchor else "")  # README is a page on the site
        elif repo_path.startswith("..") or not (REPO / repo_path).exists():
            return m.group(0)  # genuinely broken: leave it for mkdocs to report
        else:
            if path.endswith("/") and not repo_path.endswith("/"):
                repo_path += "/"
            new = _repo_blob(config, repo_path) + (f"#{anchor}" if anchor else "")
        return f"[{m.group('text')}]({new}{m.group('title') or ''})"

    for line in markdown.splitlines(keepends=True):
        if FENCE.match(line.lstrip()):
            in_fence = not in_fence
        out.append(line if in_fence else LINK.sub(fix, line))
    return "".join(out)


_used_fixes: set[int] = set()


def _apply_link_fixes(markdown: str, src: str, config) -> str:
    for i, fix in enumerate(config.get("extra", {}).get("link_fixes") or []):
        if fix.get("page") != src:
            continue
        old, new = f"]({fix['from']})", f"]({fix['to']})"
        if old in markdown:
            markdown = markdown.replace(old, new)
            _used_fixes.add(i)
    return markdown


def on_post_build(config):
    for i, fix in enumerate(config.get("extra", {}).get("link_fixes") or []):
        if i not in _used_fixes:
            log.warning("extra.link_fixes entry for %s no longer matches; remove it from mkdocs.yml",
                        fix.get("page"))
    _used_fixes.clear()


def on_page_markdown(markdown, page, config, files):
    src = page.file.src_uri
    md = _rewrite(_apply_link_fixes(markdown, src, config), src, config)
    # direction: mostly-Persian prose => rtl (theme default), otherwise ltr
    prose = re.sub(r"```.*?```|`[^`]*`|\([^)]*\)", " ", md, flags=re.S)
    fa, en = len(ARABIC.findall(prose)), len(LATIN.findall(prose))
    page.meta.setdefault("dir", "rtl" if fa >= en * 0.5 else "ltr")
    return md


def on_page_content(html, page, config, files):
    if page.meta.get("dir") == "ltr":
        return f'<div dir="ltr" class="pcdn-ltr" lang="en">\n{html}\n</div>'
    return html
