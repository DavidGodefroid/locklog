#!/usr/bin/env python3
"""Checks the static site in site/ before it is published, offline.

Every local href and src must name a file in site/ (a directory link needs
its index.html), and every #fragment must name an id on the target page.
Absolute paths are resolved from the site root: locklog.dev is a custom
domain on GitHub Pages, so site/CNAME must name it. Every sitemap.xml <loc>
must be under https://locklog.dev/ and name an existing page. Each page
needs lang, a viewport, a title and a description. External links are not
fetched.

    python3 scripts/check-site.py [site]
"""

import html.parser
import pathlib
import sys
import urllib.parse
import xml.etree.ElementTree as ET

BASE = "/"
DOMAIN = "locklog.dev"
ORIGIN = f"https://{DOMAIN}/"


class Page(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.ids, self.meta = [], set(), {}
        self.lang = self.title = False
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        if tag == "html" and a.get("lang"):
            self.lang = True
        if tag == "title":
            self._in_title = True
        if tag == "meta" and "name" in a:
            self.meta[a["name"]] = a.get("content", "")
        for attr in ("href", "src", "srcset"):
            if attr in a:
                self.links.append((tag, a[attr]))

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and data.strip():
            self.title = True


def parse(path):
    p = Page()
    p.feed(path.read_text(encoding="utf-8"))
    return p


def target(root, page, ref):
    """The file a local reference points at, or None for an external one."""
    u = urllib.parse.urlsplit(ref)
    if u.scheme or u.netloc:
        return None, None
    path = urllib.parse.unquote(u.path)
    if path.startswith("/"):
        if not path.startswith(BASE):
            return root / "__outside_base__", u.fragment
        f = root / path[len(BASE):]
    elif path:
        f = page.parent / path
    else:
        f = page
    if path.endswith("/") or f.is_dir():
        f = f / "index.html"
    return f.resolve(), u.fragment


def check_sitemap(root, pages):
    """Every <loc> is an absolute URL under ORIGIN naming an existing page."""
    sitemap = root / "sitemap.xml"
    if not sitemap.is_file():
        return ["sitemap.xml: missing"]
    try:
        tree = ET.parse(sitemap)
    except ET.ParseError as e:
        return [f"sitemap.xml: {e}"]
    errors = []
    locs = [el.text.strip() for el in tree.iter() if el.tag.endswith("}loc") or el.tag == "loc"]
    if not locs:
        errors.append("sitemap.xml: no <loc>")
    for loc in locs:
        if not loc.startswith(ORIGIN):
            errors.append(f"sitemap.xml: {loc}: not under {ORIGIN}")
            continue
        path = urllib.parse.unquote(urllib.parse.urlsplit(loc).path)
        f = root / path.lstrip("/")
        if path.endswith("/") or f.is_dir():
            f = f / "index.html"
        if f.resolve() not in pages:
            errors.append(f"sitemap.xml: {loc}: no such page")
    return errors


def main():
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "site").resolve()
    pages = {p.resolve(): parse(p) for p in root.rglob("*.html")}
    errors = []
    cname = root / "CNAME"
    if not cname.is_file():
        errors.append(f"site/CNAME: missing (must be {DOMAIN})")
    elif cname.read_text(encoding="utf-8").strip() != DOMAIN:
        errors.append(f"site/CNAME: must be exactly {DOMAIN}")
    errors += check_sitemap(root, pages)
    for page, p in sorted(pages.items()):
        rel = page.relative_to(root)
        if not p.lang:
            errors.append(f"{rel}: <html> has no lang")
        if not p.title:
            errors.append(f"{rel}: no <title>")
        if "viewport" not in p.meta:
            errors.append(f"{rel}: no viewport meta")
        if not p.meta.get("description"):
            errors.append(f"{rel}: no description meta")
        for tag, ref in p.links:
            if tag == "source":  # srcset holds a single URL here
                ref = ref.split()[0]
            f, frag = target(root, page, ref)
            if f is None:
                continue
            if not f.is_file():
                errors.append(f"{rel}: {ref}: no such file")
                continue
            if frag and f.suffix == ".html" and frag not in pages[f].ids:
                errors.append(f"{rel}: {ref}: no id {frag!r}")
    for e in errors:
        print(e, file=sys.stderr)
    print(f"{len(pages)} pages checked, {len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
