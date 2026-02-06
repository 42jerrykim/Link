"""
Download favicons for URLs in a CSV and rewrite the CSV to use local paths.

Default behavior (matches repo usage):
- Reads `link2.csv`
- Downloads one favicon per origin into `favicons/`
- Updates the `favicon` column to `./favicons/<file>`

This script uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Iterable, Optional


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/121.0 Safari/537.36"
)

_META_REFRESH_RE = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_URL_IN_REFRESH_RE = re.compile(r"""url\s*=\s*([^;]+)""", re.IGNORECASE)
_JS_REDIRECT_RE = re.compile(
    r"""(?:window\.location(?:\.href)?|location\.href|document\.location|top\.location)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_JS_REPLACE_RE = re.compile(r"""location\.replace\(\s*["']([^"']+)["']\s*\)""", re.IGNORECASE)


def normalize_content_type(value: str | None) -> str:
    return (value or "").split(";", 1)[0].strip().lower()


def sniff_is_image_bytes(body: bytes) -> bool:
    if not body:
        return False
    head = body[:32]
    # ICO/CUR
    if len(head) >= 4 and head[0:4] in (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"):
        return True
    # PNG
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    # GIF
    if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        return True
    # JPEG
    if head.startswith(b"\xff\xd8\xff"):
        return True
    # WEBP (RIFF....WEBP)
    if len(head) >= 12 and head[0:4] == b"RIFF" and head[8:12] == b"WEBP":
        return True
    # SVG is text, so detect via tag, but avoid confusing with HTML.
    # We'll accept SVG when it looks like SVG markup.
    stripped = body.lstrip()
    if stripped.startswith(b"<?xml") or stripped.startswith(b"<svg") or stripped.startswith(b"<!--"):
        # Heuristic: contains <svg somewhere near the beginning
        return b"<svg" in stripped[:1024].lower()
    return False


def is_image_response(body: bytes, content_type: str | None) -> bool:
    ct = normalize_content_type(content_type)
    if ct.startswith("image/"):
        return True
    # Some servers omit/wrongly set Content-Type; sniff the bytes.
    return sniff_is_image_bytes(body)


def extract_html_redirect(html: str) -> str | None:
    """
    Best-effort redirect extraction for pages that rely on meta refresh or simple JS redirects.
    Returns a URL/path if found.
    """
    m = _META_REFRESH_RE.search(html)
    if m:
        content = (m.group(1) or "").strip()
        um = _URL_IN_REFRESH_RE.search(content)
        if um:
            return (um.group(1) or "").strip().strip("'\"")

    for rx in (_JS_REPLACE_RE, _JS_REDIRECT_RE):
        jm = rx.search(html)
        if jm:
            return (jm.group(1) or "").strip()
    return None


def is_http_url(value: str) -> bool:
    try:
        p = urllib.parse.urlparse(value)
    except Exception:
        return False
    return p.scheme in ("http", "https") and bool(p.netloc)


def safe_netloc(netloc: str) -> str:
    # "example.com:8080" -> "example.com_8080"
    return netloc.lower().replace(":", "_")


def short_hash(text: str) -> str:
    # Avoid long hashes in filenames; 8 chars is enough to avoid collisions.
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:8]


def guess_extension(url: str, content_type: str | None) -> str:
    path = urllib.parse.urlparse(url).path.lower()
    for ext in (".ico", ".png", ".svg", ".jpg", ".jpeg", ".gif", ".webp"):
        if path.endswith(ext):
            return ".jpg" if ext == ".jpeg" else ext

    ct = (content_type or "").split(";")[0].strip().lower()
    return {
        "image/x-icon": ".ico",
        "image/vnd.microsoft.icon": ".ico",
        "image/ico": ".ico",
        "image/icon": ".ico",
        "image/png": ".png",
        "image/svg+xml": ".svg",
        "image/jpeg": ".jpg",
        "image/jpg": ".jpg",
        "image/gif": ".gif",
        "image/webp": ".webp",
    }.get(ct, ".ico")


def parse_sizes(value: str) -> int:
    """
    Return the maximum pixel area from a sizes attribute (e.g. "16x16 32x32").
    """
    value = (value or "").strip().lower()
    if not value or value == "any":
        return 0
    best = 0
    for token in value.split():
        if "x" not in token:
            continue
        w_s, h_s = token.split("x", 1)
        try:
            w, h = int(w_s), int(h_s)
        except ValueError:
            continue
        best = max(best, w * h)
    return best


def parse_sizes_distance(value: str, *, target: int = 32) -> int:
    """
    Return the closest distance to target for square icon sizes.
    If sizes is missing/any/unparseable, returns a large number.
    """
    value = (value or "").strip().lower()
    if not value or value == "any":
        return 10**9
    best = 10**9
    for token in value.split():
        if "x" not in token:
            continue
        w_s, h_s = token.split("x", 1)
        try:
            w, h = int(w_s), int(h_s)
        except ValueError:
            continue
        if w <= 0 or h <= 0:
            continue
        # Most favicons are square; approximate with average edge.
        edge = (w + h) // 2
        best = min(best, abs(edge - target))
    return best


@dataclass(frozen=True)
class IconCandidate:
    href: str
    rel: str
    sizes_area: int
    sizes_distance: int
    type_attr: str

    def score(self) -> int:
        rel = (self.rel or "").lower()
        href = (self.href or "").lower()
        t = (self.type_attr or "").lower()

        score = 0
        if "apple-touch-icon" in rel:
            score += 200
        if "shortcut" in rel and "icon" in rel:
            score += 120
        elif "icon" in rel:
            score += 100

        # Prefer explicit larger sizes (but don't overweight; many sites lie).
        if self.sizes_area:
            score += min(self.sizes_area, 512 * 512) // 1024

        # Prefer formats: png > svg > ico > others
        ext = os.path.splitext(urllib.parse.urlparse(href).path)[1].lower()
        kind = (t or ext).lower()
        if "png" in kind or ext == ".png":
            score += 35
        elif "svg" in kind or ext == ".svg":
            score += 25
        elif "icon" in kind or ext == ".ico":
            score += 15
        elif "jpeg" in kind or "jpg" in kind or ext in (".jpg", ".jpeg"):
            score += 8
        elif "webp" in kind or ext == ".webp":
            score += 6

        # Penalize non-http schemes and data URIs.
        if href.startswith("data:"):
            score -= 1000
        return score


class IconLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.candidates: list[IconCandidate] = []
        self.base_href: str | None = None
        self.manifest_hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag == "base":
            href = attrs_dict.get("href", "").strip()
            if href:
                self.base_href = href
            return

        if tag != "link":
            return

        rel = attrs_dict.get("rel", "").strip()
        href = attrs_dict.get("href", "").strip()
        if not href or not rel:
            return

        rel_l = rel.lower()
        if rel_l == "manifest":
            self.manifest_hrefs.append(href)
            return
        if "icon" not in rel_l:
            return

        sizes_attr = attrs_dict.get("sizes", "")
        sizes_area = parse_sizes(sizes_attr)
        sizes_distance = parse_sizes_distance(sizes_attr, target=32)
        type_attr = attrs_dict.get("type", "")
        self.candidates.append(
            IconCandidate(
                href=href,
                rel=rel,
                sizes_area=sizes_area,
                sizes_distance=sizes_distance,
                type_attr=type_attr,
            )
        )


def load_manifest_icon_candidates(
    manifest_url: str,
    *,
    timeout: float,
    insecure: bool,
) -> list[IconCandidate]:
    """
    Load PWA manifest and return icon candidates.
    We model them as IconCandidate with rel='manifest-icon' so selection can rank them.
    """
    try:
        body, content_type, final_url = http_get(
            manifest_url,
            timeout=timeout,
            insecure=insecure,
            accept="application/manifest+json,application/json,text/json,*/*;q=0.5",
            max_bytes=1_000_000,
        )
    except Exception:
        return []

    ct = normalize_content_type(content_type)
    if ct and ("json" not in ct and ct not in ("text/plain", "application/octet-stream")):
        # Some servers mislabel; we'll still try to parse as JSON below.
        pass

    text = ""
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            text = body.decode(enc)
            break
        except Exception:
            continue
    if not text:
        return []

    try:
        doc = json.loads(text)
    except Exception:
        return []

    icons = doc.get("icons") if isinstance(doc, dict) else None
    if not isinstance(icons, list):
        return []

    out: list[IconCandidate] = []
    for icon in icons:
        if not isinstance(icon, dict):
            continue
        src = (icon.get("src") or "").strip()
        if not src:
            continue
        # Resolve relative to the final manifest URL (after redirects)
        href = urllib.parse.urljoin(final_url, src)
        sizes = (icon.get("sizes") or "").strip()
        type_attr = (icon.get("type") or "").strip()
        out.append(
            IconCandidate(
                href=href,
                rel="manifest-icon",
                sizes_area=parse_sizes(sizes),
                sizes_distance=parse_sizes_distance(sizes, target=32),
                type_attr=type_attr,
            )
        )
    return out


def build_ssl_context(insecure: bool) -> ssl.SSLContext | None:
    if not insecure:
        return None
    return ssl._create_unverified_context()  # noqa: SLF001 (intentional)


def http_get(
    url: str,
    *,
    timeout: float,
    insecure: bool,
    accept: str,
    max_bytes: int,
) -> tuple[bytes, str | None, str]:
    """
    Returns: (body, content_type, final_url)
    """
    ctx = build_ssl_context(insecure)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": accept,
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        content_type = resp.headers.get("Content-Type")
        final_url = resp.geturl()
        body = resp.read(max_bytes)
        return body, content_type, final_url


def discover_favicon_url(
    page_url: str,
    *,
    timeout: float,
    insecure: bool,
    max_hops: int = 2,
) -> str:
    try:
        body, content_type, final_url = http_get(
            page_url,
            timeout=timeout,
            insecure=insecure,
            accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            max_bytes=2_000_000,
        )
    except Exception:
        parsed = urllib.parse.urlparse(page_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return urllib.parse.urljoin(origin + "/", "favicon.ico")

    final_parsed = urllib.parse.urlparse(final_url)
    final_origin = f"{final_parsed.scheme}://{final_parsed.netloc}"

    ct = normalize_content_type(content_type)
    if "html" not in ct and "xml" not in ct:
        return urllib.parse.urljoin(final_origin + "/", "favicon.ico")

    html = ""
    for enc in ("utf-8", "utf-8-sig", "cp949", "euc-kr", "latin-1"):
        try:
            html = body.decode(enc)
            break
        except Exception:
            continue
    if not html:
        return urllib.parse.urljoin(final_origin + "/", "favicon.ico")

    parser = IconLinkParser()
    try:
        parser.feed(html)
    except Exception:
        return urllib.parse.urljoin(final_origin + "/", "favicon.ico")

    base_for_join = final_url
    if parser.base_href:
        # base href can be relative or absolute
        base_for_join = urllib.parse.urljoin(final_url, parser.base_href)

    # Resolve HTML icon hrefs to absolute URLs.
    html_candidates: list[IconCandidate] = []
    for c in parser.candidates:
        if (c.href or "").strip().lower().startswith("data:"):
            continue
        html_candidates.append(
            IconCandidate(
                href=urllib.parse.urljoin(base_for_join, c.href),
                rel=c.rel,
                sizes_area=c.sizes_area,
                sizes_distance=c.sizes_distance,
                type_attr=c.type_attr,
            )
        )

    # Load manifest candidates (if any).
    manifest_candidates: list[IconCandidate] = []
    for mh in parser.manifest_hrefs:
        manifest_url = urllib.parse.urljoin(base_for_join, mh)
        manifest_candidates.extend(
            load_manifest_icon_candidates(manifest_url, timeout=timeout, insecure=insecure)
        )

    def rel_group(rel: str) -> int:
        r = (rel or "").lower()
        if r == "manifest-icon":
            return 1
        if "apple-touch-icon" in r:
            return 2
        if "mask-icon" in r:
            return 3
        # primary: icon/shortcut icon
        if "icon" in r:
            return 0
        return 9

    def format_priority(href: str, type_attr: str) -> int:
        # lower is better
        h = (href or "").lower()
        t = (type_attr or "").lower()
        ext = os.path.splitext(urllib.parse.urlparse(h).path)[1].lower()
        kind = (t or ext)
        if "x-icon" in kind or "icon" in kind or ext == ".ico" or h.endswith("/favicon.ico"):
            return 0
        if "png" in kind or ext == ".png":
            return 1
        if "svg" in kind or ext == ".svg":
            return 2
        if "jpeg" in kind or "jpg" in kind or ext in (".jpg", ".jpeg"):
            return 3
        if "webp" in kind or ext == ".webp":
            return 4
        return 9

    def rel_is_primary(rel: str) -> bool:
        r = (rel or "").lower()
        return "icon" in r and "apple-touch-icon" not in r and "mask-icon" not in r

    def candidate_rank(c: IconCandidate) -> tuple:
        # Favor primary HTML icons; then manifest; then apple-touch; then mask.
        group = rel_group(c.rel)

        # Prefer sizes close to 32 when sizes are present; unknown sizes go last.
        dist = c.sizes_distance if c.sizes_distance is not None else 10**9

        fmt = format_priority(c.href, c.type_attr)

        # Prefer explicit favicon.ico path among equals.
        path = urllib.parse.urlparse(c.href).path.lower()
        is_favicon_ico = 0 if path.endswith("/favicon.ico") else 1

        # As a weak signal, prefer candidates that declared a size (larger area) over none.
        # This will not override group/format.
        area_bias = -min(c.sizes_area, 1024 * 1024)

        # rel tie-breaker: shortcut icon slightly preferred within primary
        r = (c.rel or "").lower()
        rel_tie = 0
        if rel_is_primary(c.rel):
            rel_tie = 0 if ("shortcut" in r and "icon" in r) else 1
        else:
            rel_tie = 5

        return (group, dist, fmt, is_favicon_ico, rel_tie, area_bias, c.href)

    # Primary candidates: HTML primary icons
    primary = [c for c in html_candidates if rel_is_primary(c.rel)]
    secondary_manifest = manifest_candidates
    secondary_touch = [c for c in html_candidates if "apple-touch-icon" in (c.rel or "").lower()]
    tertiary_mask = [c for c in html_candidates if "mask-icon" in (c.rel or "").lower()]

    pool: list[IconCandidate] = []
    if primary:
        pool = primary
    elif secondary_manifest:
        pool = secondary_manifest
    elif secondary_touch:
        pool = secondary_touch
    elif tertiary_mask:
        pool = tertiary_mask
    else:
        pool = []

    best: Optional[IconCandidate] = None
    if pool:
        best = sorted(pool, key=candidate_rank)[0]

    if not best:
        # Try to follow a simple HTML redirect (meta refresh / location.href / location.replace)
        if max_hops > 0:
            redirect = extract_html_redirect(html)
            if redirect:
                next_url = urllib.parse.urljoin(final_url, redirect)
                return discover_favicon_url(
                    next_url, timeout=timeout, insecure=insecure, max_hops=max_hops - 1
                )
        return urllib.parse.urljoin(final_origin + "/", "favicon.ico")

    # Resolve relative icon URLs against the page/base URL.
    return best.href


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def is_invalid_local_favicon(favicon_value: str, *, outdir: str) -> bool:
    """
    Returns True if favicon_value points to a local file under outdir and it does not look like an image.
    """
    v = (favicon_value or "").strip()
    if not v:
        return False
    # Accept both './favicons/x' and 'favicons/x'
    v_norm = v.replace("\\", "/")
    out_base = os.path.basename(outdir).replace("\\", "/").strip("/")
    prefix1 = f"./{out_base}/"
    prefix2 = f"{out_base}/"
    if not (v_norm.startswith(prefix1) or v_norm.startswith(prefix2)):
        return False

    rel = v_norm[2:] if v_norm.startswith("./") else v_norm
    abs_path = os.path.join(os.getcwd(), rel.replace("/", os.sep))
    if not os.path.isfile(abs_path):
        return True
    try:
        with open(abs_path, "rb") as f:
            head = f.read(2048)
    except Exception:
        return True
    return not sniff_is_image_bytes(head)


def download_favicon(
    page_url: str,
    *,
    outdir: str,
    timeout: float,
    insecure: bool,
    dry_run: bool,
) -> str | None:
    """
    Downloads favicon for a page URL, saves under outdir, returns local relative path.
    """
    p = urllib.parse.urlparse(page_url)
    origin = f"{p.scheme}://{p.netloc}"

    # Discover a likely icon URL (may come from the final redirected page).
    discovered_icon_url = discover_favicon_url(page_url, timeout=timeout, insecure=insecure)
    parsed_discovered = urllib.parse.urlparse(discovered_icon_url)
    discovered_origin = f"{parsed_discovered.scheme}://{parsed_discovered.netloc}" if parsed_discovered.netloc else origin

    candidates: list[str] = []
    if discovered_icon_url:
        candidates.append(discovered_icon_url)
    # Common fallbacks for the discovered/final origin
    candidates.append(urllib.parse.urljoin(discovered_origin + "/", "favicon.ico"))
    candidates.append(urllib.parse.urljoin(discovered_origin + "/", "favicon.png"))
    # Also try original origin if different
    candidates.append(urllib.parse.urljoin(origin + "/", "favicon.ico"))
    candidates.append(urllib.parse.urljoin(origin + "/", "favicon.png"))

    # Domain-specific: QuickConnect pages often end up being Synology-branded, but may not expose an icon.
    # If all else fails, try Synology's public favicon as a reasonable stand-in.
    if p.netloc.lower().endswith("quickconnect.to"):
        candidates.append("https://www.synology.com/favicon.ico")
        candidates.append("https://www.synology.com/favicon.png")

    tried: set[str] = set()
    body = b""
    content_type: str | None = None
    final_icon_url = ""
    for icon_url in candidates:
        if not icon_url or icon_url in tried:
            continue
        tried.add(icon_url)
        try:
            body, content_type, final_icon_url = http_get(
                icon_url,
                timeout=timeout,
                insecure=insecure,
                accept="image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
                max_bytes=2_000_000,
            )
        except Exception:
            continue
        if is_image_response(body, content_type):
            break
        # Not an image (e.g., HTML). Keep trying other candidates.
        body = b""
        content_type = None
        final_icon_url = ""

    if not body:
        return None

    ext = guess_extension(final_icon_url, content_type)
    name = safe_netloc(p.netloc)
    # If two different origins have same netloc (rare), include a short hash of origin.
    filename = f"{name}-{short_hash(origin)}{ext}"
    abs_path = os.path.join(outdir, filename)
    rel_path = "./" + "/".join([os.path.basename(outdir), filename])

    if dry_run:
        return rel_path

    ensure_dir(outdir)
    with open(abs_path, "wb") as f:
        f.write(body)
    return rel_path


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Download favicons and update CSV.")
    parser.add_argument("--csv", dest="csv_path", default="link2.csv")
    parser.add_argument("--outdir", dest="outdir", default="favicons")
    parser.add_argument("--timeout", type=float, default=12.0)

    ssl_group = parser.add_mutually_exclusive_group()
    ssl_group.add_argument("--insecure", action="store_true", default=True, help="Disable TLS verification (default).")
    ssl_group.add_argument("--secure", action="store_true", default=False, help="Enable TLS verification.")

    parser.add_argument("--backup", action="store_true", help="Create <csv>.bak before writing.")
    parser.add_argument("--dry-run", action="store_true", help="Do not write files; just print what would change.")

    args = parser.parse_args(argv)
    insecure = True if args.insecure else False
    if args.secure:
        insecure = False

    csv_path = args.csv_path
    outdir = args.outdir

    if args.backup and not args.dry_run:
        backup_path = csv_path + ".bak"
        shutil.copyfile(csv_path, backup_path)
        print(f"[backup] {backup_path}", flush=True)

    def read_csv_with_repair(path: str) -> tuple[list[str], list[dict[str, str]], dict[str, object]]:
        """
        Read CSV as dict rows, repairing malformed lines that have too many/few columns.

        Why this exists:
        - csv.DictReader uses `None` as a key when a row has more fields than the header.
          Those `None` keys later crash csv.DictWriter with:
            ValueError: dict contains fields not in fieldnames: None
        """
        stats: dict[str, object] = {
            "rows_total": 0,
            "rows_blank_skipped": 0,
            "rows_normalized": 0,
            "rows_padded": 0,
            "rows_truncated": 0,
            "rows_join_name_repaired": 0,
            "examples": {},  # type: ignore[typeddict-item]
        }

        with open(path, "r", encoding="utf-8", newline="") as f:
            r = csv.reader(f)
            try:
                raw_header = next(r)
            except StopIteration:
                return [], [], stats

            # Keep header order stable; strip whitespace-only header cells.
            fieldnames = [(h or "").strip() for h in raw_header]
            rows: list[dict[str, str]] = []

            line_no = 1  # header line
            for raw in r:
                line_no += 1
                stats["rows_total"] = int(stats["rows_total"]) + 1

                if not raw or all(((c or "").strip() == "") for c in raw):
                    stats["rows_blank_skipped"] = int(stats["rows_blank_skipped"]) + 1
                    continue

                expected = len(fieldnames)
                got = len(raw)
                values: list[str]

                if got == expected:
                    values = [c or "" for c in raw]
                elif got < expected:
                    values = [c or "" for c in raw] + [""] * (expected - got)
                    stats["rows_normalized"] = int(stats["rows_normalized"]) + 1
                    stats["rows_padded"] = int(stats["rows_padded"]) + 1
                    examples = stats.get("examples", {})
                    if isinstance(examples, dict) and "padded" not in examples:
                        examples["padded"] = {"line": line_no, "got": got, "expected": expected}
                else:
                    # Too many columns. Common root cause: unquoted commas in the "name" field.
                    if fieldnames == ["group", "name", "favicon", "link"] and expected == 4 and got >= 4:
                        group = raw[0] or ""
                        link = raw[-1] or ""
                        favicon = raw[-2] or ""
                        name = ",".join((c or "") for c in raw[1:-2])
                        values = [group, name, favicon, link]
                        stats["rows_normalized"] = int(stats["rows_normalized"]) + 1
                        stats["rows_join_name_repaired"] = int(stats["rows_join_name_repaired"]) + 1
                        examples = stats.get("examples", {})
                        if isinstance(examples, dict) and "join_name_repaired" not in examples:
                            examples["join_name_repaired"] = {"line": line_no, "got": got, "expected": expected}
                    else:
                        # Generic fallback: truncate extras to avoid None-keys and keep script running.
                        values = [(c or "") for c in raw[:expected]]
                        stats["rows_normalized"] = int(stats["rows_normalized"]) + 1
                        stats["rows_truncated"] = int(stats["rows_truncated"]) + 1
                        examples = stats.get("examples", {})
                        if isinstance(examples, dict) and "truncated" not in examples:
                            examples["truncated"] = {"line": line_no, "got": got, "expected": expected}

                # Build a dict row with exactly the header keys (no None keys).
                row = {fieldnames[i]: values[i] for i in range(min(len(fieldnames), len(values)))}
                rows.append(row)

        return fieldnames, rows, stats

    fieldnames, rows, csv_stats = read_csv_with_repair(csv_path)

    if not fieldnames:
        print(f"[error] CSV is empty or missing a header row: {csv_path}", file=sys.stderr)
        return 2

    if int(csv_stats.get("rows_normalized", 0) or 0) > 0:
        print(
            "[warn] CSV rows normalized to match header. "
            f"normalized={csv_stats.get('rows_normalized', 0)} "
            f"padded={csv_stats.get('rows_padded', 0)} "
            f"truncated={csv_stats.get('rows_truncated', 0)} "
            f"join_name_repaired={csv_stats.get('rows_join_name_repaired', 0)} "
            f"blank_skipped={csv_stats.get('rows_blank_skipped', 0)}",
            file=sys.stderr,
        )
        examples = csv_stats.get("examples", {})
        if isinstance(examples, dict) and examples:
            # Keep this compact: show first example line(s) only.
            parts = []
            for k, v in examples.items():
                if isinstance(v, dict) and "line" in v:
                    parts.append(f"{k}=line{v.get('line')}")
            if parts:
                print(f"[warn] examples: " + ", ".join(parts), file=sys.stderr)

    if "link" not in fieldnames or "favicon" not in fieldnames:
        print(f"[error] CSV must include 'link' and 'favicon' columns. Got: {fieldnames}", file=sys.stderr)
        return 2

    origin_cache: dict[str, str] = {}
    changed = 0
    attempted = 0
    failures = 0

    start = time.time()
    for row in rows:
        link = (row.get("link") or "").strip()
        if not is_http_url(link):
            continue

        attempted += 1
        p = urllib.parse.urlparse(link)
        origin = f"{p.scheme}://{p.netloc}"

        old_favicon = (row.get("favicon") or "").strip()
        old_local_invalid = is_invalid_local_favicon(old_favicon, outdir=outdir)

        if origin in origin_cache:
            new_favicon = origin_cache[origin]
        else:
            print(f"[try] {origin}", flush=True)
            new_favicon = download_favicon(
                link,
                outdir=outdir,
                timeout=args.timeout,
                insecure=insecure,
                dry_run=args.dry_run,
            )
            if not new_favicon:
                failures += 1
                print(f"[fail] {link}", flush=True)
                if old_local_invalid and not args.dry_run:
                    row["favicon"] = ""
                    changed += 1
                    print(f"[clear] {origin} invalid local favicon -> ''", flush=True)
                continue
            origin_cache[origin] = new_favicon

        if old_favicon != new_favicon:
            row["favicon"] = new_favicon
            changed += 1
            print(f"[ok] {origin} -> {new_favicon}", flush=True)

    if args.dry_run:
        print(
            f"[dry-run] attempted={attempted} changed={changed} "
            f"failures={failures} origins={len(origin_cache)}",
            flush=True,
        )
        return 0

    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
            lineterminator="\n",
            extrasaction="ignore",
        )
        writer.writeheader()
        # Defensive: ensure no stray None-key survives.
        for row in rows:
            if None in row:  # type: ignore[operator]
                row.pop(None, None)  # type: ignore[arg-type]
        writer.writerows(rows)

    elapsed = time.time() - start
    print(
        f"[done] attempted={attempted} changed={changed} failures={failures} "
        f"origins={len(origin_cache)} elapsed={elapsed:.1f}s",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

