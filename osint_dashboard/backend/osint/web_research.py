from __future__ import annotations

import asyncio
import html
import re
import urllib.parse

import httpx

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "de-DE,de;q=0.9,en;q=0.8",
}

_TIMEOUT = 15.0
_TOTAL_BUDGET = 90.0
_MAX_CONCURRENCY = 5
_PAGE_CHARS = 1500
_SNIPPET_CHARS = 300
_MAX_DOSSIER_CHARS = 9000
_MAX_BLOCK_CHARS = 1800

_DDG_LITE = "https://lite.duckduckgo.com/lite/"
_DDG_HTML = "https://html.duckduckgo.com/html/"
_DDG_API = "https://api.duckduckgo.com/"
_WIKI_SEARCH = "https://{lang}.wikipedia.org/w/api.php"
_WIKI_SUMMARY = "https://{lang}.wikipedia.org/api/rest_v1/page/summary/{title}"

_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"<(script|style|noscript)[^>]*>.*?</\1>", re.S | re.I)
_WS_RE = re.compile(r"[ \t\r\f\v]+")


def _text_of(fragment: str) -> str:
    return html.unescape(_TAG_RE.sub(" ", fragment)).replace("\xa0", " ").strip()


def _clean_ddg_url(url: str) -> str:
    if url.startswith("//"):
        url = "https:" + url
    if "duckduckgo.com/l/" in url or url.startswith("/l/"):
        query = urllib.parse.urlparse(url).query
        target = urllib.parse.parse_qs(query).get("uddg", [""])[0]
        if target:
            return urllib.parse.unquote(target)
    return url


def _parse_ddg(body: str, max_results: int) -> list[dict]:
    rows = re.split(r"<tr[^>]*>|<div class=\"result", body)
    results, pending = [], []

    for row in rows:
        if "result-sponsored" in row or "badge--ad" in row:
            continue
        link = re.search(
            r'href="([^"]+)"[^>]*class=[\'"](?:result-link|result__a)[\'"][^>]*>(.*?)</a>',
            row, re.S,
        ) or re.search(
            r'class=[\'"](?:result-link|result__a)[\'"][^>]*href="([^"]+)"[^>]*>(.*?)</a>',
            row, re.S,
        )
        if link:
            url = _clean_ddg_url(html.unescape(link.group(1)))
            title = _text_of(link.group(2))
            if url.startswith("http") and title:
                pending.append({"title": title, "url": url, "snippet": ""})
            continue

        snippet = re.search(
            r'class=[\'"](?:result-snippet|result__snippet)[\'"][^>]*>(.*?)</(?:td|a|div)>',
            row, re.S,
        )
        if snippet and pending:
            text = _text_of(snippet.group(1))
            for item in reversed(pending):
                if not item["snippet"]:
                    item["snippet"] = text[:_SNIPPET_CHARS]
                    break

    seen = set()
    for item in pending:
        if item["url"] in seen:
            continue
        seen.add(item["url"])
        results.append(item)
        if len(results) >= max_results:
            break
    return results


async def ddg_search(query: str, client: httpx.AsyncClient, max_results: int = 5) -> list[dict]:
    for url, method in ((_DDG_LITE, "post"), (_DDG_HTML, "post"), (_DDG_LITE, "get")):
        try:
            if method == "post":
                res = await client.post(url, data={"q": query}, timeout=_TIMEOUT)
            else:
                res = await client.get(url, params={"q": query}, timeout=_TIMEOUT)
            if res.status_code != 200:
                continue
            hits = _parse_ddg(res.text, max_results)
            if hits:
                return hits
        except httpx.HTTPError:
            continue
    return []


async def ddg_instant(query: str, client: httpx.AsyncClient) -> str:
    try:
        res = await client.get(
            _DDG_API,
            params={"q": query, "format": "json", "no_html": "1", "skip_disambig": "1"},
            timeout=_TIMEOUT,
        )
        if res.status_code != 200:
            return ""
        data = res.json()
    except (httpx.HTTPError, ValueError):
        return ""
    return (data.get("AbstractText") or data.get("Definition") or "").strip()


async def wikipedia_summary(term: str, client: httpx.AsyncClient, lang: str = "de") -> dict | None:
    try:
        res = await client.get(
            _WIKI_SEARCH.format(lang=lang),
            params={"action": "query", "list": "search", "srsearch": term,
                    "format": "json", "srlimit": 1},
            timeout=_TIMEOUT,
        )
        hits = res.json().get("query", {}).get("search", [])
        if not hits:
            return None
        title = hits[0]["title"]

        res = await client.get(
            _WIKI_SUMMARY.format(lang=lang, title=urllib.parse.quote(title.replace(" ", "_"))),
            timeout=_TIMEOUT,
        )
        data = res.json()
    except (httpx.HTTPError, ValueError, KeyError, IndexError):
        return None

    extract = (data.get("extract") or "").strip()
    if not extract:
        return None
    return {
        "title": data.get("title", title),
        "url": (data.get("content_urls", {}).get("desktop", {}) or {}).get("page", ""),
        "extract": extract[:1200],
    }


async def fetch_page_text(url: str, client: httpx.AsyncClient, max_chars: int = _PAGE_CHARS) -> str:
    try:
        res = await client.get(url, timeout=_TIMEOUT, follow_redirects=True)
        if res.status_code != 200:
            return ""
        ctype = res.headers.get("content-type", "")
        if "html" not in ctype and "text" not in ctype:
            return ""
        body = res.text
    except (httpx.HTTPError, UnicodeDecodeError):
        return ""

    body = _SCRIPT_RE.sub(" ", body)
    text = _text_of(body)
    text = _WS_RE.sub(" ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text[:max_chars].strip()


async def _guarded(coro, label: str, sem: asyncio.Semaphore):
    async with sem:
        try:
            return label, await coro
        except Exception as exc:
            return label, {"error": f"{type(exc).__name__}: {exc}"}


async def _search_task(query: str, client: httpx.AsyncClient, max_results: int = 4) -> dict:
    hits = await ddg_search(query, client, max_results)
    instant = await ddg_instant(query, client) if not hits else ""
    return {"query": query, "hits": hits, "instant": instant}


async def _domain_task(domain: str, client: httpx.AsyncClient) -> dict:
    from backend.osint.web_osint import analyze_domain
    return await analyze_domain(domain)


async def _email_task(email: str, client: httpx.AsyncClient) -> dict:
    from backend.osint.email_osint import analyze_email
    return await analyze_email(email)


async def _username_task(handle: str, client: httpx.AsyncClient) -> dict:
    from backend.osint.username_osint import analyze_username
    return await analyze_username(handle)


async def _wiki_task(term: str, client: httpx.AsyncClient) -> dict:
    for lang in ("de", "en"):
        summary = await wikipedia_summary(term, client, lang)
        if summary:
            summary["lang"] = lang
            return summary
    return {}


def plan_research(found: dict[str, list[str]], extra_queries: list[str] | None = None,
                  deep: bool = True) -> list[tuple[str, str, str]]:
    plan: list[tuple[str, str, str]] = []

    for name in found.get("Possible person names", [])[:2]:
        plan.append(("search", f'"{name}"', f"Web search: {name}"))
        plan.append(("wiki", name, f"Wikipedia: {name}"))

    for domain in found.get("Domains", [])[:2]:
        plan.append(("domain", domain, f"WHOIS/DNS/subdomains: {domain}"))
        plan.append(("search", domain, f"Web search: {domain}"))

    for email in found.get("E-mail addresses", [])[:2]:
        plan.append(("email", email, f"MX/Gravatar/handle reuse: {email}"))
        plan.append(("search", f'"{email}"', f"Web search: {email}"))

    if deep:
        for handle in found.get("Usernames (@handle)", [])[:1]:
            plan.append(("username", handle, f"Platform profiles: @{handle}"))
    for handle in found.get("Usernames (@handle)", [])[:2]:
        plan.append(("search", f'"{handle}"', f"Web search: @{handle}"))

    for number in found.get("Phone numbers", [])[:1]:
        plan.append(("search", f'"{number}"', f"Web search: {number}"))

    for cve in found.get("CVE IDs", [])[:2]:
        plan.append(("search", f"{cve} advisory", f"Web search: {cve}"))

    for query in (extra_queries or [])[:3]:
        plan.append(("search", query, f"Model follow-up: {query}"))

    seen, unique = set(), []
    for kind, target, label in plan:
        key = (kind, target.lower())
        if key not in seen:
            seen.add(key)
            unique.append((kind, target, label))
    return unique[:14]


_RUNNERS = {
    "search": _search_task,
    "domain": _domain_task,
    "email": _email_task,
    "username": _username_task,
    "wiki": _wiki_task,
}


async def run_research(plan: list[tuple[str, str, str]], read_pages: int = 3) -> dict:
    if not plan:
        return {"results": [], "sources": [], "notes": ["No researchable entities found."]}

    sem = asyncio.Semaphore(_MAX_CONCURRENCY)
    notes: list[str] = []

    async with httpx.AsyncClient(headers=HEADERS, follow_redirects=True) as client:
        tasks = [
            _guarded(_RUNNERS[kind](target, client), f"{kind}|{target}|{label}", sem)
            for kind, target, label in plan
            if kind in _RUNNERS
        ]
        try:
            raw = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True), timeout=_TOTAL_BUDGET
            )
        except asyncio.TimeoutError:
            notes.append(f"Research stopped after {int(_TOTAL_BUDGET)}s - partial results are used.")
            raw = []

        results, sources = [], []
        for entry in raw:
            if isinstance(entry, Exception) or not isinstance(entry, tuple):
                continue
            label, payload = entry
            kind, target, human = label.split("|", 2)
            results.append({"kind": kind, "target": target, "label": human, "data": payload})
            if kind == "search" and isinstance(payload, dict):
                for hit in payload.get("hits", []):
                    sources.append({"title": hit["title"], "url": hit["url"]})
            elif kind == "wiki" and isinstance(payload, dict) and payload.get("url"):
                sources.append({"title": payload["title"] + " (Wikipedia)", "url": payload["url"]})

        top_urls, seen_hosts = [], set()
        for src in sources:
            host = urllib.parse.urlparse(src["url"]).netloc
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            top_urls.append(src)
            if len(top_urls) >= read_pages:
                break

        if top_urls:
            pages = await asyncio.gather(
                *(fetch_page_text(src["url"], client) for src in top_urls),
                return_exceptions=True,
            )
            for src, text in zip(top_urls, pages):
                if isinstance(text, str) and text:
                    results.append({
                        "kind": "page", "target": src["url"],
                        "label": f"Page content: {src['title']}",
                        "data": {"url": src["url"], "text": text},
                    })

    seen_urls, unique_sources = set(), []
    for src in sources:
        if src["url"] not in seen_urls:
            seen_urls.add(src["url"])
            unique_sources.append(src)

    return {"results": results, "sources": unique_sources[:25], "notes": notes}


def _fmt_search(data: dict) -> list[str]:
    lines = []
    if data.get("instant"):
        lines.append(f"  Short answer: {data['instant'][:400]}")
    for hit in data.get("hits", []):
        lines.append(f"  - {hit['title']}")
        lines.append(f"    {hit['url']}")
        if hit.get("snippet"):
            lines.append(f"    {hit['snippet']}")
    if not lines:
        lines.append("  (no hits)")
    return lines


def _fmt_domain(data: dict) -> list[str]:
    lines = []
    whois = data.get("whois") or {}
    if whois.get("error"):
        lines.append(f"  WHOIS: {whois['error']}")
    for key, label in (("registrar", "Registrar"), ("creation_date", "Created"),
                       ("expiration_date", "Expires"), ("updated_date", "Updated"),
                       ("whois_server", "WHOIS server"), ("name_servers", "Name servers"),
                       ("status", "Status")):
        value = whois.get(key)
        if not value:
            continue
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(v) for v in value[:4])
        lines.append(f"  {label}: {str(value)[:200]}")

    subs = data.get("subdomains") or {}
    if subs.get("subdomains"):
        lines.append(f"  Subdomains ({subs.get('count', 0)}): {', '.join(subs['subdomains'][:12])}")

    dns = data.get("dns") or {}
    if dns.get("resolved_ip"):
        lines.append(f"  IP: {dns['resolved_ip']}")
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        records = dns.get(rtype)
        if records:
            lines.append(f"  {rtype}: {', '.join(str(r)[:120] for r in records[:5])}")
    return lines or ["  (no data)"]


def _fmt_email(data: dict) -> list[str]:
    lines = []
    if "deliverable" in data:
        lines.append(f"  Mail deliverable (MX present): {data['deliverable']}")
    mx = data.get("mx") or {}
    if mx.get("mx"):
        lines.append(f"  MX: {', '.join(str(s) for s in mx['mx'][:4])}")
    if mx.get("error"):
        lines.append(f"  MX error: {mx['error']}")
    for key, label in (("is_free_provider", "free-mail provider"),
                       ("is_disposable", "disposable address")):
        if key in data:
            lines.append(f"  {label}: {data[key]}")

    grav = data.get("gravatar") or {}
    if grav.get("exists"):
        lines.append(f"  Gravatar present: {grav.get('profile_url') or grav.get('avatar_url')}")

    scan = data.get("account_scan") or {}
    found = [r for r in (scan.get("results") or []) if r.get("status") == "found"]
    if found:
        lines.append(f"  Handle reuse ({len(found)}): "
                     + ", ".join(f"{r.get('name', '?')} {r.get('url', '')}" for r in found[:10]))
    return lines or ["  (no data)"]


def _fmt_username(data: dict) -> list[str]:
    results = data.get("results")
    if not isinstance(results, list):
        return ["  (no data)"]

    lines = []
    found = [r for r in results if isinstance(r, dict) and r.get("status") == "found"]
    manual = [r for r in results if isinstance(r, dict) and r.get("status") == "manual"]

    lines.append(f"  Platforms checked: {data.get('total_sites', len(results))}, "
                 f"confirmed: {len(found)}, to check manually: {len(manual)}")
    for account in found[:15]:
        lines.append(f"  - {account.get('name', '?')}: {account.get('url', '')}")
    for account in manual[:5]:
        lines.append(f"  - (unconfirmed) {account.get('name', '?')}: {account.get('url', '')}")
    return lines


def _fmt_wiki(data: dict) -> list[str]:
    if not data or not data.get("extract"):
        return ["  (no Wikipedia entry)"]
    return [f"  {data['title']} ({data.get('lang', '')}): {data['extract']}", f"  {data.get('url', '')}"]


def _fmt_page(data: dict) -> list[str]:
    return [f"  {data['url']}", f"  {data['text']}"]


_FORMATTERS = {
    "search": _fmt_search,
    "domain": _fmt_domain,
    "email": _fmt_email,
    "username": _fmt_username,
    "wiki": _fmt_wiki,
    "page": _fmt_page,
}


def build_dossier(research: dict) -> str:
    if not research.get("results"):
        return ""

    blocks = []
    for item in research["results"]:
        data = item.get("data")
        if not isinstance(data, dict):
            continue
        if data.get("error"):
            blocks.append(f"### {item['label']}\n  Error: {data['error']}")
            continue
        formatter = _FORMATTERS.get(item["kind"])
        if not formatter:
            continue
        try:
            lines = formatter(data)
        except Exception as exc:
            lines = [f"  (formatting failed: {type(exc).__name__}: {exc})"]
        block = f"### {item['label']}\n" + "\n".join(lines)
        if len(block) > _MAX_BLOCK_CHARS:
            block = block[:_MAX_BLOCK_CHARS] + "\n  [truncated]"
        blocks.append(block)

    for note in research.get("notes", []):
        blocks.append(f"### Note\n  {note}")

    dossier = "\n\n".join(blocks)
    if len(dossier) > _MAX_DOSSIER_CHARS:
        dossier = dossier[:_MAX_DOSSIER_CHARS] + "\n\n[dossier truncated]"
    return dossier


async def research_for(found: dict[str, list[str]], extra_queries: list[str] | None = None,
                       deep: bool = True) -> dict:
    plan = plan_research(found, extra_queries, deep)
    research = await run_research(plan)
    research["dossier"] = build_dossier(research)
    research["plan"] = [label for _k, _t, label in plan]
    return research
