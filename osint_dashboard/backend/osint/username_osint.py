"""
Username OSINT (Sherlock-style)
-------------------------------
Concurrently probes a curated catalogue of 90+ sites to determine where a
given username is registered. Returns per-site results with URLs, so
findings are directly viewable/clickable in the web UI.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

import httpx

from .sites import SITES

_USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Substrings that reveal an anti-bot / CAPTCHA interstitial instead of a real
# page. When present we cannot trust a 200, so the site is reported as "blocked"
# rather than a (false) hit.
_BLOCK_MARKERS = (
    "client challenge",
    "just a moment",
    "attention required",
    "cf-browser-verification",
    "captcha-delivery",
    "px-captcha",
    "enable javascript and cookies to continue",
    "verifying you are human",
    "/cdn-cgi/challenge-platform",
    "request unsuccessful. incapsula",
)


def valid_username(username: str) -> bool:
    return bool(_USERNAME_RE.match(username or ""))


def _looks_blocked(body: str) -> bool:
    low = body[:4000].lower()
    return any(m in low for m in _BLOCK_MARKERS)


def _handle_on_page(body: str, url: str, handle: str) -> bool:
    """Does the handle genuinely appear on the page (not merely echoed inside
    the request URL)?

    SPA soft-404 shells return HTTP 200 and reflect the requested path in
    <link rel=canonical>, og:url, etc. — so the raw handle is "present" even
    when the account doesn't exist. We strip those URL echoes first; a real
    profile still names the handle in its <title>, display name or JSON state.
    """
    low = body.lower()
    h = handle.lower()
    try:
        path = urlparse(url).path.lower()
    except Exception:
        path = ""
    # Remove full-URL and path echoes (canonical/og:url/anchor hrefs).
    low = low.replace(url.lower(), " ")
    if path and h in path:
        low = low.replace(path, " ")
    return h in low


async def _check_site(site: dict, username: str, client: httpx.AsyncClient) -> dict:
    url = site["url"].format(username)
    result = {
        "name": site["name"],
        "url": url,
        "category": site.get("cat", "misc"),
        "status": "unknown",   # found | not_found | error | blocked
        "http": None,
    }
    try:
        resp = await client.get(url, timeout=15.0)
        result["http"] = resp.status_code
        check = site.get("check", "status")
        body = resp.text or ""

        # Anti-bot interstitial -> we can't judge this site right now.
        if resp.status_code == 200 and _looks_blocked(body):
            result["status"] = "blocked"
            return result

        # Access blocked / rate-limited -> not an error, just unverifiable now.
        if resp.status_code in (401, 403, 429, 503):
            result["status"] = "blocked"
            return result

        if check == "message":
            # Presence of the site's "missing account" marker == not found.
            absence = site.get("absence", "")
            if resp.status_code in (404, 410):
                result["status"] = "not_found"
            elif 300 <= resp.status_code < 400:
                result["status"] = "not_found"
            elif resp.status_code >= 400:
                result["status"] = "error"
            elif absence and absence.lower() in body.lower():
                result["status"] = "not_found"
            else:
                result["status"] = "found"
            return result

        # check == "status": a 200 alone is not enough on modern sites (SPA
        # shells & soft-404s return 200). Require the handle to actually appear
        # on the page unless the site is trusted to hard-404.
        if resp.status_code in (404, 410):
            result["status"] = "not_found"
        elif resp.status_code in (301, 302, 303, 307, 308):
            result["status"] = "not_found"
        elif resp.status_code == 200:
            if site.get("reliable") is False:
                # JS-only site whose real/missing pages are byte-identical over
                # plain HTTP -> we honestly cannot auto-verify; flag for review.
                result["status"] = "manual"
            elif site.get("trust_200"):
                result["status"] = "found"
            elif _handle_on_page(body, url, username):
                result["status"] = "found"
            else:
                # 200 but handle absent -> almost always a soft-404 / shell.
                result["status"] = "not_found"
        elif resp.status_code >= 400:
            result["status"] = "error"
        else:
            result["status"] = "not_found"

    except (httpx.TimeoutException,):
        result["status"] = "error"
        result["http"] = "timeout"
    except Exception as exc:
        result["status"] = "error"
        result["http"] = str(exc)[:60]

    return result


async def probe_sites(handle: str, client: httpx.AsyncClient) -> dict:
    """Probe the whole site catalogue for `handle` and aggregate the results.

    Shared by the Username block and the Email block (which feeds it the
    local-part of the address), so both use identical detection logic.
    """
    tasks = [_check_site(site, handle, client) for site in SITES]
    results = await asyncio.gather(*tasks)

    found = [r for r in results if r["status"] == "found"]
    not_found = [r for r in results if r["status"] == "not_found"]
    errors = [r for r in results if r["status"] == "error"]
    blocked = [r for r in results if r["status"] == "blocked"]
    manual = [r for r in results if r["status"] == "manual"]

    # Sort: found first (by name), then keep others
    results.sort(key=lambda r: (r["status"] != "found", r["name"].lower()))

    return {
        "handle": handle,
        "total_sites": len(SITES),
        "found_count": len(found),
        "not_found_count": len(not_found),
        "error_count": len(errors),
        "blocked_count": len(blocked),
        "manual_count": len(manual),
        "results": results,
    }


async def analyze_username(username: str) -> dict:
    username = (username or "").strip()
    if not valid_username(username):
        return {
            "ok": False,
            "error": "Invalid username. Allowed: letters, digits, . _ - (max 64).",
        }

    limits = httpx.Limits(max_connections=40, max_keepalive_connections=40)
    async with httpx.AsyncClient(
        headers=_HEADERS, follow_redirects=False, limits=limits
    ) as client:
        scan = await probe_sites(username, client)

    scan["ok"] = True
    scan["username"] = username
    return scan
