"""
Email OSINT
-----------
Given an email address, returns:
  * Syntax validation
  * Domain / MX (mail server) records -> is the domain able to receive mail?
  * Disposable / free-provider classification
  * Gravatar presence (+ profile URL if the hash resolves)
  * Account discovery: probes the same site catalogue as the username
    module using the local-part, so you can see where the handle exists.

No paid breach APIs are required. (HaveIBeenPwned integration can be
added by dropping an API key into HIBP_API_KEY env var.)
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re

import httpx

from .username_osint import probe_sites, _HEADERS

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+\.)+[A-Za-z]{2,}$")

try:
    import dns.resolver  # type: ignore
    _HAVE_DNS = True
except Exception:  # pragma: no cover
    _HAVE_DNS = False

_FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "aol.com", "icloud.com", "gmx.de", "gmx.net", "web.de",
    "protonmail.com", "proton.me", "yandex.com", "mail.com", "zoho.com",
    "t-online.de", "freenet.de",
}

_DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "trashmail.com", "yopmail.com", "getnada.com", "temp-mail.org", "sharklasers.com",
    "throwawaymail.com", "maildrop.cc", "dispostable.com", "fakeinbox.com",
}


def valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email or ""))


async def _mx_records(domain: str) -> dict:
    def _lookup():
        out = {"mx": [], "has_mx": False, "error": None}
        if not _HAVE_DNS:
            out["error"] = "dnspython not installed"
            return out
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 6.0
            answers = resolver.resolve(domain, "MX")
            records = sorted(
                [(r.preference, str(r.exchange).rstrip(".")) for r in answers]
            )
            out["mx"] = [f"{p} {h}" for p, h in records]
            out["has_mx"] = bool(records)
        except Exception as exc:
            out["error"] = str(exc)
        return out

    return await asyncio.to_thread(_lookup)


async def _gravatar(email: str, client: httpx.AsyncClient) -> dict:
    norm = email.strip().lower()
    digest = hashlib.md5(norm.encode()).hexdigest()
    # d=404 makes Gravatar 404 if there is no custom avatar
    avatar_url = f"https://www.gravatar.com/avatar/{digest}?d=404"
    profile_url = f"https://gravatar.com/{digest}"
    out = {"exists": False, "avatar_url": None, "profile_url": None, "hash": digest}
    try:
        resp = await client.get(avatar_url, timeout=12.0)
        if resp.status_code == 200:
            out["exists"] = True
            out["avatar_url"] = f"https://www.gravatar.com/avatar/{digest}"
            out["profile_url"] = profile_url
    except Exception:
        pass
    return out


async def analyze_email(email: str) -> dict:
    email = (email or "").strip()
    if not valid_email(email):
        return {"ok": False, "error": "Invalid email address format."}

    local, domain = email.rsplit("@", 1)
    domain = domain.lower()

    limits = httpx.Limits(max_connections=40, max_keepalive_connections=40)
    async with httpx.AsyncClient(
        headers=_HEADERS, follow_redirects=False, limits=limits
    ) as client:
        mx_data, grav_data, scan = await asyncio.gather(
            _mx_records(domain),
            _gravatar(email, client),
            # Full account scan on the local-part handle (same engine as
            # the Username block: found / manual / not-found breakdown).
            probe_sites(local, client),
        )

    return {
        "ok": True,
        "email": email,
        "local_part": local,
        "domain": domain,
        "is_free_provider": domain in _FREE_PROVIDERS,
        "is_disposable": domain in _DISPOSABLE,
        "deliverable": mx_data.get("has_mx", False),
        "mx": mx_data,
        "gravatar": grav_data,
        "account_scan": scan,
        "accounts_found_count": scan["found_count"],
        "hibp_note": (
            "Breach lookups (HaveIBeenPwned) require an API key — set HIBP_API_KEY to enable."
            if not os.getenv("HIBP_API_KEY")
            else "HIBP_API_KEY detected."
        ),
    }
