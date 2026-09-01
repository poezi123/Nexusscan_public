"""
Web / Domain OSINT
------------------
Given a URL or domain, returns:
  * WHOIS report (registrar, dates, name servers, status, etc.)
  * Discovered subdomains (via Certificate Transparency logs @ crt.sh)
  * Resolved A/AAAA records and a few common DNS records.

No API keys required. Certificate Transparency is a passive, public
data source and does not touch the target host directly.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from urllib.parse import urlparse

import httpx

try:
    import dns.resolver  # type: ignore
    _HAVE_DNS = True
except Exception:  # pragma: no cover
    _HAVE_DNS = False

try:
    import whois as _whois  # python-whois
    _HAVE_WHOIS = True
except Exception:  # pragma: no cover
    _HAVE_WHOIS = False


_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$")


def normalize_domain(raw: str) -> str | None:
    raw = (raw or "").strip().lower()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    host = urlparse(raw).hostname or ""
    host = host.strip(".")
    # strip a leading www. for the base lookup
    if host.startswith("www."):
        host = host[4:]
    if not host or not _DOMAIN_RE.match(host):
        return None
    return host


def _clean(value):
    """Flatten python-whois values (which are sometimes lists) into strings."""
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        out = []
        for v in value:
            if v is None:
                continue
            s = str(v)
            if s not in out:
                out.append(s)
        return out or None
    return str(value)


async def get_whois(domain: str) -> dict:
    def _lookup():
        if not _HAVE_WHOIS:
            return {"error": "python-whois not installed"}
        try:
            w = _whois.whois(domain)
        except Exception as exc:  # network / parse errors
            return {"error": f"WHOIS lookup failed: {exc}"}
        if not w or not any(w.values()):
            return {"error": "No WHOIS data found for this domain."}
        return {
            "domain_name": _clean(w.get("domain_name")),
            "registrar": _clean(w.get("registrar")),
            "whois_server": _clean(w.get("whois_server")),
            "creation_date": _clean(w.get("creation_date")),
            "expiration_date": _clean(w.get("expiration_date")),
            "updated_date": _clean(w.get("updated_date")),
            "name_servers": _clean(w.get("name_servers")),
            "status": _clean(w.get("status")),
            "emails": _clean(w.get("emails")),
            "org": _clean(w.get("org")),
            "country": _clean(w.get("country")),
            "registrant_name": _clean(w.get("name")),
        }

    return await asyncio.to_thread(_lookup)


def _add_sub(subs: set[str], name: str, domain: str) -> None:
    name = (name or "").strip().lower().lstrip("*.")
    if name.endswith(domain) and _DOMAIN_RE.match(name):
        subs.add(name)


async def _src_hackertarget(domain: str, client: httpx.AsyncClient, subs: set[str]) -> str | None:
    """api.hackertarget.com — fast, also returns resolved IPs."""
    try:
        resp = await client.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20.0
        )
        if resp.status_code == 200 and "," in resp.text and "error" not in resp.text.lower():
            for line in resp.text.splitlines():
                host = line.split(",")[0]
                _add_sub(subs, host, domain)
            return None
        return f"hackertarget: {resp.text[:60]}"
    except Exception as exc:
        return f"hackertarget: {exc}"


async def _src_certspotter(domain: str, client: httpx.AsyncClient, subs: set[str]) -> str | None:
    """api.certspotter.com — certificate transparency issuances."""
    try:
        resp = await client.get(
            "https://api.certspotter.com/v1/issuances",
            params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
            timeout=25.0,
        )
        if resp.status_code == 200:
            for entry in resp.json():
                for name in entry.get("dns_names", []):
                    _add_sub(subs, name, domain)
            return None
        return f"certspotter: HTTP {resp.status_code}"
    except Exception as exc:
        return f"certspotter: {exc}"


async def _src_crtsh(domain: str, client: httpx.AsyncClient, subs: set[str]) -> str | None:
    """crt.sh — comprehensive but often slow; short timeout so it never blocks."""
    try:
        resp = await client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15.0
        )
        if resp.status_code == 200 and resp.text.strip():
            try:
                data = resp.json()
            except Exception:
                import json
                text = resp.text.replace("}{", "},{")
                data = json.loads(f"[{text}]") if not text.startswith("[") else []
            for entry in data:
                for name in entry.get("name_value", "").splitlines():
                    _add_sub(subs, name, domain)
            return None
        return f"crt.sh: HTTP {resp.status_code}"
    except Exception as exc:
        return f"crt.sh: {exc}"


async def get_subdomains(domain: str, client: httpx.AsyncClient) -> dict:
    """Aggregate subdomains from several passive CT / DNS sources.

    Sources run concurrently; a slow or failed source never blocks the others.
    """
    subs: set[str] = set()
    results = await asyncio.gather(
        _src_hackertarget(domain, client, subs),
        _src_certspotter(domain, client, subs),
        _src_crtsh(domain, client, subs),
    )
    subs.discard(domain)
    errors = [e for e in results if e]
    # Only surface an error if EVERY source failed and we found nothing.
    error = "; ".join(errors) if (errors and not subs) else None
    return {
        "subdomains": sorted(subs),
        "count": len(subs),
        "sources_ok": 3 - len(errors),
        "error": error,
    }


async def get_dns(domain: str) -> dict:
    def _resolve():
        records: dict = {}
        # Basic A record via socket as a fallback
        try:
            ip = socket.gethostbyname(domain)
            records["resolved_ip"] = ip
        except Exception:
            records["resolved_ip"] = None

        if not _HAVE_DNS:
            return records

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 6.0
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                answers = resolver.resolve(domain, rtype)
                vals = []
                for r in answers:
                    vals.append(r.to_text().strip('"'))
                if vals:
                    records[rtype] = vals
            except Exception:
                continue
        return records

    return await asyncio.to_thread(_resolve)


async def analyze_domain(raw: str) -> dict:
    domain = normalize_domain(raw)
    if not domain:
        return {"ok": False, "error": "Invalid domain / URL. Example: example.com"}

    headers = {"User-Agent": "OSINT-Dashboard/1.0 (+research)"}
    async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
        whois_task = get_whois(domain)
        subs_task = get_subdomains(domain, client)
        dns_task = get_dns(domain)
        whois_data, subs_data, dns_data = await asyncio.gather(
            whois_task, subs_task, dns_task
        )

    return {
        "ok": True,
        "domain": domain,
        "whois": whois_data,
        "subdomains": subs_data,
        "dns": dns_data,
    }
