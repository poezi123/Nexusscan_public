ENTRIES = [

    {
        "category": "Reconnaissance",
        "title": "01 · BlackWire port scanner",
        "body": """
# BlackWire (blackwire.py)

A concurrent TCP port scanner with banner grabbing, service detection, optional
CVE mapping and a web-analysis mode. Version 3.1, ~1000 lines, standard library
plus `colorama` only.

## Scan flow

- `parse_ports()` turns inputs like `80,443,1-1000` into a port list;
  `get_default_ports(top=N)` returns the most common N ports.
- `run_scan()` spreads the ports over a `ThreadPoolExecutor` (50 threads by
  default) and calls `scan_port()` per port.
- `scan_port()` opens a TCP connect (`make_socket()` with timeout). If the port
  is open, it optionally reads a **banner**; for HTTP(S) `grab_http_banner()`
  handles it (also over TLS via `ssl`).
- `extract_banner_version()` pulls product/version from the banner via regex,
  `get_service_name()` maps port numbers to service names.

## CVE mapping

- `load_cve_db()` loads `cve_db.json` (cached in `_cve_db`).
- `lookup_cves(service, version)` looks up known weaknesses for the detected
  service - reference only, no exploit.

## Web analysis (`web` command)

- `fetch_http_headers()` / `analyze_headers()` check security headers
  (HSTS, CSP, X-Frame-Options ...).
- `scan_subdomains()` tests a subdomain wordlist in parallel via
  `check_subdomain()`.

## Output

`show_results()` formats hits with color; `export_json()` writes a
machine-readable result. Launched from the menu via `import blackwire` +
`load_cve_db()`.
""",
    },
    {
        "category": "Reconnaissance",
        "title": "02 · Packet sniffer",
        "body": """
# Packet sniffer (Nexusscan.py, case "2")

A live capture of network traffic based on **Scapy**. Needs root (raw sockets).

## How it works

- Scapy's `sniff()` captures packets and calls a callback per packet that reads
  the layers (Ethernet/IP/TCP/UDP, ports, flags, payload snippets).
- An `IDLE_TIMEOUT` (10 s) and `last_packet_time` stop the capture on inactivity
  so the menu loop doesn't hang.
- The display summarizes source/destination, protocol and relevant headers per
  packet.

Passive: only reads packets, injects nothing. Useful for analyzing your own or
an authorized network.
""",
    },
    {
        "category": "Reconnaissance",
        "title": "03 · IP-MAC mapper",
        "body": """
# IP → MAC → hostname resolver (Nexusscan.py, case "3")

Passive network discovery: listens to traffic (Scapy) and builds a table of
**IP address, MAC address and (where resolvable) hostname**.

## How it works

- IP↔MAC pairs are extracted from captured ARP/IP packets.
- MAC prefixes (OUI) point to the hardware vendor.
- Reverse DNS / hostname resolution adds the device name where possible.

Because it listens passively (no active ARP scanning needed) it is quiet on the
network. Root required.
""",
    },
    {
        "category": "Reconnaissance",
        "title": "04 · CVE exploit database",
        "body": """
# CVE exploit database (cve_exploit_database/)

A reference for vulnerabilities from the official **NVD** (National Vulnerability
Database). Reference only - shows CVE IDs, CVSS, CWE and links; it does not fetch
or run exploit code.

## Modules

- **`nvd_client.py`** - HTTP client for the NVD API. `_pace()` throttles requests
  (0.7 s with an API key, 6 s without) to respect the rate limits; an
  `NVD_API_KEY` from the environment or via `--api-key` raises the limit.
- **`db_handler.py`** - local SQLite cache (`cve_cache.sqlite3`) so repeat
  queries run fast and offline.
- **`cve_categories.py`** - categories such as RCE, SQLi, XSS, path traversal,
  buffer overflow, privilege escalation, auth bypass, DoS, SSRF, deserialization,
  XXE, command injection ... for filtering.
- **`cve_lookup.py`** - the search logic: by service+version or keyword, with
  real numeric version-range matching instead of a plain text compare.

## Menu

`Nexusscan.py` (case "4") optionally asks for an NVD API key and passes it to
`cve_lookup` via `--api-key`.
""",
    },

    {
        "category": "Offensive",
        "title": "05 · DoS attack",
        "body": """
# DoS tool (Nexusscan.py, case "5")

A load / DoS tool for **authorized** stress testing. Uses threads to send many
requests against a target in parallel.

## How it works

- Several worker threads generate traffic; `packets_sent` / `bytes_sent` are
  counted under a `stats_lock` (thread lock) to avoid race conditions in the
  statistics.
- A live display shows packet/byte rate.

⚠ Only use against your own or explicitly authorized systems - otherwise illegal.
Intended as a stress test within an authorized scope.
""",
    },
    {
        "category": "Offensive",
        "title": "06 · SQLMap (integrated)",
        "body": """
# SQLMap (vendored, Nexusscan.py, case "6")

SQLMap is the well-known open-source tool for SQL-injection detection and
exploitation. It ships **as a copy in the project folder** (`sqlmap/`) and is not
installed separately.

## Integration

- NexusScan runs the vendored `sqlmap.py` via `subprocess` with the parameters
  you choose (target URL, database options ...).
- Because it is bundled, it works without extra installation and at a known
  version.

The SQLMap code itself is third-party (its own project/license); NexusScan only
launches it, it does not modify it.
""",
    },
    {
        "category": "Offensive",
        "title": "07 · Airbreak (Wi-Fi)",
        "body": """
# Airbreak (Nexusscan.py, case "7")

A Wi-Fi attack/test workflow around the **aircrack-ng suite**. For authorized
Wi-Fi security tests. Needs root and a wireless adapter with monitor mode.

## Tools used

`aircrack-ng`, `airmon-ng`, `airodump-ng`, `mdk4`, `aireplay-ng` - Airbreak
installs these on first use if needed.

## Flow

- **Monitor mode:** `airmon-ng` switches the interface (e.g. `wlan0` →
  `wlan0mon`).
- **Scan:** `airodump-ng` lists networks/clients and records handshakes.
- **Deauth:** `mdk4`/`aireplay-ng` send deauth frames (in their own gnome-terminal
  window) to force a WPA handshake.
- **Capture check:** NexusScan looks via `ls | grep handshake_capture` whether a
  handshake was captured and aborts cleanly otherwise.
- **Cracking:** `aircrack-ng` tests the handshake against a wordlist.

⚠ Only in your own / authorized Wi-Fi. Deauth actively disrupts the radio.
""",
    },
    {
        "category": "Offensive",
        "title": "08 · XSS scanner",
        "body": """
# XSS scanner (Nexusscan.py, case "8")

Tests web forms/parameters for **cross-site scripting**, using the standard
library only (`urllib.request`, `urllib.parse`).

## How it works

- Loads the target page and finds input points (form fields, URL parameters).
- Injects known XSS payloads (marker strings) and reloads the response.
- If the marker appears **unescaped** in the response, the parameter is
  considered vulnerable (reflected XSS).

Lightweight and without a browser engine - so it detects reflected XSS, not
DOM/stored XSS that requires JavaScript execution.
""",
    },

    {
        "category": "Open Source Intelligence",
        "title": "09 · Sherlock",
        "body": """
# Sherlock (Nexusscan.py, case "9")

Searches a **username** across hundreds of platforms. Sherlock is an established
OSINT project (github.com/sherlock-project) installed as a package
(`sherlock-project`) by the installer.

## How it works

- Each known service has a URL template with the username.
- Sherlock fetches the profiles in parallel and decides from HTTP status / page
  content whether an account exists.
- NexusScan launches Sherlock with the handle you enter.

Purely passive (public profile pages). The dashboard's own "Username" block does
something similar with its own logic.
""",
    },
    {
        "category": "Open Source Intelligence",
        "title": "15 · OSINT dashboard",
        "body": """
# OSINT dashboard (osint_dashboard/)

A web UI (FastAPI backend + animated frontend) launched from menu 15.
`Nexusscan.py` starts `run.sh` with its own Python (`PYTHON=sys.executable`),
opens the browser and blocks until Ctrl+C.

## Backend (`backend/`)

- **`app.py`** - the FastAPI app with endpoints `/api/web`, `/api/username`,
  `/api/email`, `/api/phone`, `/api/ai`, `/api/ai/status`, `/api/health`, and it
  serves the static frontend.
- **`osint/web_osint.py`** - domain analysis: WHOIS (`python-whois`), DNS
  (`dnspython`), subdomains from **Certificate Transparency** logs (crt.sh,
  certspotter, hackertarget - in parallel so one slow source doesn't block).
- **`osint/username_osint.py`** - checks 90+ platforms; a hit needs hard
  evidence (404 on the "missing" page, a not-found marker, or the handle actually
  appearing), otherwise "check manually".
- **`osint/email_osint.py`** - MX/deliverability, free/disposable classification,
  Gravatar, handle reuse.
- **`osint/phone_osint.py`** - `phonenumbers` (Google's libphonenumber, offline):
  country, carrier, line type, timezone.

## Frontend

`index.html` + `script.js` + `style.css`: a "hacker-terminal" look, a form per
block, `fetch()` to the API, result rendering. The AI block has a safe
mini-Markdown renderer (escape before rendering, http/https links only).

For the AI part in detail see "AI OSINT analyst".
""",
    },
    {
        "category": "Open Source Intelligence",
        "title": "15b · AI OSINT analyst (local)",
        "body": """
# AI OSINT analyst (osint_dashboard/backend/osint/ai_osint.py)

The AI block correlates pasted free-form material and suggests research -
**fully local, no API key**.

## Backend selection

`analyze_intel()` tries backends in order (`_backend_order()`):
- **Ollama** (`localhost:11434`) → **OpenAI-compatible local server**
  (LM Studio :1234, llama.cpp :8080, vLLM :8000, TGW :5000) → **offline analyzer**.
- Settings come from `nexus_config.json` / `NEXUS_AI_*` variables through a
  `_cfg()` resolver (ENV > config > default), set in Settings/menu 99.

## Offline analyzer (always available, no LLM)

Regex extraction of entities (e-mails, domains, IPs, handles, phone numbers,
dates, BTC/ETH wallets, hashes, IBANs, CVEs, GPS, names), plus correlation:
identifier reuse (mail local-part = handle = name fragment), shared mail domains,
time range. Clearly labels hypotheses as such.

## Live research (web_research.py)

Before analysis the extracted entities are looked up in **public, key-less**
sources: DuckDuckGo (results + snippets + instant answer), Wikipedia, and the
dashboard's own modules (WHOIS/DNS/CT, MX, platform profiles). Top hits are read
in full text and handed to the model as a dossier. The model may ask up to three
follow-ups, answered in a second round. The budget is capped in `web_research.py`
(90 s, 9000-char dossier). Toggleable per request.

Note: with live research enabled, search terms leave the machine; without it,
everything stays local.
""",
    },
    {
        "category": "Cryptography & Messaging",
        "body": """
# Your identity, and what an invite actually contains

## Three key pairs, generated locally, registered nowhere

The first time you open the Contacts tab, `core/identity.py` creates a permanent
local identity. It persists, so your address never changes unless you change it:

- **Ed25519 onion key** — generated by Tor, defines your `.onion` address.
- **X25519 pair `(a, A)`** — for elliptic-curve pairing (the recommended method).
- **RSA-4096 pair** — for the alternative sealed-key pairing method.

All three live in `identity.dat`, which is itself AES-256 encrypted at rest.

## Your address IS your public key

A v3 onion address is not a name registered with anybody. It is literally:

```
base32(ed25519_public_key || checksum || version) + ".onion"
```

That has a consequence worth pausing on: there is **no DNS and no certificate
authority** anywhere in the path. When someone connects to your `.onion`, the
address itself is the proof of who they reached — either the connection
terminates at the holder of that private key, or it fails. There is no third
party to compromise, poison or subpoena in order to redirect it.

## The invite code, field by field

`pairing.make_invite()` builds a small JSON object and base64url-encodes it:

```
{
  "v":      1,
  "onion":  "abcd...xyz.onion",
  "x25519": "<32-byte public key, hex>",
  "rsa":    "<RSA-4096 public key, PEM, base64>"
}
```

That is the whole thing. Note what is **not** in it: no private key, no shared
secret, no password, no IP address, no username, no e-mail, no device
identifier, no timestamp. Every field is public by construction.

So an invite code is safe to hand over an untrusted channel **as far as
confidentiality goes** — someone who records both invite codes still cannot
derive the key. What it *does* reveal is that this address exists and someone
wants to be reached at it. That is an anonymity question, not an encryption
question, and it is exactly what the Usage tab's recommendations are about.
""",
    },
    {
        "category": "System & Suite",
        "title": "99 · Settings",
        "body": """
# Settings (nexus_settings/, menu 99)

A PyQt window to manage the suite. Tabs:

- **Storage:** breakdown of space used including dependencies (`nexusvenv`,
  Ollama binary, models) - computed in `sysinfo.py` (`storage_breakdown`, model
  sizes via the Ollama API).
- **Python packages:** install/uninstall individual packages in `nexusvenv`
  (`pip_install`/`pip_uninstall`, targeting `nexusvenv/bin/python`). Warns if the
  venv is owned by root (`venv_writable`).
- **Ollama & AI** (only if Ollama is installed): pull/remove models, start/stop
  the server (systemd/OpenRC or `ollama serve`), AI settings (backend, model, max
  tokens, timeout, follow-up round, live research) → `nexus_config.json`, which
  the dashboard reads.
- **Maintenance:** delete + rebuild the compiled AES assembly (`build.sh`), and
  **export as a ZIP** (`export_project_zip`) - a clean, installable copy without
  the venv, caches, compiled binaries or Ollama models.

Config lives in `nexus_config.json`; environment variables take precedence.
""",
    },
    {
        "category": "System & Suite",
        "title": "100 · These docs",
        "body": """
# Module documentation (nexus_docs/, menu 100)

This window. `content.py` holds the texts as `ENTRIES` and `USAGE_ENTRIES`
(`{category, title, body}`); `docs_window.py` shows the tree on the left and the
rendered text on the right (a small Markdown→HTML renderer in `_render`), split
into "How it works" and "Usage" tabs. `__init__.py` offers `launch()` like
Settings.

Documenting a new module = add an entry to `ENTRIES` (or `USAGE_ENTRIES`).
""",
    },
]


USAGE_ENTRIES = [
    {
        "category": "Per-tool usage",
        "title": "01 · BlackWire port scanner",
        "body": """
# Using BlackWire (menu 1)

A fast TCP port scanner with service/version detection.

## Step by step
1. Pick **scan** (host) or **web** (domain analysis).
2. **Target:** an IP or hostname, e.g. `192.168.1.10` or `example.com`.
3. **Ports:** choose one of
   - a list/range: `22,80,443` or `1-1000`
   - top-N most common ports (e.g. top 100)
   - full range `1-65535` (slow).
4. **Banner grabbing:** leave on to detect the service and version behind each
   open port. Turn off for a faster, quieter scan.
5. Optionally export the result to JSON.

## Reading the result
- Each open port shows the guessed **service** and, if banner grabbing found it,
  a **version**.
- When a version is detected, BlackWire lists any **known CVEs** for it from the
  local `cve_db.json` — reference only, it runs nothing.

## Web mode
Give a domain to get **security-header** analysis (HSTS, CSP, X-Frame-Options …)
and **subdomain** enumeration from a wordlist.

## Tips & safety
- Threads default to 50; raise them for speed on a fast link, lower them to be
  gentle.
- Scan only hosts you own or are authorized to test.
""",
    },
    {
        "category": "Per-tool usage",
        "title": "02/03 · Sniffer & IP-MAC mapper",
        "body": """
# Packet sniffer (menu 2) / IP-MAC mapper (menu 3)

Both read live network traffic with Scapy and **need root** (`sudo`). They are
passive — nothing is sent onto the network.

## Packet sniffer (2)
1. Start it (with root). It begins capturing immediately.
2. Each packet is summarized: source/destination, protocol (TCP/UDP/…), ports,
   flags, and a snippet of the payload.
3. It **stops itself after ~10 seconds** with no packets, so the menu doesn't
   hang. Generate some traffic (open a website) to see output.

Use it to inspect what is really flowing on your own/authorized network.

## IP-MAC mapper (3)
1. Start it (with root); it listens passively.
2. It builds a table **IP → MAC → hostname**: which IP belongs to which MAC
   (hardware address), the vendor from the MAC prefix, and a hostname via reverse
   DNS where available.
3. Let it run a while — devices only appear once they send traffic.

## Common issues
- **No output / permission error** → you're not root. Re-run with `sudo`.
- **Nothing appears** → the interface is idle; cause some traffic, or you're on a
  switched network where you only see broadcast/your own traffic.
""",
    },
    {
        "category": "Per-tool usage",
        "title": "04 · CVE database",
        "body": """
# CVE exploit database (menu 4)

Look up vulnerabilities from the official NVD. Reference only — no exploit is
fetched or run.

## First use
- On first run the local cache is empty; it fills from the NVD API.
- **No API key is required** — it works fine without one; you just get lower NVD
  rate limits (slower, ~6 s between requests instead of ~0.7 s).
- A key is purely optional to speed things up. If you want one, get a free key at
  nvd.nist.gov and either paste it when asked, or set it once with
  `export NVD_API_KEY=...` before starting NexusScan.

## Searching
1. Search by **service + version** (e.g. `openssh 8.2`) or by **keyword**.
2. Optionally **filter by category**: RCE, SQLi, XSS, path traversal, buffer
   overflow, privilege escalation, auth bypass, DoS, SSRF, deserialization, XXE,
   command injection, hardcoded credentials.
3. Results list **CVE ID, CVSS score, CWE** and a link to the official NVD
   advisory. Version matching is real numeric range matching, not text compare.

## Tips
- Once the cache is populated, searches run offline and fast.
- Pair it with BlackWire: scan a host, note the service versions, look them up
  here.
""",
    },
    {
        "category": "Per-tool usage",
        "title": "05 · DoS / stress test",
        "body": """
# DoS tool (menu 5)

A load generator for **authorized** stress testing. ⚠ Using it against systems
you don't own or aren't allowed to test is illegal.

## Step by step
1. Enter the **target** (host/IP) and the parameters it asks for.
2. Worker threads start sending traffic in parallel.
3. A live display shows the **packet and byte rate** and running totals.
4. Stop it when done.

## Use it responsibly
- Only against your own lab / systems you have written permission to test.
- Watch the target's health; the point is to measure resilience, not to cause
  lasting damage.
""",
    },
    {
        "category": "Per-tool usage",
        "title": "06 · SQLMap",
        "body": """
# SQLMap (menu 6)

Runs the bundled SQLMap for SQL-injection detection and exploitation. SQLMap is a
mature third-party tool; NexusScan just launches the copy in `sqlmap/`.

## Step by step
1. Provide the **target URL** (e.g. `http://site/item?id=1`) and any options the
   prompt offers.
2. NexusScan starts SQLMap with those parameters.
3. Follow SQLMap's own prompts (it asks about testing more parameters, dumping
   data, etc.).

## Tips
- Start narrow (one URL/parameter) before enabling deeper options.
- For the full option set, SQLMap's own documentation applies — it's the real
  tool underneath.
- Authorized targets only.
""",
    },
    {
        "category": "Per-tool usage",
        "title": "07 · Airbreak (Wi-Fi)",
        "body": """
# Airbreak (menu 7)

A WPA handshake capture + crack workflow around the aircrack-ng suite. Needs
**root** and a wireless adapter that supports **monitor mode**. On first use it
installs aircrack-ng/mdk4/gnome-terminal if missing. ⚠ Your own / authorized
Wi-Fi only — deauth actively disrupts the radio.

## Step by step
1. Start with `sudo`.
2. **Monitor mode** is enabled on your adapter via `airmon-ng` (e.g. `wlan0` →
   `wlan0mon`).
3. `airodump-ng` lists nearby networks and clients. Note the target's **BSSID**
   and **channel**.
4. **Deauth** (mdk4/aireplay) is fired in a separate terminal to force a client
   to reconnect, which captures the **WPA handshake**.
5. NexusScan checks for a `handshake_capture` file — if none was caught it stops
   cleanly so you can retry.
6. `aircrack-ng` tests the captured handshake against a **wordlist** you provide.

## Common issues
- **No monitor mode** → your adapter/driver doesn't support it; use one that
  does.
- **No handshake** → no client reconnected; try again, get closer, or wait for a
  client to be active.
- Cracking only succeeds if the passphrase is in your wordlist.
""",
    },
    {
        "category": "Per-tool usage",
        "title": "08 · XSS scanner",
        "body": """
# XSS scanner (menu 8)

Finds **reflected** cross-site scripting in URL parameters and forms.

## Step by step
1. Give a **target URL**, ideally one with parameters, e.g.
   `http://site/search?q=test`.
2. The scanner injects marker payloads into each parameter/form field and
   reloads the response.
3. If a payload comes back **unescaped** in the page, that parameter is flagged
   as vulnerable, and the URL + payload are shown.
4. You can also scan **multiple URLs from a file**.

## What it does and doesn't catch
- Catches **reflected** XSS (payload echoed straight back).
- Does **not** catch DOM-based or stored XSS that only triggers via JavaScript —
  there's no browser engine, it inspects the raw HTML response.

## Tip
Point it at URLs that actually take parameters; a static page with no inputs has
nothing to test (it will tell you so).
""",
    },
    {
        "category": "Per-tool usage",
        "title": "09 · Sherlock (usernames)",
        "body": """
# Sherlock (menu 9)

Hunts a **username** across hundreds of platforms. Uses the `sherlock-project`
package installed by the installer.

## Step by step
1. Enter the handle to search (e.g. `johndoe`).
2. Sherlock checks each known platform's profile URL in parallel and reports
   where an account with that name exists.
3. Review the list of found profiles.

## Tips
- Purely passive — it only requests public profile pages.
- Some platforms block automated checks; those may show as uncertain.
- The OSINT dashboard's **Username** block (menu 15) does a similar job with its
  own verification logic if you prefer a GUI.
""",
    },
    {
        "category": "Per-tool usage",
        "title": "15 · OSINT dashboard",
        "body": """
# OSINT dashboard (menu 15)

Opens a local web UI in your browser. Everything here is passive and needs no API
keys. Press **Ctrl+C** in the terminal to stop the dashboard and return to the
menu.

## The blocks
- **Web** — enter a domain → WHOIS, DNS records, and subdomains from Certificate
  Transparency logs.
- **Username** — a handle → accounts across 35+ platforms (hard-verified, or
  flagged "check manually").
- **Email** — an address → MX/deliverability, free/disposable classification,
  Gravatar, and handle reuse.
- **Phone** — a number in international format (`+49151…`) → country, carrier,
  line type, timezone (fully offline).

## AI analyst block
1. Paste any collected material (names, dates, handles, notes) into the big box.
2. Optionally write a **prompt** ("who is this / how does it connect?").
3. **Live research** checkbox:
   - **on** → it looks the detected entities up in public sources (DuckDuckGo,
     Wikipedia, WHOIS/DNS, MX, profiles) and feeds the model — your search terms
     leave the machine.
   - **off** → everything stays local; you still get entity extraction and
     correlation from the offline analyzer.
4. The engine badge at the top shows which local backend is active (Ollama, a
   local OpenAI-compatible server, or the offline analyzer). Configure it in
   Settings → Ollama & AI (menu 99).

## Notes
- On a CPU-only machine the AI can take a minute or two per analysis; a smaller
  model or turning live research off is faster.
- Free public sources (CT logs, etc.) have daily limits; the dashboard degrades
  gracefully if one is throttled.
""",
    },
    {
        "category": "Management",
        "title": "99 · Settings",
        "body": """
# Using Settings (menu 99)

A PyQt window that opens over the menu. Tabs:

## Storage
Shows how much disk the project and its dependencies use, broken down: project
code, the `nexusvenv`, the Ollama program, and Ollama models. Click
**Recalculate** to refresh.

## Python packages
Lists the packages in `nexusvenv`. Type a name and **Install**, or select one and
**Uninstall**. pip's output shows in the log box. If the venv is owned by root
(installed with sudo), you'll see a warning — run NexusScan with matching
privileges to change packages.

## Ollama & AI (only shown if Ollama is installed)
- See installed models with sizes; **pull** a new one or **delete** one.
- **Start/Stop** the Ollama server.
- Tune the dashboard's local AI: backend, model, **max tokens**, timeout,
  follow-up round, and whether **live research** is on by default. Saved to
  `nexus_config.json`; changes apply the next time the dashboard starts.

## Maintenance
- **Delete build / Rebuild now** — removes the compiled AES core
  (`libaes256.so`/`.o`) and rebuilds it from source via `build.sh`. Useful after
  updates or on a new machine.
- **Export as ZIP** — packs the whole project into a clean, shareable archive
  **without** the venv, caches, compiled binaries or Ollama models. The recipient
  just runs `install.py` and builds everything fresh. The export is
  pattern-based, so new files are always included as the suite grows.
""",
    },
    {
        "category": "Management",
        "title": "100 · These docs",
        "body": """
# Using the docs (menu 100)

- **How it works** tab — a technical explanation of each module's internals.
- **Usage** tab — this: step-by-step how-to for every tool.
- Use the **filter box** at the top of either tab to jump to a module by name.
- Links in the text open in your browser.

The content lives in `nexus_docs/content.py`; add an entry to `ENTRIES` or
`USAGE_ENTRIES` to document something new.
""",
    },
]
