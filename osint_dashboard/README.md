# 🛰️ OSINT Dashboard

A user-friendly, hacker-styled OSINT (Open-Source Intelligence) dashboard with a
Python backend and a live animated web UI. All four tools are **custom-built**
(no fragile external CLIs) and rely only on **passive, public data sources** — no
API keys required.

![style: hacker-terminal](https://img.shields.io/badge/style-hacker--terminal-00ff9c)
![backend: FastAPI](https://img.shields.io/badge/backend-FastAPI-009688)

## Blocks

| # | Block | Input | Output |
|---|-------|-------|--------|
| 01 | **WEB OSINT** | domain / URL | WHOIS report, subdomains (multi-source CT logs), DNS records |
| 01B | **AI OSINT ANALYST** | free-form text + prompt | Live research in public sources + correlations, hypotheses, timeline, sources — **local AI, no API key** |
| 02 | **USERNAME OSINT** | username | Accounts across 35+ platforms (Sherlock-style) |
| 03 | **EMAIL OSINT** | email | MX / deliverability, free/disposable class, Gravatar, handle reuse |
| 04 | **PHONE OSINT** | phone number | Country of origin, **carrier (Mobilfunk-Anbieter)**, line type, timezone |

## Quick start

```bash
./run.sh              # creates venv, installs deps, starts server on :8000
# or a custom port:
./run.sh 9000
```

The dashboard is also reachable as **menu 15** in NexusScan. Its dependencies (and
optionally the local AI) are set up by `sudo python3 install.py` in the project root.

Then open **http://127.0.0.1:8000** in your browser.

### Manual start

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

## How each tool works

- **Web OSINT** — WHOIS via `python-whois`; subdomains aggregated concurrently
  from **hackertarget**, **certspotter** and **crt.sh** (Certificate Transparency),
  so a single slow/failed source never blocks the result; DNS via `dnspython`.
- **Username OSINT** — probes a curated site catalogue concurrently. To avoid the
  classic false-positives, a hit requires either a hard-404 on the "missing" page,
  a site-specific "not found" marker, **or the handle actually appearing on the
  returned page**. Anti-bot/CAPTCHA interstitials and JS-only sites (Instagram,
  Spotify, …) that can't be verified over plain HTTP are flagged **CHECK MANUALLY**
  instead of reported as false hits.
- **Email OSINT** — syntax + MX (can the domain receive mail?), free-provider and
  disposable-domain classification, Gravatar presence, and account discovery by
  reusing the local-part as a handle across the site catalogue.
- **Phone OSINT** — Google's `libphonenumber` (offline DB) for country, geocoding,
  **carrier**, line type and timezone. Best results with international format
  (`+49 151 …`); otherwise pass a default region.
- **AI OSINT Analyst** — paste any collected material (names, places, dates,
  handles, notes) plus a prompt describing what you want to know. Runs on a
  **local model only — no API key, no cloud.**

  **Live research (on by default, toggle in the card).** Before the model sees
  anything, the dashboard extracts the entities from your text and looks them up
  in public, key-less sources: DuckDuckGo (results + snippets + instant answers),
  Wikipedia, plus its own passive modules (WHOIS, DNS, Certificate-Transparency
  subdomains, MX, Gravatar, 90+ platform profiles). The top hits are fetched and
  read in full text. All of it is handed to the model as a dossier, and the model
  may request **up to three follow-up searches** (`SUCHE: …`), which are executed
  for a second pass. Every answer lists the sources it used.

  Without live research the analysis stays entirely on your machine. With it,
  search terms — that is, parts of your pasted material — go to those services.
  The checkbox says so, and the toggle is per request.

  Model backends are auto-detected in this order:
  1. **Ollama** (`http://localhost:11434`) — recommended.
  2. Any **OpenAI-compatible local server** — LM Studio `:1234`,
     llama.cpp/llamafile `:8080`, vLLM `:8000`, text-generation-webui `:5000`.
  3. **Built-in offline analyzer** (always works, no LLM): regex entity
     extraction (e-mails, domains, IPs, handles, phone numbers, dates, wallets,
     hashes, IBANs, CVEs, coordinates, names), identifier-reuse correlation,
     shared-domain detection, timeline, and next-step suggestions that point at
     the dashboard's other blocks.

  The card at the top of the block shows which engine is active.

  **Setup is handled by NexusScan's installer** — `sudo python3 install.py` asks
  whether to install Ollama and a model, picks the right package manager for your
  distro (or the official install script), enables the service for your init
  system, and downloads the model you choose.

  Manual setup, if you prefer:

  ```bash
  # Arch / openSUSE / Alpine / Void / NixOS ship a package:
  sudo pacman -S ollama     # zypper in ollama · apk add ollama · xbps-install ollama
  # everywhere else:
  curl -fsSL https://ollama.com/install.sh | sh

  sudo systemctl enable --now ollama    # OpenRC: sudo rc-service ollama start
  ollama pull llama3.1:8b               # or llama3.2:3b (~2 GB) / qwen2.5:14b (~9 GB)
  ```

### AI environment variables (all optional)

| Variable | Default | Meaning |
|---|---|---|
| `NEXUS_AI_BACKEND` | `auto` | Force a backend: `ollama`, `local_openai`, `offline` |
| `NEXUS_AI_OLLAMA_URL` / `OLLAMA_HOST` | `http://localhost:11434` | Ollama endpoint |
| `NEXUS_AI_OLLAMA_MODEL` | first suitable chat model | Ollama model name |
| `NEXUS_AI_LOCAL_URL` | probes `:1234`, `:8080`, `:8000`, `:5000` | OpenAI-compatible base URL (incl. `/v1`) |
| `NEXUS_AI_LOCAL_MODEL` | first model reported by the server | Model name at that server |
| `NEXUS_AI_TIMEOUT` | `600` | Seconds to wait for local inference |
| `NEXUS_AI_MAX_TOKENS` | `1500` | Cap on generated tokens — a CPU-only model emits roughly 10 tokens/s, so this bounds the wait |
| `NEXUS_AI_FOLLOWUP` | `auto` | Second pass for the model's own `SUCHE:` queries. `auto` = only when the first research round returned little (< 2500 chars); `always`; `never` |

Live research needs no configuration and no key. Its budget is capped in
`web_research.py` (90 s total, 5 concurrent lookups, 14 planned queries, 3 pages
read in full, 9 000-character dossier). Send `"web": false` — or untick the box —
to disable it per request.

**Expect it to be slow on CPU.** Live research itself takes ~15–20 s; the local
model then generates at roughly 10 tokens/s, so a full analysis on a 3B model
lands in the low minutes. A GPU, a smaller `NEXUS_AI_MAX_TOKENS`, or
`"web": false` all shorten it.

## API

```
POST /api/web       {"target": "example.com"}
POST /api/username  {"username": "johndoe"}
POST /api/email     {"email": "john@example.com"}
POST /api/phone     {"number": "+49 151 12345678", "region": "DE"}
POST /api/ai        {"data": "free-form intel…", "prompt": "what to find out",
                     "web": true}     -> {analysis, sources[], research[], web_used, …}
GET  /api/ai/status  -> active local AI backend + availability of the others
GET  /api/health
```

## Notes & limits

- Uses only public/passive sources. Free CT/DNS APIs (hackertarget, certspotter)
  have per-day rate limits; the dashboard degrades gracefully if one is throttled.
- HaveIBeenPwned breach lookups can be enabled by setting the `HIBP_API_KEY`
  environment variable (the email block detects it automatically).
- Some platforms actively block scripted requests; those are honestly reported as
  "check manually" rather than guessed.

## ⚠️ Legal / ethical

This tool queries only publicly available information. Use it **only** for
authorized security research, education, and investigations you are permitted to
perform. You are responsible for complying with applicable laws and the terms of
service of the queried platforms.
