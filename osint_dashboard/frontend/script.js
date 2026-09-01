/* ============================================================
   OSINT DASHBOARD — frontend logic
   ============================================================ */

/* ---------- Matrix rain background ---------- */
(function matrixRain() {
  const canvas = document.getElementById("matrix");
  const ctx = canvas.getContext("2d");
  const chars = "01アカサタナハマヤラワ0123456789ABCDEFｦｧｨｩｪ<>[]{}#$%&".split("");
  let cols, drops, fontSize = 14;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    cols = Math.floor(canvas.width / fontSize);
    drops = new Array(cols).fill(1).map(() => Math.random() * canvas.height / fontSize);
  }
  resize();
  window.addEventListener("resize", resize);

  function draw() {
    ctx.fillStyle = "rgba(3, 7, 5, 0.08)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = fontSize + "px monospace";
    for (let i = 0; i < drops.length; i++) {
      const text = chars[Math.floor(Math.random() * chars.length)];
      const x = i * fontSize;
      const y = drops[i] * fontSize;
      // lead char brighter
      ctx.fillStyle = Math.random() > 0.975 ? "#c8ffe6" : "#00ff9c";
      ctx.fillText(text, x, y);
      if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }
  setInterval(draw, 52);
})();

/* ---------- Clock ---------- */
setInterval(() => {
  const el = document.getElementById("clock");
  if (el) el.textContent = new Date().toTimeString().slice(0, 8);
}, 1000);

/* ---------- Helpers ---------- */
function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
function kv(k, v) {
  if (v == null || v === "" || (Array.isArray(v) && !v.length)) return "";
  const val = Array.isArray(v) ? v.map(esc).join("<br>") : esc(v);
  return `<div class="kv"><span class="k">${esc(k)}</span><span class="v">${val}</span></div>`;
}
function title(t) { return `<div class="section-title">${esc(t)}</div>`; }

/* ---------- Renderers ---------- */
function renderWeb(d) {
  if (!d.ok) return `<div class="err">✖ ${esc(d.error)}</div>`;
  let h = `<div class="big">▚ ${esc(d.domain)}</div>`;

  // WHOIS
  h += title("WHOIS");
  const w = d.whois || {};
  if (w.error) {
    h += `<div class="err">${esc(w.error)}</div>`;
  } else {
    h += kv("Registrar", w.registrar);
    h += kv("Org", w.org);
    h += kv("Created", w.creation_date);
    h += kv("Expires", w.expiration_date);
    h += kv("Updated", w.updated_date);
    h += kv("Country", w.country);
    h += kv("Name servers", w.name_servers);
    h += kv("Status", w.status);
    h += kv("Emails", w.emails);
    h += kv("WHOIS server", w.whois_server);
  }

  // DNS
  const dns = d.dns || {};
  const dnsKeys = Object.keys(dns).filter(k => dns[k]);
  if (dnsKeys.length) {
    h += title("DNS RECORDS");
    if (dns.resolved_ip) h += kv("Resolved IP", dns.resolved_ip);
    ["A", "AAAA", "MX", "NS", "TXT"].forEach(k => { if (dns[k]) h += kv(k, dns[k]); });
  }

  // Subdomains
  const s = d.subdomains || {};
  h += title(`SUBDOMAINS (${s.count || 0})`);
  if (s.error) h += `<div class="err">${esc(s.error)}</div>`;
  if (s.subdomains && s.subdomains.length) {
    h += `<div class="sub-list">` +
      s.subdomains.map(sd =>
        `<a href="https://${esc(sd)}" target="_blank" rel="noopener">${esc(sd)}</a>`
      ).join("") + `</div>`;
  } else if (!s.error) {
    h += `<div class="idle">// none found in certificate transparency logs</div>`;
  }
  return h;
}

/* Shared scan renderer — used by both the Username block and the Email
   block's "linked accounts" section. `d` = a scan object with
   {results, found_count, total_sites, manual_count, blocked_count, error_count}. */
function renderScan(d) {
  let h = `<div style="margin:8px 0">
    <span class="chip ok">FOUND ${d.found_count}</span>
    <span class="chip">CHECKED ${d.total_sites}</span>
    ${((d.blocked_count||0) + (d.manual_count||0)) ? `<span class="chip warn">MANUAL ${(d.blocked_count||0) + (d.manual_count||0)}</span>` : ''}
    <span class="chip warn">ERRORS ${d.error_count}</span></div>`;

  const found = d.results.filter(r => r.status === "found");
  h += title(`ACCOUNTS FOUND (${found.length})`);
  if (found.length) {
    h += found.map(r => `
      <div class="hit">
        <a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.name)}</a>
        <span class="badge">${esc(r.category)}</span>
      </div>`).join("");
  } else {
    h += `<div class="idle">// no accounts found</div>`;
  }

  const manual = d.results.filter(r => r.status === "manual" || r.status === "blocked");
  if (manual.length) {
    h += title(`CHECK MANUALLY (${manual.length}) — JS-only / anti-bot`);
    h += `<div>` + manual.map(r =>
      `<a class="chip warn" href="${esc(r.url)}" target="_blank" rel="noopener" style="text-decoration:none">${esc(r.name)} ↗</a>`
    ).join("") + `</div>`;
  }

  const others = d.results.filter(r => r.status === "not_found" || r.status === "error");
  if (others.length) {
    h += title(`NOT FOUND / ERRORS (${others.length})`);
    h += `<div style="opacity:.65">` + others.map(r =>
      `<span class="chip ${r.status === 'error' ? 'warn' : 'bad'}">${esc(r.name)}</span>`
    ).join("") + `</div>`;
  }
  return h;
}

function renderUsername(d) {
  if (!d.ok) return `<div class="err">✖ ${esc(d.error)}</div>`;
  return `<div class="big">@${esc(d.username)}</div>` + renderScan(d);
}

function renderEmail(d) {
  if (!d.ok) return `<div class="err">✖ ${esc(d.error)}</div>`;
  let h = `<div class="big">✉ ${esc(d.email)}</div>`;
  h += `<div style="margin:8px 0">
    <span class="chip ${d.deliverable ? 'ok' : 'bad'}">${d.deliverable ? 'MX PRESENT' : 'NO MX'}</span>
    ${d.is_free_provider ? '<span class="chip warn">FREE PROVIDER</span>' : ''}
    ${d.is_disposable ? '<span class="chip bad">DISPOSABLE</span>' : ''}
    <span class="chip ${d.gravatar.exists ? 'ok' : ''}">${d.gravatar.exists ? 'GRAVATAR ✓' : 'NO GRAVATAR'}</span>
  </div>`;

  h += title("ADDRESS");
  h += kv("Local part", d.local_part);
  h += kv("Domain", d.domain);

  h += title("MAIL SERVERS (MX)");
  if (d.mx && d.mx.mx && d.mx.mx.length) h += kv("MX", d.mx.mx);
  else h += `<div class="idle">// no MX records${d.mx && d.mx.error ? " — " + esc(d.mx.error) : ""}</div>`;

  if (d.gravatar && d.gravatar.exists) {
    h += title("GRAVATAR");
    h += `<div class="hit"><a href="${esc(d.gravatar.profile_url)}" target="_blank" rel="noopener">${esc(d.gravatar.profile_url)}</a></div>`;
    if (d.gravatar.avatar_url)
      h += `<img src="${esc(d.gravatar.avatar_url)}" alt="avatar" style="width:64px;height:64px;border-radius:6px;border:1px solid var(--panel-line);margin-top:6px"/>`;
  }

  h += title(`LINKED ACCOUNTS — handle "${esc(d.local_part)}"`);
  if (d.account_scan) {
    h += renderScan(d.account_scan);
  }
  h += `<div class="idle" style="margin-top:8px">${esc(d.hibp_note)}</div>`;
  return h;
}

function renderPhone(d) {
  if (!d.ok) return `<div class="err">✖ ${esc(d.error)}</div>`;
  let h = `<div class="big">${esc(d.flag)} ${esc(d.international)}</div>`;
  h += `<div style="margin:8px 0">
    <span class="chip ${d.valid ? 'ok' : 'bad'}">${d.valid ? 'VALID' : 'INVALID'}</span>
    <span class="chip">${esc(d.line_type)}</span>
  </div>`;

  h += title("ORIGIN");
  h += kv("Country", d.country_name || d.location);
  h += kv("Region code", d.region_code);
  h += kv("Country code", "+" + d.country_code);
  h += kv("Location", d.location);
  h += kv("Timezone(s)", d.timezones);

  h += title("CARRIER (MOBILFUNK-ANBIETER)");
  h += `<div class="big" style="font-size:16px">${esc(d.carrier)}</div>`;

  h += title("FORMATS");
  h += kv("E.164", d.e164);
  h += kv("International", d.international);
  h += kv("National", d.national);
  return h;
}

/* Minimal, safe Markdown → HTML for the AI analysis.
   Escapes first, then applies a small, line-based subset. */
function mdToHtml(src) {
  const lines = String(src == null ? "" : src).replace(/\r\n/g, "\n").split("\n");
  let html = "", inList = false;
  const closeList = () => { if (inList) { html += "</ul>"; inList = false; } };

  const inline = (s) => esc(s)
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)<>"']+)\)/g,
             '<a href="$2" target="_blank" rel="noopener noreferrer nofollow">$1</a>')
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[\s(])\*([^*\n]+?)\*(?=[\s.,;:)]|$)/g, "$1<em>$2</em>")
    .replace(/`([^`]+?)`/g, "<code>$1</code>");

  for (let raw of lines) {
    const line = raw.trimEnd();
    if (!line.trim()) { closeList(); continue; }

    const h = line.match(/^\s*#{1,6}\s+(.*)$/);
    if (h) { closeList(); html += `<h3>${inline(h[1])}</h3>`; continue; }

    const bq = line.match(/^\s*>\s?(.*)$/);
    if (bq) { closeList(); html += `<blockquote>${inline(bq[1])}</blockquote>`; continue; }

    const li = line.match(/^\s*(?:[-*+]|\d+[.)])\s+(.*)$/);
    if (li) {
      if (!inList) { html += "<ul>"; inList = true; }
      html += `<li>${inline(li[1])}</li>`;
      continue;
    }

    closeList();
    html += `<p>${inline(line.trim())}</p>`;
  }
  closeList();
  return html;
}

function safeUrl(u) {
  const s = String(u == null ? "" : u).trim();
  return /^https?:\/\//i.test(s) ? s : "";
}

function renderAi(d) {
  if (!d.ok) return `<div class="err">✖ ${esc(d.error)}</div>`;
  let h = `<div class="big">🧠 KI-ANALYSE</div>`;
  h += `<div class="ai-analysis">${mdToHtml(d.analysis)}</div>`;

  if (d.research && d.research.length) {
    h += `<div class="section-title">RESEARCH PERFORMED (${d.research.length})</div>`;
    h += `<ul class="ai-research">` +
         d.research.map(r => `<li>${esc(r)}</li>`).join("") + `</ul>`;
  }

  const sources = (d.sources || []).filter(s => safeUrl(s.url));
  if (sources.length) {
    h += `<div class="section-title">SOURCES (${sources.length})</div>`;
    h += `<ul class="ai-sources">` + sources.map(s =>
      `<li><a href="${esc(safeUrl(s.url))}" target="_blank" rel="noopener noreferrer nofollow">${esc(s.title || s.url)}</a></li>`
    ).join("") + `</ul>`;
  }

  if (d.model) h += `<div class="idle" style="margin-top:10px">// engine: ${esc(d.model)}</div>`;
  h += `<div class="idle">// live research: ${d.web_used ? "on" : "off (local data only)"}</div>`;
  if (d.fallback_note)
    h += `<div class="idle">// fallback: ${esc(d.fallback_note)}</div>`;
  return h;
}

async function loadAiBackend() {
  const el = document.getElementById("ai-backend");
  if (!el) return;
  try {
    const d = await (await fetch("/api/ai/status")).json();
    const active = (d.backends || []).find(b => b.id === d.backend) || {};
    const others = (d.backends || [])
      .filter(b => b.id !== d.backend)
      .map(b => `${b.ready ? "✔" : "✖"} ${b.label}`)
      .join(" · ");
    el.className = "ai-backend" + (d.backend === "offline" ? " degraded" : " live");
    el.innerHTML =
      `// engine: <strong>${esc(active.label || d.backend)}</strong> — ${esc(active.detail || "")}` +
      `<br><span class="dim">// 100% local · no API key · others: ${esc(others)}</span>`;
    if (typeof d.web_default === "boolean") {
      const cb = document.querySelector('form[data-endpoint="ai"] input[name="web"]');
      if (cb) cb.checked = d.web_default;
    }
  } catch (err) {
    el.className = "ai-backend";
    el.textContent = "// engine status unavailable";
  }
}
loadAiBackend();

const RENDERERS = { web: renderWeb, username: renderUsername, email: renderEmail, phone: renderPhone, ai: renderAi };
const LOADING = {
  web: "resolving DNS · pulling WHOIS · scraping CT logs",
  username: "probing 40+ platforms",
  email: "checking MX · gravatar · handle reuse",
  phone: "parsing number · geocoding · carrier lookup",
  ai: "live research in public sources · AI correlates · builds analysis",
};

/* ---------- Wire up forms ---------- */
document.querySelectorAll("form[data-endpoint]").forEach(form => {
  const endpoint = form.dataset.endpoint;
  const out = document.getElementById("out-" + endpoint);
  const btn = form.querySelector("button");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(form).entries());
    form.querySelectorAll('input[type="checkbox"][name]').forEach(cb => {
      data[cb.name] = cb.checked;
    });
    const firstVal = Object.values(data)[0];
    if (typeof firstVal !== "string" || !firstVal.trim()) return;

    btn.disabled = true;
    const startLabel = btn.textContent;
    let dots = 0;
    out.innerHTML = `<div class="loader">// ${LOADING[endpoint]}</div>`;
    const anim = setInterval(() => {
      dots = (dots + 1) % 4;
      out.querySelector(".loader").textContent =
        `// ${LOADING[endpoint]}${".".repeat(dots)}`;
    }, 350);

    const t0 = performance.now();
    try {
      const res = await fetch("/api/" + endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      const json = await res.json();
      clearInterval(anim);
      const ms = Math.round(performance.now() - t0);
      out.innerHTML = RENDERERS[endpoint](json) +
        `<div class="idle" style="margin-top:10px;text-align:right">// completed in ${ms} ms</div>`;
    } catch (err) {
      clearInterval(anim);
      out.innerHTML = `<div class="err">✖ request failed: ${esc(err.message)}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = startLabel;
    }
  });
});
