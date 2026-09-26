// RF Radar dashboard — polls /api/state and redraws. No framework, no build step.
"use strict";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

let state = null;
let kind = "ble";
let paused = false;
const seenAlerts = new Set();
let firstLoad = true;

function ago(ts) {
  const s = Math.max(0, Math.round(state.now - ts));
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  return `${Math.round(s / 3600)} h ago`;
}

function signal(rssi) {
  if (rssi == null) return "—";
  const pct = Math.max(0, Math.min(100, ((rssi + 95) / 65) * 100));
  const word = rssi >= -55 ? "very close" : rssi >= -70 ? "near" : rssi >= -82 ? "in range" : "far";
  return `<span class="sig"><span class="bar" aria-hidden="true"><i style="width:${pct}%"></i></span>${rssi} dBm <span class="sr-only">(${word})</span></span>`;
}

function macCell(d) {
  const tags = [];
  if (d.randomized) tags.push('<span class="tag" title="Privacy address that changes over time">random</span>');
  if (d.mine) tags.push('<span class="tag good">✓ mine</span>');
  return `<td class="mac">${esc(d.mac)}<br>${tags.join("")}</td>`;
}

function mineBtn(d) {
  const label = d.mine ? "Not mine" : "Mine";
  return `<button type="button" class="btn small" data-act="mine" data-kind="${d.kind}" data-mac="${esc(d.mac)}"
    data-mine="${d.mine ? 0 : 1}" data-fk="mine-${esc(d.mac)}" aria-label="${label}: ${esc(d.mac)}">${label}</button>`;
}

function placesCell(d) {
  const n = d.places.length;
  return n > 1 ? `<span class="tag ${n >= 3 && !d.mine ? "bad" : "warn"}">${n} places</span>` : n ? "1 place" : "—";
}

const TABLES = {
  ble: {
    caption: "Bluetooth devices heard recently, strongest first",
    head: ["Device", "Address", "Signal", "Tracker", "Seen at", "Last heard", ""],
    row: (d) => `<tr class="${d.active ? "" : "stale"}">
      <td>${esc(d.names[0] || d.vendor || "Unnamed device")}${d.names[0] && d.vendor ? `<br><span class="tag">${esc(d.vendor)}</span>` : ""}</td>
      ${macCell(d)}<td>${signal(d.rssi)}</td>
      <td>${d.tracker ? `<span class="tag ${d.tracker_state === "near-owner" ? "" : "warn"}">⚠ ${esc(d.tracker)}</span>${d.tracker_state ? `<br>${esc(d.tracker_state)}` : ""}` : "—"}</td>
      <td>${placesCell(d)}</td><td>${ago(d.last_seen)}</td><td>${mineBtn(d)}</td></tr>`,
  },
  ap: {
    caption: "Wi-Fi networks (access points) heard recently, strongest first",
    head: ["Network name", "Access point", "Signal", "Channel", "Security", "Last heard", ""],
    row: (d) => {
      const ssid = d.names[0];
      const sec = d.security || "OPEN";
      const secTag = sec === "OPEN" || sec === "WEP"
        ? `<span class="tag bad">🔓 ${sec === "OPEN" ? "Open" : "WEP"}</span>` : `<span class="tag">🔒 ${esc(sec)}</span>`;
      const trust = ssid ? (d.trusted ? '<span class="tag good">✓ trusted</span>'
        : `<button type="button" class="btn small" data-act="trust" data-ssid="${esc(ssid)}" data-fk="trust-${esc(d.mac)}"
            aria-label="Trust network ${esc(ssid)}">Trust</button>`) : "";
      return `<tr class="${d.active ? "" : "stale"}">
        <td>${ssid ? esc(d.names.join(", ")) : "<em>Hidden network</em>"}</td>${macCell(d)}
        <td>${signal(d.rssi)}</td><td>${d.channel ?? "—"}</td><td>${secTag}</td><td>${ago(d.last_seen)}</td><td>${trust}</td></tr>`;
    },
  },
  client: {
    caption: "Wi-Fi devices (phones, laptops, gadgets) heard recently, strongest first",
    head: ["Device", "Address", "Signal", "Looking for / using", "Seen at", "Last heard", ""],
    row: (d) => `<tr class="${d.active ? "" : "stale"}">
      <td>${esc(d.vendor || (d.randomized ? "Phone or laptop (private address)" : "Unknown maker"))}</td>
      ${macCell(d)}<td>${signal(d.rssi)}</td>
      <td>${d.probes.length ? d.probes.map((p) => `<span class="tag">${esc(p)}</span>`).join("") : ""}${d.bssid ? `<br>on ${esc(d.bssid)}` : d.probes.length ? "" : "—"}</td>
      <td>${placesCell(d)}</td><td>${ago(d.last_seen)}</td><td>${mineBtn(d)}</td></tr>`,
  },
};

function renderTable() {
  const panel = $("panel");
  if (kind === "places") {
    const rows = state.places.map((p) => `<tr>
      <td><form class="label-form" data-place="${p.id}">
        <label class="sr-only" for="pl-${p.id}">Name for ${esc(p.label)}</label>
        <input id="pl-${p.id}" data-fk="pl-${p.id}" value="${esc(p.label)}" maxlength="60">
        <button class="btn small" data-fk="plb-${p.id}">Rename</button></form></td>
      <td>${p.aps}</td><td>${ago(p.first_seen)}</td><td>${ago(p.last_seen)}</td>
      <td>${state.place && state.place.id === p.id ? '<span class="tag good">● you are here</span>' : ""}</td></tr>`).join("");
    panel.innerHTML = state.places.length ? `<table><caption>Places are recognised by the Wi-Fi networks visible there. Give them names you'll recognise.</caption>
      <thead><tr><th scope="col">Place</th><th scope="col">Networks in fingerprint</th><th scope="col">First visit</th><th scope="col">Last visit</th><th scope="col"><span class="sr-only">Status</span></th></tr></thead>
      <tbody>${rows}</tbody></table>` : '<p class="empty">No places yet. They appear once a few Wi-Fi networks are visible.</p>';
    return;
  }
  const t = TABLES[kind];
  const list = state.devices[kind];
  panel.innerHTML = list.length
    ? `<table><caption>${t.caption} (${list.length})</caption><thead><tr>${t.head.map((h) =>
        `<th scope="col">${h || '<span class="sr-only">Actions</span>'}</th>`).join("")}</tr></thead>
       <tbody>${list.map(t.row).join("")}</tbody></table>`
    : '<p class="empty">Nothing heard yet.</p>';
}

function renderAlerts() {
  const ul = $("alerts");
  $("alert-count").textContent = state.alerts.length ? `(${state.alerts.length})` : "";
  $("no-alerts").hidden = state.alerts.length > 0;
  ul.innerHTML = state.alerts.map((a) => {
    const sev = { high: "⛔ High", medium: "⚠ Medium", info: "ℹ Info" }[a.severity];
    return `<li class="alert ${a.severity}">
      <h3><span class="sev">${sev}</span>${esc(a.title)}</h3>
      <button type="button" class="btn small" data-act="dismiss" data-key="${esc(a.key)}" data-fk="dis-${esc(a.key)}"
        aria-label="Dismiss alert: ${esc(a.title)}">Dismiss</button>
      <p>${esc(a.detail)}</p>
      <p class="meta">${a.ongoing ? "Happening now" : "Last seen " + ago(a.last_seen)} · first ${ago(a.first_seen)}</p></li>`;
  }).join("");

  // Announce genuinely new alerts to screen readers (not every refresh).
  const fresh = state.alerts.filter((a) => !seenAlerts.has(a.key));
  fresh.forEach((a) => seenAlerts.add(a.key));
  if (fresh.length && !firstLoad) $("announce").textContent = "New alert: " + fresh.map((a) => a.title).join("; ");
}

function render() {
  const active = (k) => state.devices[k].filter((d) => d.active).length;
  $("n-ap").textContent = active("ap");
  $("n-client").textContent = active("client");
  $("n-ble").textContent = active("ble");
  $("n-tracker").textContent = state.devices.ble.filter((d) => d.active && d.tracker).length;
  $("n-places").textContent = state.places.length;
  $("where").textContent = state.place ? `Location: ${state.place.label}` : "Location: unknown (too few Wi-Fi networks visible)";
  $("sources").innerHTML = state.sources.map((s) => `<li><strong>${esc(s.name)}</strong> — ${esc(s.status)}</li>`).join("");

  // Keep keyboard focus on the same control across redraws.
  const fk = document.activeElement?.dataset?.fk;
  const typing = document.activeElement?.tagName === "INPUT";
  renderAlerts();
  if (!typing) renderTable();
  if (fk) document.querySelector(`[data-fk="${CSS.escape(fk)}"]`)?.focus();
  firstLoad = false;
}

async function refresh() {
  if (paused) return;
  try {
    const r = await fetch("/api/state");
    state = await r.json();
    render();
  } catch (e) {
    $("where").textContent = "Lost connection to RF Radar — is it still running?";
  }
}

async function post(url, body) {
  await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  const was = paused; paused = false; await refresh(); paused = was;
}

document.addEventListener("click", (e) => {
  const b = e.target.closest("button[data-act]");
  if (!b) return;
  const act = b.dataset.act;
  if (act === "mine") post(`/api/devices/${b.dataset.kind}/${encodeURIComponent(b.dataset.mac)}/mine`, { mine: b.dataset.mine === "1" });
  if (act === "trust") post("/api/trust", { ssid: b.dataset.ssid });
  if (act === "dismiss") post(`/api/alerts/${encodeURIComponent(b.dataset.key)}/dismiss`);
});

document.addEventListener("submit", (e) => {
  const f = e.target.closest("form[data-place]");
  if (!f) return;
  e.preventDefault();
  post(`/api/places/${f.dataset.place}/label`, { label: f.querySelector("input").value });
  document.activeElement.blur();
});

// Tabs: click or arrow keys (WAI-ARIA tabs pattern).
const tabs = [...document.querySelectorAll('[role="tab"]')];
function selectTab(t) {
  tabs.forEach((x) => { x.setAttribute("aria-selected", x === t); x.tabIndex = x === t ? 0 : -1; });
  $("panel").setAttribute("aria-labelledby", t.id);
  kind = t.dataset.kind;
  if (state) renderTable();
}
tabs.forEach((t, i) => {
  t.addEventListener("click", () => selectTab(t));
  t.addEventListener("keydown", (e) => {
    const n = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
    if (n) { const next = tabs[(i + n + tabs.length) % tabs.length]; selectTab(next); next.focus(); }
    if (e.key === "Home") { selectTab(tabs[0]); tabs[0].focus(); }
    if (e.key === "End") { const l = tabs[tabs.length - 1]; selectTab(l); l.focus(); }
  });
});

$("pause").addEventListener("click", (e) => {
  paused = !paused;
  e.target.setAttribute("aria-pressed", paused);
  e.target.textContent = paused ? "Resume live updates" : "Pause live updates";
  if (!paused) refresh();
});

refresh();
setInterval(refresh, 2000);
