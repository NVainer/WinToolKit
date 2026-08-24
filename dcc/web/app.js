/* Device Control Console -- UI logic.  Vanilla ES2020, no dependencies. */
"use strict";

const TOKEN = window.DCC_TOKEN;
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
  snap: null,
  view: "devices",
  search: "",
  rows: [],
  selectedId: null,
  checked: new Set(),
  sort: {
    devices: { key: "resolved_name", dir: 1 },
    drivers: { key: "driver_name", dir: 1 },
    cleanup: { key: "kind", dir: 1 },
  },
  filters: {
    devices: { status: "all", cls: "", type: "" },
    drivers: { state: "all", cls: "" },
    cleanup: { kind: "all" },
  },
  treeExpanded: new Set(),
};

/* ------------------------------------------------------------------ api */
async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { "X-DCC-Token": TOKEN, "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { error: text.slice(0, 400) }; }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body || {}) });

/* --------------------------------------------------------------- helpers */
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function statusPill(status, problem) {
  const cls = String(status || "").toLowerCase();
  const title = problem ? ` title="Code ${problem}"` : "";
  return `<span class="pill ${cls}"${title}>${esc(status || "?")}</span>`;
}

function toast(title, body, kind = "") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.innerHTML = `<b>${esc(title)}</b>${body ? `<pre>${esc(body)}</pre>` : ""}`;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), kind === "err" ? 14000 : 7000);
}

function fmtDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function cmp(a, b) {
  if (a == null) a = "";
  if (b == null) b = "";
  if (typeof a === "boolean" || typeof b === "boolean") return (a ? 1 : 0) - (b ? 1 : 0);
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: "base" });
}

/* ---------------------------------------------------------------- columns */
const COLUMNS = {
  devices: [
    { key: "device_type", label: "Type", width: "132px",
      cell: (d) => `<span title="${esc(d.type_from || "")}">${esc(d.device_type || "")}</span>` },
    { key: "resolved_name", label: "Resolved device",
      cell: (d) => `${esc(d.resolved_name || "")}<span class="conf ${d.resolved_confidence}" title="Resolved from: ${esc(d.resolved_from || "")}">${d.resolved_confidence === "high" ? "\u25cf" : d.resolved_confidence === "medium" ? "\u25d0" : "\u25cb"}</span>` },
    { key: "instance_id", label: "Instance ID", cls: "mono" },
    { key: "description", label: "Device description" },
    { key: "class_name", label: "Class", width: "110px" },
    { key: "manufacturer", label: "Manufacturer name" },
    { key: "status", label: "Status", width: "112px",
      cell: (d) => statusPill(d.status, d.problem_code) },
    { key: "driver_name", label: "Driver name", cls: "mono", width: "132px" },
    { key: "extension_drivers", label: "Extension drivers", cls: "mono",
      cell: (d) => esc((d.extension_drivers || []).join(", ")) },
  ],
  drivers: [
    { key: "_check", label: "", width: "30px", nosort: true,
      cell: (d) => `<input type="checkbox" data-check="${esc(d.driver_name)}"${state.checked.has(d.driver_name) ? " checked" : ""}>` },
    { key: "driver_name", label: "Published name", cls: "mono", width: "112px" },
    { key: "original_name", label: "Original name", cls: "mono" },
    { key: "provider_name", label: "Provider" },
    { key: "class_name", label: "Class", width: "116px" },
    { key: "version_number", label: "Version", cls: "mono", width: "128px" },
    { key: "version_date", label: "Date", width: "104px",
      cell: (d) => esc(d.version_date || "") },
    { key: "signer_name", label: "Signer" },
    { key: "device_count", label: "Devices", width: "76px", cls: "num" },
    { key: "_state", label: "State", width: "150px", nosort: true,
      cell: (d) => driverStatePills(d) },
  ],
  cleanup: [
    { key: "_check", label: "", width: "30px", nosort: true,
      cell: (r) => (r.driver_name ? `<input type="checkbox" data-check="${esc(r.driver_name)}"${state.checked.has(r.driver_name) ? " checked" : ""}>` : "") },
    { key: "kind", label: "Finding", width: "168px",
      cell: (r) => `<span class="pill ${r.severity}">${esc(r.kind)}</span>` },
    { key: "name", label: "Item" },
    { key: "detail", label: "Detail" },
    { key: "hint", label: "Suggested action" },
  ],
};

function driverStatePills(d) {
  const out = [];
  if (d.is_extension) out.push(`<span class="pill ext">extension</span>`);
  if (d.orphaned) out.push(`<span class="pill orphan">orphaned</span>`);
  else out.push(`<span class="pill started">in use \u00d7${d.device_count}</span>`);
  if (d.superseded_by) out.push(`<span class="pill orphan" title="Newer package: ${esc(d.superseded_by)}">old</span>`);
  return out.join(" ");
}

/* ------------------------------------------------------------------ rows */
function cleanupRows() {
  const snap = state.snap;
  const rows = [];
  for (const d of snap.drivers) {
    if (d.orphaned) {
      rows.push({
        kind: "Orphaned package", severity: "orphan", driver_name: d.driver_name,
        name: `${d.driver_name} \u2014 ${d.original_name}`,
        detail: `${d.provider_name} \u00b7 ${d.driver_version}`,
        hint: "No device uses it. Safe to delete in most cases.",
        _driver: d,
      });
    }
    if (d.superseded_by) {
      rows.push({
        kind: "Superseded version", severity: "orphan", driver_name: d.driver_name,
        name: `${d.driver_name} \u2014 ${d.original_name}`,
        detail: `${d.driver_version} \u2014 newer copy is ${d.superseded_by}`,
        hint: `Delete after confirming ${d.superseded_by} is the one in use.`,
        _driver: d,
      });
    }
  }
  for (const d of state.snap.devices) {
    if (d.problem_code) {
      rows.push({
        kind: `Device problem ${d.problem_code}`, severity: "problem", driver_name: "",
        name: d.resolved_name || d.description,
        detail: `${d.problem_text || ""} \u2014 ${d.instance_id}`,
        hint: "Reinstall or update the driver, or remove the device.",
        _device: d,
      });
    }
  }
  const ghosts = state.snap.devices.filter((d) => !d.present);
  if (ghosts.length) {
    rows.push({
      kind: "Disconnected devices", severity: "disconnected", driver_name: "",
      name: `${ghosts.length} device nodes are not present`,
      detail: "Left behind by hardware that is unplugged or replaced",
      hint: "Filter Devices \u2192 Disconnected to review and remove.",
      _filter: "disconnected",
    });
  }
  return rows;
}

function baseRows() {
  if (!state.snap) return [];
  if (state.view === "devices") return state.snap.devices;
  if (state.view === "drivers") return state.snap.drivers;
  if (state.view === "cleanup") return cleanupRows();
  return [];
}

function applyFilters(rows) {
  const q = state.search.trim().toLowerCase();
  const terms = q ? q.split(/\s+/) : [];
  const f = state.filters[state.view] || {};

  return rows.filter((r) => {
    if (state.view === "devices") {
      if (f.status === "connected" && !r.present) return false;
      if (f.status === "disconnected" && r.present) return false;
      if (f.status === "problem" && !r.problem_code) return false;
      if (f.cls && r.class_name !== f.cls) return false;
      if (f.type && r.device_type !== f.type) return false;
    } else if (state.view === "drivers") {
      if (f.state === "orphaned" && !r.orphaned) return false;
      if (f.state === "inuse" && r.orphaned) return false;
      if (f.state === "superseded" && !r.superseded_by) return false;
      if (f.state === "extension" && !r.is_extension) return false;
      if (f.cls && r.class_name !== f.cls) return false;
    } else if (state.view === "cleanup") {
      if (f.kind !== "all" && !r.kind.toLowerCase().includes(f.kind)) return false;
    }
    if (!terms.length) return true;
    const blob = r.search_blob || `${r.kind} ${r.name} ${r.detail}`.toLowerCase();
    return terms.every((t) => blob.includes(t));
  });
}

function sortRows(rows) {
  const s = state.sort[state.view];
  if (!s || !s.key) return rows;
  return rows.slice().sort((a, b) => cmp(a[s.key], b[s.key]) * s.dir);
}

/* ---------------------------------------------------------------- render */
function renderFilters() {
  const box = $("#filters");
  const f = state.filters[state.view];
  if (state.view === "devices") {
    const classes = [...new Set(state.snap.devices.map((d) => d.class_name).filter(Boolean))].sort();
    const types = [...new Set(state.snap.devices.map((d) => d.device_type).filter(Boolean))].sort();
    box.innerHTML = `
      ${chip("status", "all", "All")}${chip("status", "connected", "Connected")}
      ${chip("status", "disconnected", "Disconnected")}${chip("status", "problem", "Problems")}
      <select data-filter="cls">${opt("", "All classes", f.cls)}${classes.map((c) => opt(c, c, f.cls)).join("")}</select>
      <select data-filter="type">${opt("", "All types", f.type)}${types.map((c) => opt(c, c, f.type)).join("")}</select>`;
  } else if (state.view === "drivers") {
    const classes = [...new Set(state.snap.drivers.map((d) => d.class_name).filter(Boolean))].sort();
    box.innerHTML = `
      ${chip("state", "all", "All")}${chip("state", "inuse", "In use")}
      ${chip("state", "orphaned", "Orphaned")}${chip("state", "superseded", "Superseded")}
      ${chip("state", "extension", "Extensions")}
      <select data-filter="cls">${opt("", "All classes", f.cls)}${classes.map((c) => opt(c, c, f.cls)).join("")}</select>`;
  } else if (state.view === "cleanup") {
    box.innerHTML = `${chip("kind", "all", "All")}${chip("kind", "orphaned", "Orphaned")}
      ${chip("kind", "superseded", "Superseded")}${chip("kind", "problem", "Problems")}`;
  } else {
    box.innerHTML = "";
  }
}

const chip = (field, value, label) =>
  `<button class="chip${state.filters[state.view][field] === value ? " on" : ""}" data-chip="${field}" data-value="${value}">${label}</button>`;
const opt = (value, label, sel) =>
  `<option value="${esc(value)}"${sel === value ? " selected" : ""}>${esc(label)}</option>`;

function renderTable() {
  const cols = COLUMNS[state.view];
  const rows = (state.rows = sortRows(applyFilters(baseRows())));
  const s = state.sort[state.view];

  $("#gridHead").innerHTML = `<tr>${cols.map((c) => {
    const active = s.key === c.key;
    const arrow = active ? `<span class="arrow">${s.dir > 0 ? "\u25b2" : "\u25bc"}</span>` : "";
    return `<th${c.nosort ? ' class="nosort"' : ` data-sort="${c.key}"`}${c.width ? ` style="width:${c.width}"` : ""}>${esc(c.label)}${arrow}</th>`;
  }).join("")}</tr>`;

  const body = rows.map((r) => {
    const id = r.instance_id || r.driver_name || r.name;
    const classes = [];
    if (id === state.selectedId) classes.push("sel");
    if (state.view === "devices" && !r.present) classes.push("ghost");
    return `<tr class="${classes.join(" ")}" data-id="${esc(id)}">${cols.map((c) => {
      const raw = c.cell ? c.cell(r) : esc(Array.isArray(r[c.key]) ? r[c.key].join(", ") : r[c.key] ?? "");
      const title = c.cell ? "" : ` title="${esc(Array.isArray(r[c.key]) ? r[c.key].join(", ") : r[c.key] ?? "")}"`;
      return `<td class="${c.cls || ""}"${title}>${raw}</td>`;
    }).join("")}</tr>`;
  }).join("");

  $("#gridBody").innerHTML = body;
  $("#emptyState").hidden = rows.length > 0;
  $("#rowInfo").textContent = `${rows.length} of ${baseRows().length} rows`;
  updateSelectionUi();
}

function renderTree() {
  const devices = state.snap.devices;
  const byId = new Map(devices.map((d) => [d.instance_id, d]));
  const kids = new Map();
  const roots = [];
  for (const d of devices) {
    if (d.parent && byId.has(d.parent)) {
      if (!kids.has(d.parent)) kids.set(d.parent, []);
      kids.get(d.parent).push(d);
    } else {
      roots.push(d);
    }
  }
  const q = state.search.trim().toLowerCase();
  const matches = (d) => !q || (d.search_blob || "").includes(q);
  const subtreeMatches = (d, depth = 0) => {
    if (matches(d)) return true;
    if (depth > 6) return false;
    return (kids.get(d.instance_id) || []).some((c) => subtreeMatches(c, depth + 1));
  };

  const node = (d, depth) => {
    if (!subtreeMatches(d)) return "";
    const children = (kids.get(d.instance_id) || []).sort((a, b) =>
      cmp(a.resolved_name, b.resolved_name));
    const open = state.treeExpanded.has(d.instance_id) || (q && depth < 4);
    const twisty = children.length ? (open ? "\u25be" : "\u25b8") : "\u00b7";
    return `<li>
      <div class="node" data-id="${esc(d.instance_id)}" data-toggle="${children.length ? 1 : 0}">
        <span class="twisty">${twisty}</span>
        <span class="type-tag">${esc(d.type_icon || "?")}</span>
        <span>${esc(d.resolved_name || d.description)}</span>
        ${statusPill(d.status, d.problem_code)}
        <span class="iid">${esc(d.instance_id)}</span>
      </div>
      ${children.length && open ? `<ul>${children.map((c) => node(c, depth + 1)).join("")}</ul>` : ""}
    </li>`;
  };

  roots.sort((a, b) => cmp(a.resolved_name, b.resolved_name));
  $("#tablePane").innerHTML =
    `<div class="table-scroll"><div class="tree"><ul>${roots.map((r) => node(r, 0)).join("")}</ul></div></div>` +
    `<footer class="table-foot"><span>${devices.length} device nodes \u00b7 click a row to inspect, click the arrow to expand</span></footer>`;
}

function restoreTablePane() {
  $("#tablePane").innerHTML = `
    <div class="table-scroll">
      <table id="grid"><thead id="gridHead"></thead><tbody id="gridBody"></tbody></table>
      <p class="empty" id="emptyState" hidden>Nothing matches the current search and filters.</p>
    </div>
    <footer class="table-foot">
      <span id="rowInfo">—</span><span class="spacer"></span>
      <span id="selInfo"></span>
      <button class="btn danger small" id="btnBulkDelete" hidden>Delete selected packages…</button>
    </footer>`;
}

function render() {
  if (!state.snap) return;
  renderFilters();
  if (state.view === "tree") {
    renderTree();
  } else {
    if (!$("#grid")) restoreTablePane();
    renderTable();
  }
  const m = state.snap.meta;
  $("#cDevices").textContent = m.device_count;
  $("#cDrivers").textContent = m.driver_count;
  $("#cCleanup").textContent = m.orphan_driver_count + m.superseded_driver_count + m.problem_count;
  $("#metaLine").textContent =
    `${m.present_count} connected \u00b7 ${m.ghost_count} disconnected \u00b7 ` +
    `${m.driver_count} store packages (${m.orphan_driver_count} orphaned) \u00b7 scanned ${fmtDate(m.generated_at)}`;
  const badge = $("#elevBadge");
  badge.textContent = m.elevated ? "administrator" : "standard user";
  badge.className = `badge ${m.elevated ? "admin" : "user"}`;
  badge.title = m.elevated ? "Write actions run directly" : "Write actions will raise a UAC prompt";
}

/* ---------------------------------------------------------------- detail */
async function openDevice(instanceId) {
  state.selectedId = instanceId;
  renderTable && state.view !== "tree" && renderTable();
  const pane = $("#detail");
  pane.hidden = false;
  $("#detailTitle").textContent = "loading…";
  $("#detailBody").innerHTML = "";
  let data;
  try {
    data = await api(`/api/device?id=${encodeURIComponent(instanceId)}`);
  } catch (e) {
    $("#detailTitle").textContent = "Error";
    $("#detailBody").innerHTML = `<p class="note warn">${esc(e.message)}</p>`;
    return;
  }
  const d = data.summary;
  $("#detailTitle").innerHTML =
    `${esc(d.resolved_name || d.description)} <span class="conf ${d.resolved_confidence}">${esc(d.resolved_confidence)}</span>`;
  $("#detailSub").textContent = `${d.device_type || ""} \u00b7 ${d.class_display || d.class_name}`;

  const kv = (pairs) => `<dl class="kv">${pairs.filter(Boolean).map(([k, v, plain]) =>
    `<dt>${esc(k)}</dt><dd class="${plain ? "plain" : ""}">${v}</dd>`).join("")}</dl>`;

  const relList = (items) => items.length
    ? `<ul class="rel-list">${items.map((r) => `<li data-goto="${esc(r.instance_id)}">
        <div class="rn">${esc(r.resolved_name || r.description || "(unnamed)")} ${statusPill(r.status)}</div>
        <div class="ri">${esc(r.instance_id)}</div></li>`).join("")}</ul>`
    : `<p class="dim">none</p>`;

  const p = data.properties || {};
  const drivers = data.drivers.map((x) => `<li data-driver="${esc(x.driver_name)}">
      <div class="rn">${esc(x.driver_name)} ${x.is_extension ? '<span class="pill ext">extension</span>' : ""}
        ${x.in_store ? "" : '<span class="pill">inbox</span>'}</div>
      <div class="ri">${esc([x.original_name, x.provider_name, x.driver_version].filter(Boolean).join(" \u00b7 ") || "Windows in-box driver")}</div>
    </li>`).join("");

  $("#detailBody").innerHTML = `
    <div class="section">
      <h3>Identity</h3>
      ${kv([
        ["Instance ID", esc(d.instance_id)],
        ["Resolved device", esc(d.resolved_name), true],
        ["Resolved from", esc(d.resolved_from), true],
        ["Device description", esc(d.description), true],
        d.friendly_name && ["Friendly name", esc(d.friendly_name), true],
        d.bus_reported && ["Bus reported name", esc(d.bus_reported), true],
        ["Type", `${esc(d.device_type)} <span class="dim">(${esc(d.type_from)})</span>`, true],
        ["Class name", esc(d.class_name), true],
        ["Class GUID", esc(d.class_guid)],
        ["Manufacturer name", esc(d.manufacturer), true],
        ["Resolved vendor", esc(d.vendor), true],
        ["Status", `${statusPill(d.status, d.problem_code)} ${esc(d.problem_text || "")}`, true],
        d.ids && d.ids.vid && ["Vendor / product ID", `${esc(d.ids.id_kind || "").toUpperCase()} ${esc(d.ids.vid)}:${esc(d.ids.pid || "")}`],
        d.service && ["Service", esc(d.service)],
        d.location && ["Location", esc(d.location), true],
        d.last_arrival && ["Last arrival", esc(fmtDate(d.last_arrival)), true],
        d.last_removal && ["Last removal", esc(fmtDate(d.last_removal)), true],
      ])}
    </div>

    <div class="section">
      <h3>Drivers</h3>
      ${drivers ? `<ul class="rel-list">${drivers}</ul>` : '<p class="dim">none</p>'}
    </div>

    <div class="section">
      <h3>Actions</h3>
      <div class="action-row">
        <button class="btn small" data-devact="enable-device">Enable</button>
        <button class="btn small" data-devact="disable-device">Disable</button>
        <button class="btn small" data-devact="restart-device">Restart</button>
        <button class="btn small danger" data-devact="remove-device">Remove device…</button>
        <button class="btn small" data-copy="${esc(d.instance_id)}">Copy instance ID</button>
      </div>
      ${d.present ? "" : '<p class="note warn" style="margin-top:8px">This device is not connected. Removing it clears the leftover node and its settings.</p>'}
    </div>

    <div class="section"><h3>Parent</h3>${data.parent ? relList([data.parent]) : '<p class="dim">none (root)</p>'}</div>
    <div class="section"><h3>Children (${data.children.length})</h3>${relList(data.children)}</div>
    <div class="section"><h3>Related hardware (${data.related.length})</h3>${relList(data.related)}</div>

    <div class="section">
      <h3>All properties (${Object.keys(p).length})</h3>
      ${kv(Object.entries(p).sort((a, b) => cmp(a[0], b[0])).map(([k, v]) =>
        [k, esc(Array.isArray(v) ? v.join("\n") : String(v))]))}
    </div>`;
}

async function openDriver(driverName) {
  state.selectedId = driverName;
  if (state.view !== "tree") renderTable();
  const pane = $("#detail");
  pane.hidden = false;
  $("#detailTitle").textContent = "loading…";
  let data;
  try {
    data = await api(`/api/driver?name=${encodeURIComponent(driverName)}`);
  } catch (e) {
    $("#detailTitle").textContent = "Error";
    $("#detailBody").innerHTML = `<p class="note warn">${esc(e.message)}</p>`;
    return;
  }
  const d = data.driver;
  $("#detailTitle").textContent = `${d.driver_name} \u2014 ${d.original_name}`;
  $("#detailSub").textContent = `${d.provider_name} \u00b7 ${d.class_name}`;
  const kv = (pairs) => `<dl class="kv">${pairs.filter(Boolean).map(([k, v, plain]) =>
    `<dt>${esc(k)}</dt><dd class="${plain ? "plain" : ""}">${v}</dd>`).join("")}</dl>`;

  $("#detailBody").innerHTML = `
    <div class="section">
      <h3>Package</h3>
      ${kv([
        ["Published name", esc(d.driver_name)],
        ["Original name", esc(d.original_name)],
        ["Provider", esc(d.provider_name), true],
        ["Class", `${esc(d.class_name)} <span class="dim">${esc(d.class_guid)}</span>`, true],
        ["Driver version", esc(d.driver_version)],
        ["Signer", esc(d.signer_name), true],
        ["Attributes", esc((d.attributes || []).join(", ")), true],
        ["WHCP version", esc(d.whcp_version), true],
        ["Package ID", esc(d.driver_package_id)],
        ["Family ID", esc(d.family_id)],
        ["State", driverStatePills(d), true],
        d.superseded_by && ["Superseded by", esc(d.superseded_by)],
        d.family_members.length > 1 && ["Family members", esc(d.family_members.join(", "))],
      ])}
    </div>

    <div class="section">
      <h3>Actions</h3>
      <div class="action-row">
        <button class="btn small danger" data-drvact="delete">Delete package…</button>
        <button class="btn small" data-drvact="export">Export to folder…</button>
        <button class="btn small" data-copy="${esc(d.driver_name)}">Copy name</button>
      </div>
      ${d.orphaned
        ? '<p class="note" style="margin-top:8px">No device references this package. Deleting it is normally safe.</p>'
        : `<p class="note warn" style="margin-top:8px">${d.device_count} device(s) use this package. Deleting needs <b>/uninstall</b> or <b>/force</b>.</p>`}
    </div>

    <div class="section">
      <h3>Devices using this package (${data.devices.length})</h3>
      ${data.devices.length ? `<ul class="rel-list">${data.devices.map((x) => `<li data-goto="${esc(x.instance_id)}">
          <div class="rn">${esc(x.resolved_name || x.description || "(unnamed)")} ${statusPill(x.status)}
            ${x.is_extension_use ? '<span class="pill ext">via extension</span>' : ""}</div>
          <div class="ri">${esc(x.instance_id)}</div></li>`).join("")}</ul>`
        : '<p class="dim">none</p>'}
    </div>`;
}

/* ----------------------------------------------------------------- modal */
function modal({ title, bodyHtml, okLabel = "Confirm", danger = true }) {
  return new Promise((resolve) => {
    $("#modalTitle").textContent = title;
    $("#modalBody").innerHTML = bodyHtml;
    const ok = $("#modalOk");
    ok.textContent = okLabel;
    ok.className = `btn ${danger ? "danger" : "primary"}`;
    $("#modalBackdrop").hidden = false;
    const done = (value) => {
      $("#modalBackdrop").hidden = true;
      ok.onclick = null;
      $("#modalCancel").onclick = null;
      resolve(value);
    };
    ok.onclick = () => {
      const opts = {};
      $$("#modalBody [data-opt]").forEach((el) => {
        opts[el.dataset.opt] = el.type === "checkbox" ? el.checked : el.value;
      });
      done(opts);
    };
    $("#modalCancel").onclick = () => done(null);
  });
}

async function runAction(payload, label) {
  try {
    const res = await post("/api/action", payload);
    const kind = res.ok ? "ok" : "err";
    toast(`${label}: ${res.ok ? "succeeded" : "failed"}${res.reboot_required ? " (reboot required)" : ""}`,
      `${res.command}\nexit ${res.returncode}\n\n${res.output}`, kind);
    await reload(false);
    return res;
  } catch (e) {
    toast(`${label}: failed`, e.message, "err");
    return null;
  }
}

async function confirmDeleteDriver(names) {
  const many = names.length > 1;
  const snap = state.snap;
  const info = names.map((n) => {
    const d = snap.drivers.find((x) => x.driver_name === n);
    return d ? `${d.driver_name}  ${d.original_name}  (${d.provider_name}, ${d.device_count} device(s))` : n;
  }).join("\n");
  const inUse = names.some((n) => (snap.drivers.find((x) => x.driver_name === n) || {}).device_count > 0);
  const opts = await modal({
    title: many ? `Delete ${names.length} driver packages?` : `Delete ${names[0]}?`,
    okLabel: "Delete",
    bodyHtml: `
      <p>These packages will be removed from the Windows driver store:</p>
      <pre>${esc(info)}</pre>
      <label><input type="checkbox" data-opt="uninstall"${inUse ? " checked" : ""}> <b>/uninstall</b> — also uninstall the driver from devices using it</label>
      <label><input type="checkbox" data-opt="force"> <b>/force</b> — delete even while in use (can leave devices without a driver)</label>
      <label><input type="checkbox" data-opt="reboot"> <b>/reboot</b> — let Windows reboot if it needs to</label>
      <p class="note warn">Deleting a driver package cannot be undone. Export it first if you might need it back.</p>`,
  });
  if (!opts) return;
  for (const name of names) {
    await runAction({ verb: "delete-driver", driver_name: name, ...opts }, `Delete ${name}`);
  }
  state.checked.clear();
}

/* ----------------------------------------------------------------- wiring */
function updateSelectionUi() {
  const btn = $("#btnBulkDelete");
  const info = $("#selInfo");
  if (!btn || !info) return;
  const n = state.checked.size;
  btn.hidden = n === 0;
  info.textContent = n ? `${n} package(s) selected` : "";
}

function setView(view) {
  state.view = view;
  state.checked.clear();
  $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === view));
  render();
}

async function reload(refresh = true) {
  try {
    const data = await api(`/api/snapshot${refresh ? "?refresh=1" : ""}`);
    state.snap = data;
    render();
  } catch (e) {
    toast("Could not load snapshot", e.message, "err");
  }
}

function bind() {
  $$(".tab").forEach((t) => t.addEventListener("click", () => setView(t.dataset.view)));

  $("#search").addEventListener("input", (e) => {
    state.search = e.target.value;
    if (state.view === "tree") renderTree(); else renderTable();
  });

  $("#btnRefresh").addEventListener("click", () => reload(true));

  $("#btnMore").addEventListener("click", (e) => {
    e.stopPropagation();
    $("#morePanel").hidden = !$("#morePanel").hidden;
  });
  document.addEventListener("click", () => { $("#morePanel").hidden = true; });

  $("#morePanel").addEventListener("click", async (e) => {
    const act = e.target.dataset.act;
    if (!act) return;
    if (act.startsWith("export-")) {
      const [, what, fmt] = act.split("-");
      window.location = `/api/export?what=${what}&format=${fmt}&token=${encodeURIComponent(TOKEN)}`;
      return;
    }
    if (act === "toggle-theme") {
      const root = document.documentElement;
      const next = root.dataset.theme === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      localStorage.setItem("dcc-theme", next);
      return;
    }
    if (act === "scan-devices") return void runAction({ verb: "scan-devices" }, "Scan for hardware changes");
    if (act === "update-hwids") {
      toast("Downloading usb.ids and pci.ids…", "This is the only outbound request the console makes.");
      try {
        const res = await post("/api/hwids/update", {});
        const lines = Object.entries(res.results)
          .map(([k, v]) => `${k}: ${v.ok ? `${v.vendors} vendors` : v.error}`).join("\n");
        toast("Hardware ID database updated", lines, "ok");
        await reload(true);
      } catch (err) { toast("Update failed", err.message, "err"); }
      return;
    }
    if (act === "add-driver") {
      const opts = await modal({
        title: "Add a driver package to the store", okLabel: "Add", danger: false,
        bodyHtml: `<p>Full path to the <code>.inf</code> file:</p>
          <input type="text" data-opt="inf_path" placeholder="C:\\drivers\\device.inf">
          <label><input type="checkbox" data-opt="subdirs"> <b>/subdirs</b> — include sub-directories</label>
          <label><input type="checkbox" data-opt="install"> <b>/install</b> — install on matching devices now</label>`,
      });
      if (opts && opts.inf_path) await runAction({ verb: "add-driver", ...opts }, "Add driver");
    }
  });

  document.addEventListener("click", async (e) => {
    const th = e.target.closest("th[data-sort]");
    if (th) {
      const s = state.sort[state.view];
      const key = th.dataset.sort;
      if (s.key === key) s.dir *= -1; else { s.key = key; s.dir = 1; }
      renderTable();
      return;
    }

    const box = e.target.closest("input[data-check]");
    if (box) {
      e.stopPropagation();
      const name = box.dataset.check;
      if (box.checked) state.checked.add(name); else state.checked.delete(name);
      updateSelectionUi();
      return;
    }

    const treeNode = e.target.closest(".tree .node");
    if (treeNode) {
      const id = treeNode.dataset.id;
      if (e.target.classList.contains("twisty") && treeNode.dataset.toggle === "1") {
        if (state.treeExpanded.has(id)) state.treeExpanded.delete(id);
        else state.treeExpanded.add(id);
        renderTree();
      } else {
        openDevice(id);
      }
      return;
    }

    const tr = e.target.closest("#gridBody tr");
    if (tr) {
      const id = tr.dataset.id;
      if (state.view === "devices") openDevice(id);
      else if (state.view === "drivers") openDriver(id);
      else {
        const row = state.rows.find((r) => (r.driver_name || r.name) === id);
        if (row && row._driver) openDriver(row._driver.driver_name);
        else if (row && row._device) openDevice(row._device.instance_id);
        else if (row && row._filter) {
          setView("devices");
          state.filters.devices.status = row._filter;
          render();
        }
      }
      return;
    }

    const goto = e.target.closest("[data-goto]");
    if (goto) return void openDevice(goto.dataset.goto);
    const drv = e.target.closest("[data-driver]");
    if (drv) return void openDriver(drv.dataset.driver);

    const copy = e.target.closest("[data-copy]");
    if (copy) {
      navigator.clipboard.writeText(copy.dataset.copy).then(
        () => toast("Copied", copy.dataset.copy, "ok"),
        () => toast("Copy failed", "", "err"));
      return;
    }

    const devact = e.target.closest("[data-devact]");
    if (devact) {
      const verb = devact.dataset.devact;
      const id = state.selectedId;
      const dev = state.snap.devices.find((d) => d.instance_id === id);
      if (verb === "remove-device") {
        const opts = await modal({
          title: "Remove device node?", okLabel: "Remove",
          bodyHtml: `<p>This removes the device node and its settings from Windows:</p>
            <pre>${esc(dev ? `${dev.resolved_name}\n${dev.instance_id}` : id)}</pre>
            <label><input type="checkbox" data-opt="subtree"> <b>/subtree</b> — also remove child devices</label>
            <p class="note warn">A connected device will be re-detected on the next hardware scan; a disconnected one is gone for good.</p>`,
        });
        if (!opts) return;
        await runAction({ verb, instance_id: id, ...opts }, "Remove device");
      } else {
        await runAction({ verb, instance_id: id }, verb);
      }
      return;
    }

    const drvact = e.target.closest("[data-drvact]");
    if (drvact) {
      const name = state.selectedId;
      if (drvact.dataset.drvact === "delete") return void confirmDeleteDriver([name]);
      const opts = await modal({
        title: `Export ${name}`, okLabel: "Export", danger: false,
        bodyHtml: `<p>Target folder (must already exist):</p>
          <input type="text" data-opt="target_dir" value="${esc(homeGuess())}">`,
      });
      if (opts && opts.target_dir) {
        await runAction({ verb: "export-driver", driver_name: name, target_dir: opts.target_dir },
          `Export ${name}`);
      }
      return;
    }

    const bulk = e.target.closest("#btnBulkDelete");
    if (bulk) return void confirmDeleteDriver([...state.checked]);

    if (e.target.closest("#btnCloseDetail")) {
      $("#detail").hidden = true;
      state.selectedId = null;
      if (state.view !== "tree") renderTable();
    }
  });

  $("#filters").addEventListener("click", (e) => {
    const c = e.target.closest("[data-chip]");
    if (!c) return;
    state.filters[state.view][c.dataset.chip] = c.dataset.value;
    render();
  });
  $("#filters").addEventListener("change", (e) => {
    const s = e.target.closest("[data-filter]");
    if (!s) return;
    state.filters[state.view][s.dataset.filter] = s.value;
    render();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement !== $("#search")) {
      e.preventDefault();
      $("#search").focus();
      $("#search").select();
    } else if (e.key === "Escape") {
      if (!$("#modalBackdrop").hidden) $("#modalCancel").click();
      else if (!$("#detail").hidden) $("#btnCloseDetail").click();
      else { $("#search").value = ""; state.search = ""; render(); }
    } else if (e.key === "F5") {
      e.preventDefault();
      reload(true);
    }
  });
}

const homeGuess = () => "C:\\Drivers";

(function init() {
  const saved = localStorage.getItem("dcc-theme");
  if (saved) document.documentElement.dataset.theme = saved;
  bind();
  reload(false);
})();
