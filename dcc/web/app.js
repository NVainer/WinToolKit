/* Device Control Console -- UI logic.  Vanilla ES2020, no dependencies. */
"use strict";

const TOKEN = window.DCC_TOKEN;
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const STORE = "dcc-prefs-v2";

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

const listText = (v) => (Array.isArray(v) ? v.join(", ") : v ?? "");

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
  return el;
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
function driverStatePills(d) {
  const out = [];
  if (d.is_extension) out.push(`<span class="pill ext">extension</span>`);
  if (d.orphaned) out.push(`<span class="pill orphan">orphaned</span>`);
  else out.push(`<span class="pill started">in use \u00d7${d.device_count}</span>`);
  if (d.superseded_by) out.push(`<span class="pill orphan" title="Newer package: ${esc(d.superseded_by)}">old</span>`);
  return out.join(" ");
}

/* Full catalogue per view.  `def` marks the default-visible set; anything here
   can be switched on from the column picker. */
const ALL_COLUMNS = {
  devices: [
    { key: "device_type", label: "Type", w: 118, def: true,
      cell: (d) => `<span title="${esc(d.type_from || "")}">${esc(d.device_type || "")}</span>` },
    { key: "resolved_name", label: "Resolved device", w: 250, def: true,
      cell: (d) => `${esc(d.resolved_name || "")}<span class="conf ${d.resolved_confidence}" title="Resolved from: ${esc(d.resolved_from || "")}">${d.resolved_confidence === "high" ? "\u25cf" : d.resolved_confidence === "medium" ? "\u25d0" : "\u25cb"}</span>` },
    { key: "instance_id", label: "Instance ID", w: 300, cls: "mono", def: true },
    { key: "description", label: "Device description", w: 210, def: true },
    { key: "class_name", label: "Class name", w: 108, def: true },
    { key: "class_display", label: "Class (friendly)", w: 190 },
    { key: "class_guid", label: "Class GUID", w: 268, cls: "mono", def: true },
    { key: "manufacturer", label: "Manufacturer name", w: 190, def: true },
    { key: "vendor", label: "Resolved vendor", w: 160 },
    { key: "status", label: "Status", w: 112, def: true,
      cell: (d) => statusPill(d.status, d.problem_code) },
    { key: "problem_text", label: "Problem", w: 200 },
    { key: "driver_name", label: "Driver name", w: 128, cls: "mono", def: true },
    { key: "extension_drivers", label: "Extension drivers", w: 138, cls: "mono", def: true,
      cell: (d) => esc((d.extension_drivers || []).join(", ")) },
    { key: "driver_inf", label: "Driver INF (CM)", w: 128, cls: "mono" },
    { key: "driver_version", label: "Driver version", w: 128, cls: "mono" },
    { key: "driver_provider", label: "Driver provider", w: 160 },
    { key: "service", label: "Service", w: 118, cls: "mono" },
    { key: "_vidpid", label: "VID / PID", w: 118, cls: "mono",
      get: (d) => (d.ids && d.ids.vid ? `${d.ids.vid}:${d.ids.pid || ""}` : "") },
    { key: "_bus", label: "Bus", w: 96, get: (d) => (d.ids && d.ids.bus) || "" },
    { key: "hardware_ids", label: "Hardware IDs", w: 320, cls: "mono",
      cell: (d) => esc((d.hardware_ids || []).join("  |  ")) },
    { key: "location", label: "Location", w: 180 },
    { key: "container_id", label: "Container ID", w: 268, cls: "mono" },
    { key: "last_arrival", label: "Last arrival", w: 170, get: (d) => d.last_arrival,
      cell: (d) => esc(fmtDate(d.last_arrival)) },
    { key: "last_removal", label: "Last removal", w: 170, get: (d) => d.last_removal,
      cell: (d) => esc(fmtDate(d.last_removal)) },
    { key: "install_date", label: "Installed", w: 170, cell: (d) => esc(fmtDate(d.install_date)) },
    { key: "child_count", label: "Children", w: 84, cls: "num" },
    { key: "resolved_from", label: "Name resolved from", w: 260 },
    { key: "type_from", label: "Type resolved from", w: 260 },
    { key: "resolved_confidence", label: "Confidence", w: 108 },
    { key: "present", label: "Present", w: 88, cell: (d) => (d.present ? "yes" : "no") },
  ],
  drivers: [
    { key: "_check", label: "", w: 32, def: true, nosort: true,
      cell: (d) => `<input type="checkbox" data-check="${esc(d.driver_name)}"${state.checked.has(d.driver_name) ? " checked" : ""}>` },
    { key: "driver_name", label: "Published name", w: 122, cls: "mono", def: true },
    { key: "original_name", label: "Original name", w: 210, cls: "mono", def: true },
    { key: "provider_name", label: "Provider", w: 200, def: true },
    { key: "class_name", label: "Class", w: 150, def: true },
    { key: "class_guid", label: "Class GUID", w: 268, cls: "mono" },
    { key: "version_number", label: "Version", w: 140, cls: "mono", def: true },
    { key: "version_date", label: "Date", w: 108, def: true },
    { key: "signer_name", label: "Signer", w: 240, def: true },
    { key: "device_count", label: "Devices", w: 82, cls: "num", def: true },
    { key: "present_device_count", label: "Connected", w: 96, cls: "num" },
    { key: "_state", label: "State", w: 158, def: true, nosort: true, cell: driverStatePills },
    { key: "superseded_by", label: "Superseded by", w: 130, cls: "mono" },
    { key: "attributes", label: "Attributes", w: 150, cell: (d) => esc((d.attributes || []).join(", ")) },
    { key: "whcp_version", label: "WHCP", w: 96 },
    { key: "driver_package_id", label: "Package ID", w: 320, cls: "mono" },
    { key: "family_id", label: "Family ID", w: 240, cls: "mono" },
    { key: "device_names", label: "Device names", w: 320,
      cell: (d) => esc((d.device_names || []).join("; ")) },
  ],
  cleanup: [
    { key: "_check", label: "", w: 32, def: true, nosort: true,
      cell: (r) => (r.driver_name ? `<input type="checkbox" data-check="${esc(r.driver_name)}"${state.checked.has(r.driver_name) ? " checked" : ""}>` : "") },
    { key: "kind", label: "Finding", w: 180, def: true,
      cell: (r) => `<span class="pill ${r.severity}">${esc(r.kind)}</span>` },
    { key: "name", label: "Item", w: 330, def: true },
    { key: "detail", label: "Detail", w: 380, def: true },
    { key: "hint", label: "Suggested action", w: 380, def: true },
  ],
};

const colDef = (view, key) => ALL_COLUMNS[view].find((c) => c.key === key);
const colValue = (col, row) => (col.get ? col.get(row) : row[col.key]);

/* ------------------------------------------------------------- group-by */
const GROUPS = {
  devices: [
    { key: "", label: "No grouping" },
    { key: "device_type", label: "Type" },
    { key: "class_name", label: "Class" },
    { key: "status", label: "Status" },
    { key: "manufacturer", label: "Manufacturer" },
    { key: "vendor", label: "Vendor" },
    { key: "driver_name", label: "Driver package" },
    { key: "_bus", label: "Bus / enumerator", get: (d) => (d.ids && d.ids.bus) || "(none)" },
    { key: "_physical", label: "Physical device", get: (d) => physicalLabel(d) },
    { key: "resolved_confidence", label: "Name confidence" },
    { key: "present", label: "Connected / disconnected",
      get: (d) => (d.present ? "Connected" : "Disconnected") },
  ],
  drivers: [
    { key: "", label: "No grouping" },
    { key: "provider_name", label: "Provider" },
    { key: "class_name", label: "Class" },
    { key: "_state", label: "State",
      get: (d) => (d.orphaned ? "Orphaned" : d.superseded_by ? "Superseded" : "In use") },
    { key: "original_name", label: "Original INF" },
    { key: "family_id", label: "Package family" },
  ],
  cleanup: [
    { key: "", label: "No grouping" },
    { key: "kind", label: "Finding" },
  ],
};

let PHYSICAL_LABELS = new Map();

function physicalLabel(d) {
  const c = d.container_id;
  if (!c || c.startsWith("{00000000") || c.startsWith("{ffffffff")) return "(not a container)";
  return PHYSICAL_LABELS.get(c) || c;
}

/** Name each hardware container after its most specific member. */
function buildPhysicalLabels(devices) {
  const best = new Map();
  const rank = { high: 3, medium: 2, low: 1, none: 0 };
  for (const d of devices) {
    const c = d.container_id;
    if (!c || c.startsWith("{00000000") || c.startsWith("{ffffffff")) continue;
    const cur = best.get(c);
    const score = (rank[d.resolved_confidence] || 0) * 10 + (d.parent ? 0 : 5);
    if (!cur || score > cur.score) best.set(c, { score, name: d.resolved_name || d.description });
  }
  PHYSICAL_LABELS = new Map([...best].map(([c, v]) => [c, v.name]));
}

/* ------------------------------------------------------------------ state */
const DEFAULT_PREFS = () => ({
  columns: Object.fromEntries(Object.entries(ALL_COLUMNS)
    .map(([v, cols]) => [v, cols.filter((c) => c.def).map((c) => c.key)])),
  widths: { devices: {}, drivers: {}, cleanup: {} },
  groupBy: { devices: "", drivers: "", cleanup: "" },
  theme: null,
});

function loadPrefs() {
  const base = DEFAULT_PREFS();
  try {
    const saved = JSON.parse(localStorage.getItem(STORE) || "{}");
    for (const view of Object.keys(base.columns)) {
      const keys = saved.columns && saved.columns[view];
      if (Array.isArray(keys) && keys.length) {
        const valid = keys.filter((k) => colDef(view, k));
        if (valid.length) base.columns[view] = valid;
      }
      if (saved.widths && saved.widths[view]) base.widths[view] = { ...saved.widths[view] };
      if (saved.groupBy && typeof saved.groupBy[view] === "string") {
        base.groupBy[view] = saved.groupBy[view];
      }
    }
    if (saved.theme) base.theme = saved.theme;
  } catch { /* corrupt prefs are not worth a crash */ }
  return base;
}

const state = {
  snap: null,
  view: "devices",
  search: "",
  rows: [],
  groups: [],
  selectedId: null,
  checked: new Set(),
  collapsedGroups: { devices: new Set(), drivers: new Set(), cleanup: new Set() },
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
  treeMode: "tree",
  prefs: loadPrefs(),
};

function savePrefs() {
  try { localStorage.setItem(STORE, JSON.stringify(state.prefs)); } catch { /* private mode */ }
}

const visibleColumns = () =>
  state.prefs.columns[state.view].map((k) => colDef(state.view, k)).filter(Boolean);
const columnWidth = (col) => state.prefs.widths[state.view][col.key] || col.w || 140;

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
  for (const d of snap.devices) {
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
  const ghosts = snap.devices.filter((d) => !d.present);
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
  const col = colDef(state.view, s.key);
  const val = col ? (r) => colValue(col, r) : (r) => r[s.key];
  return rows.slice().sort((a, b) => cmp(val(a), val(b)) * s.dir);
}

function groupRows(rows) {
  const key = state.prefs.groupBy[state.view];
  if (!key) return [{ key: "", label: "", rows }];
  const spec = GROUPS[state.view].find((g) => g.key === key);
  const get = spec && spec.get ? spec.get : (r) => r[key];
  const buckets = new Map();
  for (const r of rows) {
    const raw = get(r);
    const label = (raw === "" || raw == null) ? "(none)" : String(raw);
    if (!buckets.has(label)) buckets.set(label, []);
    buckets.get(label).push(r);
  }
  return [...buckets.entries()]
    .map(([label, list]) => ({ key: label, label, rows: list }))
    .sort((a, b) => (a.label === "(none)") - (b.label === "(none)") || cmp(a.label, b.label));
}

/* ---------------------------------------------------------------- render */
const chip = (field, value, label) =>
  `<button class="chip${state.filters[state.view][field] === value ? " on" : ""}" data-chip="${field}" data-value="${value}">${label}</button>`;
const opt = (value, label, sel) =>
  `<option value="${esc(value)}"${sel === value ? " selected" : ""}>${esc(label)}</option>`;

function groupSelect() {
  const cur = state.prefs.groupBy[state.view];
  return `<label class="inline-lbl">Group by
    <select data-groupby>${GROUPS[state.view].map((g) => opt(g.key, g.label, cur)).join("")}</select>
  </label>`;
}

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
      <select data-filter="type">${opt("", "All types", f.type)}${types.map((c) => opt(c, c, f.type)).join("")}</select>
      ${groupSelect()}`;
  } else if (state.view === "drivers") {
    const classes = [...new Set(state.snap.drivers.map((d) => d.class_name).filter(Boolean))].sort();
    box.innerHTML = `
      ${chip("state", "all", "All")}${chip("state", "inuse", "In use")}
      ${chip("state", "orphaned", "Orphaned")}${chip("state", "superseded", "Superseded")}
      ${chip("state", "extension", "Extensions")}
      <select data-filter="cls">${opt("", "All classes", f.cls)}${classes.map((c) => opt(c, c, f.cls)).join("")}</select>
      ${groupSelect()}`;
  } else if (state.view === "cleanup") {
    box.innerHTML = `${chip("kind", "all", "All")}${chip("kind", "orphaned", "Orphaned")}
      ${chip("kind", "superseded", "Superseded")}${chip("kind", "problem", "Problems")}
      ${groupSelect()}`;
  } else if (state.view === "tree") {
    box.innerHTML = `
      <button class="chip${state.treeMode === "tree" ? " on" : ""}" data-treemode="tree">Outline</button>
      <button class="chip${state.treeMode === "graph" ? " on" : ""}" data-treemode="graph">Graph</button>`;
  } else {
    box.innerHTML = "";
  }
}

function renderTable() {
  const cols = visibleColumns();
  const rows = (state.rows = sortRows(applyFilters(baseRows())));
  const groups = (state.groups = groupRows(rows));
  const s = state.sort[state.view];
  const grouped = !!state.prefs.groupBy[state.view];

  $("#gridCols").innerHTML = cols
    .map((c) => `<col style="width:${columnWidth(c)}px">`).join("");

  $("#gridHead").innerHTML = `<tr>${cols.map((c) => {
    const active = s.key === c.key;
    const arrow = active ? `<span class="arrow">${s.dir > 0 ? "\u25b2" : "\u25bc"}</span>` : "";
    return `<th${c.nosort ? ' class="nosort"' : ` data-sort="${c.key}"`} title="${esc(c.label)}">` +
      `${esc(c.label)}${arrow}<span class="col-grip" data-grip="${esc(c.key)}"></span></th>`;
  }).join("")}</tr>`;

  const collapsed = state.collapsedGroups[state.view];
  const out = [];
  for (const g of groups) {
    if (grouped) {
      const isCollapsed = collapsed.has(g.key);
      const meta = state.view === "devices"
        ? `${g.rows.filter((r) => r.present).length} connected`
        : state.view === "drivers"
          ? `${g.rows.filter((r) => r.orphaned).length} orphaned`
          : "";
      out.push(`<tr class="group" data-group="${esc(g.key)}"><td colspan="${cols.length}">
        <span class="twisty">${isCollapsed ? "\u25b8" : "\u25be"}</span>${esc(g.label)}
        <span class="gcount">${g.rows.length}</span>
        ${meta ? `<span class="gmeta">${esc(meta)}</span>` : ""}</td></tr>`);
      if (isCollapsed) continue;
    }
    for (const r of g.rows) out.push(rowHtml(r, cols));
  }

  $("#gridBody").innerHTML = out.join("");
  $("#emptyState").hidden = rows.length > 0;
  $("#rowInfo").textContent =
    `${rows.length} of ${baseRows().length} rows` + (grouped ? ` in ${groups.length} groups` : "");
  $("#btnExpandAll").hidden = !grouped;
  $("#btnCollapseAll").hidden = !grouped;
  updateSelectionUi();
}

function rowHtml(r, cols) {
  const id = r.instance_id || r.driver_name || r.name;
  const classes = [];
  if (id === state.selectedId) classes.push("sel");
  if (state.view === "devices" && !r.present) classes.push("ghost");
  return `<tr class="${classes.join(" ")}" data-id="${esc(id)}">${cols.map((c) => {
    const raw = colValue(c, r);
    const html = c.cell ? c.cell(r) : esc(listText(raw));
    const title = c.cell ? "" : ` title="${esc(listText(raw))}"`;
    return `<td class="${c.cls || ""}"${title}>${html}</td>`;
  }).join("")}</tr>`;
}

function restoreTablePane() {
  $("#tablePane").innerHTML = `
    <div class="table-scroll">
      <table id="grid">
        <colgroup id="gridCols"></colgroup>
        <thead id="gridHead"></thead><tbody id="gridBody"></tbody>
      </table>
      <p class="empty" id="emptyState" hidden>Nothing matches the current search and filters.</p>
    </div>
    <footer class="table-foot">
      <span id="rowInfo">—</span>
      <button class="btn small" id="btnExpandAll" hidden>Expand all</button>
      <button class="btn small" id="btnCollapseAll" hidden>Collapse all</button>
      <span class="spacer"></span>
      <span id="selInfo"></span>
      <button class="btn danger small" id="btnBulkDelete" hidden>Delete selected packages…</button>
      <button class="btn small" id="btnColumns" title="Choose columns">Columns…</button>
    </footer>`;
}

function render() {
  if (!state.snap) return;
  renderFilters();
  if (state.view === "tree") {
    if (state.treeMode === "graph") renderGraph(); else renderTree();
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
  $("#btnAdmin").hidden = !!m.elevated;
}

/* ------------------------------------------------------- column resizing */
let measureCtx = null;
function textWidth(text, font) {
  if (!measureCtx) measureCtx = document.createElement("canvas").getContext("2d");
  measureCtx.font = font;
  return measureCtx.measureText(text).width;
}

function autoFitColumn(key) {
  const col = colDef(state.view, key);
  if (!col) return;
  const font = getComputedStyle(document.body).font ||
    '12.5px "Segoe UI", system-ui, sans-serif';
  let widest = textWidth(col.label, font) + 26;
  const sample = state.rows.slice(0, 400);
  for (const r of sample) {
    const text = listText(colValue(col, r));
    if (!text) continue;
    widest = Math.max(widest, textWidth(String(text), font) + 26);
  }
  state.prefs.widths[state.view][key] = Math.round(Math.min(Math.max(widest, 56), 720));
  savePrefs();
  renderTable();
}

function bindColumnResize() {
  let drag = null;
  document.addEventListener("mousedown", (e) => {
    const grip = e.target.closest(".col-grip");
    if (!grip) return;
    e.preventDefault();
    e.stopPropagation();
    const key = grip.dataset.grip;
    const cols = visibleColumns();
    const index = cols.findIndex((c) => c.key === key);
    if (index < 0) return;
    drag = { key, index, startX: e.clientX, startW: columnWidth(cols[index]) };
    grip.classList.add("dragging");
    document.body.classList.add("resizing");
  });

  document.addEventListener("mousemove", (e) => {
    if (!drag) return;
    const next = Math.max(40, drag.startW + (e.clientX - drag.startX));
    const colEl = $("#gridCols").children[drag.index];
    if (colEl) colEl.style.width = `${next}px`;
    drag.current = next;
  });

  document.addEventListener("mouseup", () => {
    if (!drag) return;
    if (drag.current) {
      state.prefs.widths[state.view][drag.key] = Math.round(drag.current);
      savePrefs();
    }
    $$(".col-grip.dragging").forEach((g) => g.classList.remove("dragging"));
    document.body.classList.remove("resizing");
    drag = null;
  });

  document.addEventListener("dblclick", (e) => {
    const grip = e.target.closest(".col-grip");
    if (grip) {
      e.preventDefault();
      e.stopPropagation();
      autoFitColumn(grip.dataset.grip);
    }
  });
}

/* --------------------------------------------------------- column picker */
async function openColumnPicker() {
  const view = state.view;
  if (!ALL_COLUMNS[view]) return void toast("No columns here", "Switch to a table view first.", "warn");
  const chosen = new Set(state.prefs.columns[view]);
  const body = `
    <p class="dim" style="margin-top:0">Tick the columns to show in <b>${esc(view)}</b>.
    Drag a header edge to resize, or double-click it to fit the contents.</p>
    <div class="col-picker">
      ${ALL_COLUMNS[view].map((c) => {
        const locked = c.key === "_check";
        return `<label class="${locked ? "locked" : ""}">
          <input type="checkbox" data-col="${esc(c.key)}"${chosen.has(c.key) ? " checked" : ""}${locked ? " disabled" : ""}>
          ${esc(c.label || "(select)")}</label>`;
      }).join("")}
    </div>`;
  const res = await modal({ title: "Choose columns", bodyHtml: body, okLabel: "Apply", danger: false,
    collect: () => $$("#modalBody [data-col]").filter((i) => i.checked || i.disabled).map((i) => i.dataset.col) });
  if (!res) return;
  const keys = res.length ? res : ALL_COLUMNS[view].filter((c) => c.def).map((c) => c.key);
  state.prefs.columns[view] = ALL_COLUMNS[view].map((c) => c.key).filter((k) => keys.includes(k));
  savePrefs();
  renderTable();
}

function resetColumns() {
  const fresh = DEFAULT_PREFS();
  state.prefs.columns = fresh.columns;
  state.prefs.widths = fresh.widths;
  savePrefs();
  render();
  toast("Columns reset", "", "ok");
}

/* ------------------------------------------------------------ tree (text) */
function childMap() {
  const byId = new Map(state.snap.devices.map((d) => [d.instance_id, d]));
  const kids = new Map();
  const roots = [];
  for (const d of state.snap.devices) {
    if (d.parent && byId.has(d.parent)) {
      if (!kids.has(d.parent)) kids.set(d.parent, []);
      kids.get(d.parent).push(d);
    } else {
      roots.push(d);
    }
  }
  for (const list of kids.values()) list.sort((a, b) => cmp(a.resolved_name, b.resolved_name));
  roots.sort((a, b) => cmp(a.resolved_name, b.resolved_name));
  return { byId, kids, roots };
}

function renderTree() {
  const { kids, roots } = childMap();
  const q = state.search.trim().toLowerCase();
  const matches = (d) => !q || (d.search_blob || "").includes(q);
  const subtreeMatches = (d, depth = 0) => {
    if (matches(d)) return true;
    if (depth > 6) return false;
    return (kids.get(d.instance_id) || []).some((c) => subtreeMatches(c, depth + 1));
  };
  const node = (d, depth) => {
    if (!subtreeMatches(d)) return "";
    const children = kids.get(d.instance_id) || [];
    const open = state.treeExpanded.has(d.instance_id) || (q && depth < 4) || depth < 1;
    const twisty = children.length ? (open ? "\u25be" : "\u25b8") : "\u00b7";
    return `<li>
      <div class="node" data-id="${esc(d.instance_id)}" data-toggle="${children.length ? 1 : 0}">
        <span class="twisty">${twisty}</span>
        <span>${esc(d.resolved_name || d.description)}</span>
        <span class="pill">${esc(d.device_type || "")}</span>
        ${statusPill(d.status, d.problem_code)}
        <span class="iid">${esc(d.instance_id)}</span>
      </div>
      ${children.length && open ? `<ul>${children.map((c) => node(c, depth + 1)).join("")}</ul>` : ""}
    </li>`;
  };
  $("#tablePane").innerHTML =
    `<div class="table-scroll"><div class="tree"><ul>${roots.map((r) => node(r, 0)).join("")}</ul></div></div>` +
    `<footer class="table-foot"><span>${state.snap.devices.length} device nodes \u00b7 click the arrow to expand, the row to inspect</span>
      <span class="spacer"></span>
      <button class="btn small" id="btnTreeExpand">Expand all</button>
      <button class="btn small" id="btnTreeCollapse">Collapse all</button></footer>`;
}

/* ----------------------------------------------------------- tree (graph) */
const graph = { root: "", depth: 3, showDrivers: false, scale: 1, tx: 40, ty: 40, laidOut: false };
const NODE_W = 244, NODE_H = 38, COL_GAP = 300, ROW_GAP = 48;

function buildGraphModel() {
  const { byId, kids, roots } = childMap();
  const startIds = graph.root && byId.has(graph.root)
    ? [graph.root]
    : roots.flatMap((r) => (kids.get(r.instance_id) || []).length ? [r.instance_id] : [r.instance_id]);
  const MAX = 300;
  const nodes = [];
  let truncated = 0;

  const visit = (id, depth) => {
    const dev = byId.get(id);
    if (!dev) return null;
    if (nodes.length >= MAX) { truncated++; return null; }
    const childIds = (kids.get(id) || []).map((c) => c.instance_id);
    const open = depth + 1 < graph.depth || state.treeExpanded.has(id);
    const node = { id, dev, depth, children: [], hidden: open ? 0 : childIds.length, kind: "device" };
    nodes.push(node);
    if (open) {
      for (const c of childIds) {
        const cn = visit(c, depth + 1);
        if (cn) node.children.push(cn);
      }
      node.hidden = childIds.length - node.children.length;
    }
    return node;
  };

  const tops = startIds.map((id) => visit(id, 0)).filter(Boolean);

  let cursor = 0;
  const place = (n) => {
    n.x = n.depth * COL_GAP;
    if (!n.children.length) { n.y = cursor; cursor += ROW_GAP; }
    else {
      n.children.forEach(place);
      n.y = (n.children[0].y + n.children[n.children.length - 1].y) / 2;
    }
  };
  tops.forEach((t) => { place(t); cursor += ROW_GAP * 0.5; });

  const edges = [];
  for (const n of nodes) for (const c of n.children) edges.push({ from: n, to: c, kind: "child" });

  if (graph.showDrivers) {
    const maxDepth = Math.max(0, ...nodes.map((n) => n.depth));
    const packs = new Map();
    for (const n of nodes) {
      const names = [n.dev.driver_name, ...(n.dev.extension_drivers || [])].filter(Boolean);
      for (const name of names) {
        if (!packs.has(name)) packs.set(name, { id: `drv:${name}`, name, kind: "driver", users: [] });
        packs.get(name).users.push(n);
      }
    }
    let py = 0;
    for (const p of [...packs.values()].sort((a, b) => cmp(a.name, b.name))) {
      p.depth = maxDepth + 1;
      p.x = p.depth * COL_GAP;
      p.y = p.users.reduce((s, u) => s + u.y, 0) / p.users.length;
      if (p.y < py) p.y = py;
      py = p.y + ROW_GAP;
      nodes.push(p);
      for (const u of p.users) edges.push({ from: u, to: p, kind: "driver" });
    }
  }
  return { nodes, edges, truncated };
}

function fitGraph(nodes) {
  const wrap = $("#graphWrap");
  if (!wrap || !nodes.length) return;
  const xs = nodes.map((n) => n.x), ys = nodes.map((n) => n.y);
  const minX = Math.min(...xs), maxX = Math.max(...xs) + NODE_W;
  const minY = Math.min(...ys), maxY = Math.max(...ys) + NODE_H;
  const w = wrap.clientWidth || 1200, h = wrap.clientHeight || 700;
  const scale = Math.min(w / (maxX - minX + 90), h / (maxY - minY + 90), 1.4);
  // Fitting a tall tree to the window can shrink it past legibility; below
  // this it is better to start at the top-left and let the user pan.
  graph.scale = Math.min(Math.max(scale, 0.42), 1.4);
  graph.tx = 45 - minX * graph.scale;
  graph.ty = 45 - minY * graph.scale;
  applyGraphTransform();
}

function applyGraphTransform() {
  const g = $("#graphZoom");
  if (g) g.setAttribute("transform", `translate(${graph.tx},${graph.ty}) scale(${graph.scale})`);
}

function clipText(text, maxPx, font) {
  let s = String(text || "");
  if (textWidth(s, font) <= maxPx) return s;
  while (s.length > 3 && textWidth(s + "…", font) > maxPx) s = s.slice(0, -1);
  return s + "…";
}

function renderGraph() {
  const { byId, roots } = childMap();
  const busOptions = roots.flatMap((r) => [r, ...(state.snap.devices.filter((d) => d.parent === r.instance_id))]);
  const model = buildGraphModel();
  const q = state.search.trim().toLowerCase();
  const nameFont = '12px "Segoe UI", system-ui, sans-serif';
  const subFont = '10px ui-monospace, Consolas, monospace';

  const edgePath = (e) => {
    const x1 = e.from.x + NODE_W, y1 = e.from.y + NODE_H / 2;
    const x2 = e.to.x, y2 = e.to.y + NODE_H / 2;
    const mid = (x1 + x2) / 2;
    return `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`;
  };

  const nodeSvg = (n) => {
    if (n.kind === "driver") {
      return `<g class="gnode drv" data-driver="${esc(n.name)}" transform="translate(${n.x},${n.y})">
        <rect width="${NODE_W - 60}" height="${NODE_H}" rx="9" fill="var(--accent-soft)" stroke="var(--accent)"></rect>
        <text class="gname" x="12" y="16">${esc(n.name)}</text>
        <text class="gsub" x="12" y="29">${n.users.length} device(s)</text>
      </g>`;
    }
    const d = n.dev;
    const hit = q && (d.search_blob || "").includes(q);
    const cls = ["gnode", d.instance_id === state.selectedId ? "sel" : "",
      hit ? "hit" : "", d.present ? "" : "ghost"].filter(Boolean).join(" ");
    const fill = d.present ? "var(--bg-elev)" : "var(--bg-elev2)";
    const stroke = d.problem_code ? "var(--danger)" : d.present ? "var(--line)" : "var(--ghost)";
    const badge = n.hidden > 0
      ? `<g class="gexp-hit" data-expand="${esc(d.instance_id)}">
           <rect x="${NODE_W - 34}" y="${NODE_H / 2 - 9}" width="30" height="18" rx="9"
                 fill="var(--bg-elev2)" stroke="var(--line)"></rect>
           <text class="gexp" x="${NODE_W - 19}" y="${NODE_H / 2 + 4}" text-anchor="middle">+${n.hidden}</text>
         </g>` : "";
    return `<g class="${cls}" data-id="${esc(d.instance_id)}" transform="translate(${n.x},${n.y})">
      <rect width="${NODE_W}" height="${NODE_H}" rx="9" fill="${fill}" stroke="${stroke}"></rect>
      <text class="gname" x="12" y="16">${esc(clipText(d.resolved_name || d.description, NODE_W - 56, nameFont))}</text>
      <text class="gsub" x="12" y="29">${esc(clipText(`${d.device_type || ""} · ${d.instance_id}`, NODE_W - 56, subFont))}</text>
      ${badge}
    </g>`;
  };

  $("#tablePane").innerHTML = `
    <div class="graph-wrap" id="graphWrap">
      <div class="graph-toolbar">
        <label>Root
          <select id="graphRoot">
            <option value="">Whole machine</option>
            ${busOptions.map((d) => `<option value="${esc(d.instance_id)}"${graph.root === d.instance_id ? " selected" : ""}>${esc(d.resolved_name || d.description)}</option>`).join("")}
            ${state.selectedId && byId.has(state.selectedId) ? `<option value="${esc(state.selectedId)}"${graph.root === state.selectedId ? " selected" : ""}>Selected: ${esc(byId.get(state.selectedId).resolved_name)}</option>` : ""}
          </select>
        </label>
        <label>Depth <input type="number" id="graphDepth" min="1" max="8" value="${graph.depth}" style="width:52px"></label>
        <label><input type="checkbox" id="graphDrivers"${graph.showDrivers ? " checked" : ""}> Driver packages</label>
        <button class="btn small" id="graphFit">Fit</button>
        <button class="btn small" id="graphReset">Reset root</button>
      </div>
      <svg id="graphSvg">
        <g id="graphZoom">
          <g id="graphEdges">${model.edges.map((e) =>
            `<path class="gedge ${e.kind === "driver" ? "drv" : ""}" d="${edgePath(e)}"></path>`).join("")}</g>
          <g id="graphNodes">${model.nodes.map(nodeSvg).join("")}</g>
        </g>
      </svg>
      <div class="graph-legend">
        <span><i style="background:var(--bg-elev);border:1px solid var(--line)"></i>device</span>
        <span><i style="background:var(--bg-elev2);border:1px dashed var(--ghost)"></i>disconnected</span>
        <span><i style="background:var(--accent-soft);border:1px solid var(--accent)"></i>driver package</span>
      </div>
      ${model.truncated ? `<div class="graph-note">${model.truncated} more node(s) not drawn — narrow the root or reduce depth</div>` : ""}
    </div>
    <footer class="table-foot">
      <span>${model.nodes.length} nodes \u00b7 drag to pan, wheel to zoom, click a node to inspect, double-click to re-root</span>
    </footer>`;

  if (!graph.laidOut) { fitGraph(model.nodes); graph.laidOut = true; } else applyGraphTransform();
  bindGraphInteractions(model);
}

function bindGraphInteractions(model) {
  const svg = $("#graphSvg");
  if (!svg) return;
  let pan = null;

  svg.addEventListener("mousedown", (e) => {
    if (e.target.closest(".gnode")) return;
    pan = { x: e.clientX, y: e.clientY, tx: graph.tx, ty: graph.ty };
    svg.classList.add("panning");
  });
  window.addEventListener("mousemove", (e) => {
    if (!pan) return;
    graph.tx = pan.tx + (e.clientX - pan.x);
    graph.ty = pan.ty + (e.clientY - pan.y);
    applyGraphTransform();
  });
  window.addEventListener("mouseup", () => { pan = null; svg.classList.remove("panning"); });

  svg.addEventListener("wheel", (e) => {
    e.preventDefault();
    const rect = svg.getBoundingClientRect();
    const px = e.clientX - rect.left, py = e.clientY - rect.top;
    const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
    const next = Math.min(3, Math.max(0.06, graph.scale * factor));
    graph.tx = px - (px - graph.tx) * (next / graph.scale);
    graph.ty = py - (py - graph.ty) * (next / graph.scale);
    graph.scale = next;
    applyGraphTransform();
  }, { passive: false });

  svg.addEventListener("click", (e) => {
    const exp = e.target.closest("[data-expand]");
    if (exp) {
      state.treeExpanded.add(exp.dataset.expand);
      renderGraph();
      return;
    }
    const drv = e.target.closest("[data-driver]");
    if (drv) return void openDriver(drv.dataset.driver);
    const node = e.target.closest(".gnode[data-id]");
    if (node) openDevice(node.dataset.id);
  });

  svg.addEventListener("dblclick", (e) => {
    const node = e.target.closest(".gnode[data-id]");
    if (!node) return;
    graph.root = node.dataset.id;
    graph.laidOut = false;
    renderGraph();
  });

  $("#graphRoot").addEventListener("change", (e) => {
    graph.root = e.target.value; graph.laidOut = false; renderGraph();
  });
  $("#graphDepth").addEventListener("change", (e) => {
    graph.depth = Math.min(8, Math.max(1, parseInt(e.target.value, 10) || 3));
    graph.laidOut = false; renderGraph();
  });
  $("#graphDrivers").addEventListener("change", (e) => {
    graph.showDrivers = e.target.checked; graph.laidOut = false; renderGraph();
  });
  $("#graphFit").addEventListener("click", () => fitGraph(model.nodes));
  $("#graphReset").addEventListener("click", () => {
    graph.root = ""; graph.laidOut = false; renderGraph();
  });
}

/* ---------------------------------------------------------------- detail */
async function openDevice(instanceId) {
  state.selectedId = instanceId;
  if (state.view !== "tree") renderTable();
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
        d.container_id && ["Container ID", esc(d.container_id)],
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
        <button class="btn small" data-graphroot="${esc(d.instance_id)}">Show in graph</button>
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
function modal({ title, bodyHtml, okLabel = "Confirm", danger = true, collect = null }) {
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
      if (collect) return done(collect());
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
  if (!names.length) return;
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

/* ------------------------------------------------------------ elevation */
async function openAsAdmin() {
  const go = await modal({
    title: "Restart the console as administrator?",
    okLabel: "Restart elevated", danger: false,
    bodyHtml: `<p>The console will close and reopen with administrator rights on the same
      address, so this page keeps working — Windows will show a UAC prompt.</p>
      <p class="note">Elevated, driver deletions and device changes run without a prompt each time.
      Decline the UAC prompt and the current console simply carries on unelevated.</p>`,
  });
  if (!go) return;
  const waiting = toast("Waiting for the UAC prompt…", "Approve it to restart elevated.");
  try { await post("/api/relaunch-admin", {}); } catch { /* the socket drops as it shuts down */ }

  const deadline = Date.now() + 120000;
  const tick = async () => {
    try {
      const r = await api("/api/ping");
      if (r.elevated) {
        waiting.remove();
        toast("Running as administrator", "", "ok");
        setTimeout(() => location.reload(), 600);
        return;
      }
      if (r.elevation_declined) {
        waiting.remove();
        toast("Still a standard user", "The UAC prompt was declined, so the console kept running unelevated.", "warn");
        await reload(false);
        return;
      }
    } catch { /* port is briefly free during the handover */ }
    if (Date.now() < deadline) setTimeout(tick, 600);
    else { waiting.remove(); toast("Gave up waiting for the elevated instance", "", "err"); }
  };
  setTimeout(tick, 900);
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
  if (view !== "tree" && !$("#grid")) restoreTablePane();
  render();
}

async function reload(refresh = true) {
  try {
    const data = await api(`/api/snapshot${refresh ? "?refresh=1" : ""}`);
    state.snap = data;
    buildPhysicalLabels(data.devices);
    render();
  } catch (e) {
    toast("Could not load snapshot", e.message, "err");
  }
}

function bind() {
  $$(".tab").forEach((t) => t.addEventListener("click", () => setView(t.dataset.view)));

  $("#search").addEventListener("input", (e) => {
    state.search = e.target.value;
    if (state.view === "tree") { state.treeMode === "graph" ? renderGraph() : renderTree(); }
    else renderTable();
  });

  $("#btnRefresh").addEventListener("click", () => reload(true));
  $("#btnAdmin").addEventListener("click", openAsAdmin);

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
    if (act === "columns") return void openColumnPicker();
    if (act === "reset-columns") return void resetColumns();
    if (act === "toggle-theme") {
      const root = document.documentElement;
      const next = root.dataset.theme === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      state.prefs.theme = next;
      savePrefs();
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
    if (th && !e.target.closest(".col-grip")) {
      const s = state.sort[state.view];
      const key = th.dataset.sort;
      if (s.key === key) s.dir *= -1; else { s.key = key; s.dir = 1; }
      renderTable();
      return;
    }

    const groupRow = e.target.closest("tr.group");
    if (groupRow) {
      const set = state.collapsedGroups[state.view];
      const key = groupRow.dataset.group;
      if (set.has(key)) set.delete(key); else set.add(key);
      renderTable();
      return;
    }

    if (e.target.closest("#btnExpandAll")) {
      state.collapsedGroups[state.view].clear();
      renderTable();
      return;
    }
    if (e.target.closest("#btnCollapseAll")) {
      state.collapsedGroups[state.view] = new Set(state.groups.map((g) => g.key));
      renderTable();
      return;
    }
    if (e.target.closest("#btnColumns")) return void openColumnPicker();

    if (e.target.closest("#btnTreeExpand")) {
      state.snap.devices.forEach((d) => state.treeExpanded.add(d.instance_id));
      renderTree();
      return;
    }
    if (e.target.closest("#btnTreeCollapse")) {
      state.treeExpanded.clear();
      renderTree();
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

    const tr = e.target.closest("#gridBody tr:not(.group)");
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
    if (drv && !e.target.closest("svg")) return void openDriver(drv.dataset.driver);

    const gr = e.target.closest("[data-graphroot]");
    if (gr) {
      graph.root = gr.dataset.graphroot;
      graph.laidOut = false;
      state.treeMode = "graph";
      setView("tree");
      return;
    }

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
          <input type="text" data-opt="target_dir" value="C:\\Drivers">`,
      });
      if (opts && opts.target_dir) {
        await runAction({ verb: "export-driver", driver_name: name, target_dir: opts.target_dir },
          `Export ${name}`);
      }
      return;
    }

    if (e.target.closest("#btnBulkDelete")) return void confirmDeleteDriver([...state.checked]);

    if (e.target.closest("#btnCloseDetail")) {
      $("#detail").hidden = true;
      state.selectedId = null;
      if (state.view !== "tree") renderTable();
    }
  });

  $("#filters").addEventListener("click", (e) => {
    const mode = e.target.closest("[data-treemode]");
    if (mode) {
      state.treeMode = mode.dataset.treemode;
      graph.laidOut = false;
      render();
      return;
    }
    const c = e.target.closest("[data-chip]");
    if (!c) return;
    state.filters[state.view][c.dataset.chip] = c.dataset.value;
    render();
  });

  $("#filters").addEventListener("change", (e) => {
    if (e.target.matches("[data-groupby]")) {
      state.prefs.groupBy[state.view] = e.target.value;
      state.collapsedGroups[state.view].clear();
      savePrefs();
      renderTable();
      return;
    }
    const s = e.target.closest("[data-filter]");
    if (!s) return;
    state.filters[state.view][s.dataset.filter] = s.value;
    render();
  });

  bindColumnResize();

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

(function init() {
  if (state.prefs.theme) document.documentElement.dataset.theme = state.prefs.theme;
  bind();
  reload(false);
})();
