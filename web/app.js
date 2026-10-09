const STAGES = [
  { id: "discovery", index: "01", title: "Threat discovery" },
  { id: "intel", index: "02", title: "Attack intelligence" },
  { id: "remediate", index: "03", title: "Autonomous remediation" },
  { id: "defense", index: "04", title: "Continuous defense" },
  { id: "drift", index: "05", title: "Runtime drift" },
];

const PILLARS = [
  ["Threat discovery", "Read the deploy and surface misconfigurations, default credentials, and dependencies that are missing a published fix."],
  ["Attack intelligence", "Join separate signals — a published port, a default password, a privileged container — into paths with a stated impact."],
  ["Autonomous remediation", "Edit the workspace copy, then scan it again. A fix counts when the finding is gone."],
  ["Continuous defense", "Keep reading the files. A later change that puts a path back shows up on the tape."],
  ["Runtime drift", "On Northwind Checkout, stage 05 starts the service in a sandbox and compares the running process with the files. Scan that demo first."],
];

let state = null;
let stage = "discovery";
let busy = false;
let pending = "";
let fileFilter = null;

const view = document.querySelector("#view");
const tape = document.querySelector("#tape");
const stages = document.querySelector("#stages");
const risk = document.querySelector("#risk");
const target = document.querySelector("#target");
const error = document.querySelector("#error");

document.querySelector("#run").addEventListener("click", runLoop);
document.querySelector("#reset").addEventListener("click", () => act("/api/reset", "discovery"));
document.querySelector("#scan").addEventListener("click", () => act("/api/scan", "discovery"));

stages.innerHTML = STAGES.map(
  (item) => `<button type="button" data-stage="${item.id}"><span class="idx">${item.index}</span>${esc(item.title)}</button>`
).join("");
stages.addEventListener("click", (event) => {
  const button = event.target.closest("button");
  if (!button || busy) return;
  stage = button.dataset.stage;
  render();
});

boot();
setInterval(poll, 2000);

async function boot() {
  try {
    state = await api("/api/state");
    render();
  } catch (err) {
    showError(err);
  }
}

async function poll() {
  if (!state?.watching || busy) return;
  try {
    const next = await api("/api/check", { method: "POST" });
    const changed = signature(next) !== signature(state);
    state = next;
    if (changed) render();
    else paintWatch();
  } catch (err) {
    showError(err);
  }
}

async function act(url, nextStage) {
  if (busy) return;
  busy = true;
  pending = url;
  render();
  try {
    state = await api(url, { method: "POST" });
    if (nextStage) stage = nextStage;
    clearError();
  } catch (err) {
    showError(err);
  } finally {
    busy = false;
    pending = "";
    render();
  }
}

async function runLoop() {
  if (busy) return;
  busy = true;
  clearError();
  render();
  try {
    stage = "discovery";
    state = await api("/api/scan", { method: "POST" });
    render();
    await pause(1100);
    stage = "intel";
    render();
    await pause(1400);
    stage = "remediate";
    render();
    await pause(900);
    state = await api("/api/remediate", { method: "POST" });
    render();
    await pause(1100);
    stage = "defense";
  } catch (err) {
    showError(err);
  } finally {
    busy = false;
    render();
  }
}

function render() {
  paintChrome();
  paintTape();
  if (!state || state.phase === "ready") {
    view.innerHTML = stage === "drift" ? driftNeedsScan() : readyView();
    bindActions();
    return;
  }
  const views = {
    discovery: discoveryView,
    intel: intelView,
    remediate: remediateView,
    defense: defenseView,
    drift: driftView,
  };
  view.innerHTML = views[stage]();
  bindActions();
}

function paintChrome() {
  const score = state ? state.risk : 0;
  const tone = score === 0 && state && state.phase !== "ready" ? "zero" : score >= 60 ? "hot" : "";
  risk.className = `risk ${tone}`;
  risk.innerHTML = `<div class="risk-value">${state ? score : "–"}</div><div class="risk-label">risk points</div>`;
  target.innerHTML = state
    ? `<div class="target-kicker">${esc(state.target.badge || "Demo deploy")}</div><div class="target-name">${esc(state.target.name)}</div><div class="target-summary">${esc(state.target.summary)}</div>`
    : "";
  const note = document.querySelector("#demo-note");
  if (note && state?.target) {
    note.textContent = `${state.target.name} is a demo deploy. Northwind Checkout and Harbor Archive are samples, not real customers.`;
  }
  paintSwitcher();
  for (const button of stages.querySelectorAll("button")) {
    button.classList.toggle("active", button.dataset.stage === stage);
    button.disabled = busy;
  }
  document.querySelector("#run").disabled = busy;
  document.querySelector("#reset").disabled = busy;
  const scan = document.querySelector("#scan");
  if (scan) {
    const ready = Boolean(state && state.phase === "ready");
    const name = state?.target?.name || "deployment";
    scan.hidden = !ready;
    scan.textContent = `Scan ${name}`;
    scan.disabled = busy || !state;
  }
}

function paintTape() {
  const events = state ? [...state.events].reverse() : [];
  const rows = events.length
    ? events.map((event) => `
        <article class="event">
          <time datetime="${esc(event.at)}">${esc(clock(event.at))}</time>
          <strong>${esc(event.title)}</strong>
          <p>${esc(event.detail)}</p>
        </article>
      `).join("")
    : `<p class="empty">The tape stays quiet until a scan. Each pass — discovery, the joined paths, a verified fix, a regression — lands here.</p>`;
  tape.innerHTML = `<h2 class="tape-title">Event tape</h2>${rows}`;
}

function paintWatch() {
  const node = document.querySelector("[data-checked]");
  if (node && state?.last_checked) node.textContent = `Last read ${clock(state.last_checked)}`;
}

function readyView() {
  const demos = state?.demos || [];
  const name = state?.target?.name || "the demo";
  const cards = demos.map((demo) => {
    const selected = state?.target?.id === demo.id;
    return `
      <button type="button" class="demo-card${selected ? " selected" : ""}" data-demo="${esc(demo.id)}" aria-pressed="${selected}">
        <span class="demo-badge">Demo</span>
        <h2>${esc(demo.name)}</h2>
        <p>${esc(demo.role)}</p>
      </button>
    `;
  }).join("");
  return `
    <p class="kicker">Demo deploys</p>
    <h1>Find the path, close it, and watch for its return.</h1>
    <p class="lede">Northwind Checkout and Harbor Archive are sample deployments, not real customers. Scan reads the selected demo. On Northwind Checkout, stage 05 Runtime drift then starts the checkout in a sandbox and compares the running process with those files.</p>
    <div class="actions">
      <button class="primary" type="button" data-act="/api/scan" data-stage="discovery" ${busy || !state ? "disabled" : ""}>Scan ${esc(name)}</button>
    </div>
    <div class="demo-cards">${cards}</div>
    <div class="pillars">
      ${PILLARS.map(([title, copy]) => `<article class="pillar"><h2>${esc(title)}</h2><p>${esc(copy)}</p></article>`).join("")}
    </div>
  `;
}

function discoveryView() {
  const known = new Set((state.files || []).map((file) => file.path));
  if (fileFilter && !known.has(fileFilter)) fileFilter = null;
  const visible = state.findings.filter(matchesFile);
  const groups = groupFindings(visible);
  const assets = state.target.assets || [];
  const listed = new Set(assets.map((asset) => asset.id));
  const extras = Object.keys(groups)
    .filter((id) => !listed.has(id))
    .map((id) => ({ id, name: id, role: "" }));
  const body = [...assets, ...extras].filter((asset) => groups[asset.id]).map((asset) => `
    <section class="asset">
      <h2>${esc(asset.name)}</h2>
      ${asset.role ? `<p class="asset-role">${esc(asset.role)}</p>` : ""}
      ${asset.id.startsWith("checkout-") ? `<p class="asset-id">${esc(asset.id)}</p>` : ""}
      ${groups[asset.id].map(findingCard).join("")}
    </section>
  `).join("");
  const openHere = visible.filter((finding) => finding.status === "open").length;
  const heading = fileFilter ? `${openHere} open in ${fileFilter}` : `${state.counts.open} open findings`;
  const empty = fileFilter && visible.length === 0
    ? `<p class="lede">No findings cite ${esc(fileFilter)}.</p>`
    : "";
  return `
    ${stageKicker("01", "Threat discovery")}
    <h1>${esc(heading)}</h1>
    <p class="lede">${esc(state.target.story)}</p>
    ${fileTabs()}
    ${empty}
    ${body}
  `;
}

function intelView() {
  const linked = new Set(state.paths.flatMap((path) => path.steps.map((step) => step.finding_id).filter(Boolean)));
  const unlinked = state.findings.filter((finding) => finding.status === "open" && !linked.has(finding.id));
  const extra = unlinked.length
    ? `<p class="unlinked">Still open, and not part of a path: ${unlinked.map((finding) => esc(finding.title)).join("; ")}. ${unlinked.map((finding) => esc(finding.detail)).join(" ")}</p>`
    : "";
  return `
    ${stageKicker("02", "Attack intelligence")}
    <h1>${state.counts.paths_open} open paths</h1>
    <p class="lede">${esc(state.picture)} A path stays open only while every condition it requires is still open.</p>
    ${state.paths.map(pathCard).join("")}
    ${extra}
  `;
}

function remediateView() {
  const proposed = state.proposed || [];
  const applied = state.applied || [];
  const showing = proposed.length ? proposed : applied;
  const heading = proposed.length ? "Hardening ready to apply" : "Last change, verified by a rescan";
  const lede = proposed.length
    ? "One action writes the workspace copy and scans it again. The finding stays on the board until that rescan comes back clean."
    : "The diffs below are what was written. Open findings after the rescan: " + state.counts.open + ".";
  const button = proposed.length
    ? `<div class="actions"><button class="primary" type="button" data-act="/api/remediate" ${busy ? "disabled" : ""}>Apply and verify</button></div>`
    : "";
  const checks = state.paths.map((path) => `
    <div class="check ${path.status === "open" ? "bad" : ""}">
      <span class="mark">${path.status === "open" ? "!" : "✓"}</span>
      <span>${esc(path.title)}</span>
    </div>
  `).join("");
  return `
    ${stageKicker("03", "Autonomous remediation")}
    <h1>${heading}</h1>
    <p class="lede">${lede}</p>
    ${button}
    ${showing.map(diffCard).join("")}
    <h2 class="section-label">Paths after rescan</h2>
    ${checks}
  `;
}

function defenseView() {
  const regressed = state.phase === "regressed";
  const openPaths = state.paths.filter((path) => path.status === "open");
  const note = regressed
    ? `Risk climbed to ${state.risk}. ${openPaths.map((path) => path.title).join("; ")}.`
    : `Risk is at 0. The workspace is still being read. ${state.target.regression_hint}`;
  const action = regressed
    ? `<button class="primary" type="button" data-act="/api/remediate" ${busy ? "disabled" : ""}>Harden again</button>`
    : `<button class="primary" type="button" data-act="/api/inject" data-stage="defense" ${busy ? "disabled" : ""}>Simulate a bad deploy</button>`;
  const max = Math.max(state.risk, ...state.events.map((event) => event.risk), 1);
  const bars = state.events.map((event) => {
    const height = Math.max(4, Math.round((event.risk / max) * 72));
    return `<div class="bar ${event.risk === 0 ? "zero" : ""}" style="height:${height}px" title="${esc(event.title)} · ${event.risk}"></div>`;
  }).join("");
  return `
    ${stageKicker("04", "Continuous defense")}
    <h1>${regressed ? "A path came back" : "Watching the workspace"}</h1>
    <div class="watch ${regressed ? "regressed" : ""}">
      <div class="pulse" aria-hidden="true"></div>
      <p data-checked>${state.last_checked ? `Last read ${esc(clock(state.last_checked))}` : "Waiting for the next read"}</p>
    </div>
    <p class="lede">${esc(note)}</p>
    <div class="spark" aria-hidden="true">${bars}</div>
    <div class="actions">${action}</div>
    ${openPaths.map(pathCard).join("")}
  `;
}

function driftNeedsScan() {
  if (state?.target && !state.target.drift) return harborDriftView();
  const disabled = busy || !state ? "disabled" : "";
  return `
    ${stageKicker("05", "Runtime drift")}
    <h1>Scan Northwind Checkout first.</h1>
    <p class="lede">Runtime drift compares the running checkout with its files. Scan Northwind Checkout, then this stage can start it in the sandbox.</p>
    <div class="actions">
      <button class="primary" type="button" data-act="/api/scan" data-stage="drift" ${disabled}>Scan Northwind Checkout</button>
    </div>
  `;
}

function harborDriftView() {
  return `
    ${stageKicker("05", "Runtime drift")}
    <h1>This audit is for Northwind Checkout.</h1>
    <p class="lede">${esc(state.target.drift_intro)}</p>
    <div class="actions">
      <button class="primary" type="button" data-demo="northwind">Open Northwind Checkout</button>
    </div>
  `;
}

function driftView() {
  if (!state.target.drift) return harborDriftView();
  const report = state.drift;
  const buttonLabel = pending === "/api/audit" ? "Starting the sandbox…" : "Audit in the sandbox";
  const button = `<div class="actions"><button class="primary" type="button" data-act="/api/audit" data-stage="drift" ${busy ? "disabled" : ""}>${buttonLabel}</button></div>`;
  if (!report) {
    return `
      ${stageKicker("05", "Runtime drift")}
      <h1>Compare the files with the running checkout.</h1>
      <p class="lede">${esc(state.target.drift_intro)}</p>
      ${button}
      <div class="controls">
        <span>No host ports</span>
        <span>Privileged mode off</span>
        <span>No egress</span>
        <span>Removed after the snapshot</span>
      </div>
    `;
  }
  const rows = (report.rows || []).map((row) => `
    <tr class="${esc(row.state)}">
      <td>${esc(row.service)}</td>
      <td>${esc(row.field)}</td>
      <td>${esc(row.baseline)}</td>
      <td>${esc(row.observed)}</td>
    </tr>
  `).join("");
  const sandbox = report.sandbox || {};
  const controls = [
    ["Host ports", sandbox.host_ports ? "published" : "none"],
    ["Privileged", sandbox.privileged ? "on" : "off"],
    ["Egress", sandbox.egress ? "open" : "blocked"],
    ["Containers", sandbox.removed ? "removed" : "still present"],
  ].map(([label, value]) => `<span>${esc(label)}: ${esc(value)}</span>`).join("");
  const headline = report.headline || report.title || "Runtime drift";
  const verdict = report.verdict || report.summary || "";
  const why = report.why || "";
  const sentences = report.sentences?.length
    ? report.sentences
    : (report.findings || []).map((item) => item.detail).filter(Boolean);
  const story = sentences.length
    ? `<ol class="drift-story">${sentences.map((text) => `<li>${esc(text)}</li>`).join("")}</ol>`
    : `<p class="lede">Nothing in the snapshot disagreed with the files.</p>`;
  const againLabel = pending === "/api/audit" ? "Starting the sandbox…" : "Audit again";
  const again = `<div class="actions"><button class="ghost" type="button" data-act="/api/audit" data-stage="drift" ${busy ? "disabled" : ""}>${againLabel}</button></div>`;
  return `
    ${stageKicker("05", "Runtime drift")}
    <h1>${esc(headline)}</h1>
    <p class="lede">${esc(verdict)}</p>
    ${why ? `<p class="why">${esc(why)}</p>` : ""}
    ${story}
    <p class="sandbox-line">${esc(sandboxSentence(sandbox))}</p>
    <div class="controls">${controls}</div>
    <h2 class="section-label">Evidence from the snapshot</h2>
    <p class="lede evidence-note">Each row is the file next to what was running. Secret values stay hidden.</p>
    <table class="compare">
      <thead><tr><th>Service</th><th>Field</th><th>Files</th><th>Running</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    ${again}
  `;
}

function sandboxSentence(sandbox) {
  const ports = sandbox.host_ports ? "published host ports" : "published no host ports";
  const privileged = sandbox.privileged ? "granted privileged mode" : "did not grant privileged mode";
  const egress = sandbox.egress ? "left egress open" : "blocked egress";
  const removed = sandbox.removed ? "removed the containers" : "left the containers in place";
  return `The sandbox ${ports}, ${privileged}, ${egress}, and ${removed}.`;
}

function findingCard(finding) {
  const places = finding.locations.map((loc) => `${loc.path}:${loc.line}`).join(" · ");
  return `
    <article class="finding ${finding.status}">
      <div class="sev ${esc(finding.severity)}">${esc(finding.severity)}</div>
      <div>
        <h3>${esc(finding.title)}${finding.status === "fixed" ? ' <span class="status-fixed">fixed</span>' : ""}</h3>
        <p>${esc(finding.detail)}</p>
        <div class="meta">${esc(places)} · ${esc(finding.recommendation)}</div>
      </div>
    </article>
  `;
}

function pathCard(path) {
  const rail = path.steps.map((step, index) => {
    const node = `<span class="node ${esc(step.status)}">${esc(step.label)}</span>`;
    const arrow = index < path.steps.length - 1 ? `<span class="arrow">→</span>` : "";
    return node + arrow;
  }).join("");
  return `
    <article class="path ${esc(path.severity)} ${path.status}">
      <div class="path-head">
        <h2>${esc(path.title)}</h2>
        <span class="badge">${path.status === "open" ? esc(path.severity) : "closed"}</span>
      </div>
      <p class="summary">${esc(path.summary)}</p>
      <p class="impact">Impact: ${esc(path.impact)}</p>
      <div class="rail">${rail}</div>
    </article>
  `;
}

function diffCard(entry) {
  const lines = (entry.diff || "").split("\n").map((line) => {
    let kind = "";
    if (line.startsWith("+") && !line.startsWith("+++")) kind = "add";
    else if (line.startsWith("-") && !line.startsWith("---")) kind = "del";
    else if (line.startsWith("@@") || line.startsWith("+++") || line.startsWith("---")) kind = "meta";
    return `<div class="diff-line ${kind}">${esc(line) || " "}</div>`;
  }).join("");
  return `
    <section class="diff-card">
      <header>
        <h2>${esc(entry.path)}</h2>
        <p>${esc(entry.summary)}</p>
      </header>
      <pre class="diff">${lines}</pre>
    </section>
  `;
}

function fileTabs() {
  const files = state.files || [];
  const tabs = [
    fileTab("*", "All", state.findings.length, !fileFilter),
    ...files.map((file) => fileTab(file.path, file.path, countFor(file.path), fileFilter === file.path)),
  ];
  return `<div class="file-tabs" role="tablist" aria-label="Filter findings by file">${tabs.join("")}</div>`;
}

function fileTab(value, label, count, selected) {
  return `<button type="button" class="file-tab${selected ? " selected" : ""}" role="tab" aria-selected="${selected}" data-file="${esc(value)}">${esc(label)} <span class="file-count">${count}</span></button>`;
}

function countFor(path) {
  return state.findings.filter((finding) => finding.locations.some((loc) => loc.path === path)).length;
}

function matchesFile(finding) {
  if (!fileFilter) return true;
  return finding.locations.some((loc) => loc.path === fileFilter);
}

function groupFindings(findings) {
  const groups = {};
  for (const finding of findings) {
    (groups[finding.asset] ||= []).push(finding);
  }
  return groups;
}

function selectFile(path, focusValue) {
  fileFilter = path;
  render();
  if (!focusValue) return;
  const target = [...view.querySelectorAll("[data-file]")].find((button) => button.dataset.file === focusValue);
  target?.focus();
}

function stageKicker(index, title) {
  const name = state?.target?.name ? ` · ${esc(state.target.name)}` : "";
  return `<p class="kicker">${index} · ${title} · Demo${name}</p>`;
}

function paintSwitcher() {
  const host = document.querySelector("#demo-switch");
  if (!host || !state?.demos) return;
  host.innerHTML = state.demos.map((demo) => {
    const selected = state.target?.id === demo.id;
    return `<button type="button" class="demo-choice${selected ? " selected" : ""}" data-demo="${esc(demo.id)}" aria-pressed="${selected}" ${busy ? "disabled" : ""}>${esc(demo.name)}</button>`;
  }).join("");
  for (const button of host.querySelectorAll("[data-demo]")) {
    button.addEventListener("click", () => chooseDemo(button.dataset.demo));
  }
}

async function chooseDemo(id) {
  if (busy || !id || state?.target?.id === id) return;
  busy = true;
  pending = "demo";
  render();
  try {
    state = await api("/api/target", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    stage = "discovery";
    fileFilter = null;
    clearError();
  } catch (err) {
    showError(err);
  } finally {
    busy = false;
    pending = "";
    render();
  }
}

function bindActions() {
  for (const button of view.querySelectorAll("[data-act]")) {
    button.addEventListener("click", () => act(button.dataset.act, button.dataset.stage || null));
  }
  for (const button of view.querySelectorAll("[data-demo]")) {
    button.addEventListener("click", () => chooseDemo(button.dataset.demo));
  }
  const tabs = [...view.querySelectorAll("[data-file]")];
  tabs.forEach((button, index) => {
    button.addEventListener("click", () => {
      const choice = button.dataset.file;
      if (choice === "*" || choice === fileFilter) selectFile(null);
      else selectFile(choice);
    });
    button.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
      event.preventDefault();
      const next = event.key === "ArrowRight" ? (index + 1) % tabs.length : (index - 1 + tabs.length) % tabs.length;
      const choice = tabs[next].dataset.file;
      selectFile(choice === "*" ? null : choice, choice);
    });
  });
}

function signature(value) {
  return [
    value.phase,
    value.risk,
    value.target?.id,
    value.findings.map((finding) => finding.id + finding.status).join(","),
    value.events.length,
    value.drift?.status || "",
  ].join("|");
}

function clock(iso) {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  return new Date(iso).toLocaleTimeString();
}

function pause(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function api(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = data.detail;
    throw new Error(typeof detail === "string" ? detail : "Request failed");
  }
  return data;
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[char]);
}

function showError(err) {
  error.hidden = false;
  error.textContent = err.message || String(err);
}

function clearError() {
  error.hidden = true;
  error.textContent = "";
}
