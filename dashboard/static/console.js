"use strict";
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const el = (t, c, h) => { const e = document.createElement(t); if (c) e.className = c; if (h != null) e.innerHTML = h; return e; };
const esc = s => (s == null ? "" : String(s)).replace(/[&<>"]/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]));
const hhmmss = ts => { if (!ts) return ""; const d = new Date(ts); return isNaN(d) ? String(ts).slice(11, 19) : d.toISOString().slice(11, 19); };
const short = (s, n) => { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };
async function jget(u) { const r = await fetch(u); return r.json(); }
async function jpost(u, b) { const r = await fetch(u, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) }); return r.json(); }
function toast(m, err) { const t = $("#toast"); t.textContent = m; t.className = "toast show" + (err ? " err" : ""); setTimeout(() => t.className = "toast", 2800); }
const pctF = x => x == null ? "—" : Math.round(x * 100) + "%";
const secF = x => x == null ? "—" : x + "s";
const numF = x => x == null ? "—" : String(x);

let overviewCache = {}, incidentCache = {}, sessionsCache = [], selected = null, tab = "all", openNode = null, autoSelect = true;

/* ---------------- layout ---------------- */
const COLS = [["TRIGGER", 9.5], ["ENVIRONMENT", 26], ["INGEST", 42], ["AGENT", 58], ["CONTROL", 75], ["OUTPUT", 91]];
const ZONES = [
  { cls: "attack", label: "ATTACK ZONE · attack-net · internal, no internet", x: 1.5, w: 33, y: 13.5, h: 79 },
  { cls: "defense", label: "DEFENSE ZONE · defense-net", x: 35.5, w: 63, y: 13.5, h: 79 },
];
const NODES = [
  { id: "attacker", code: "ATK", name: "Attacker", group: "trigger", x: 9, y: 50 },
  { id: "env", code: "ENV", name: "SSH decoys", group: "environment", x: 25.5, y: 28 },
  { id: "mcp", code: "MCP", name: "Company MCP", group: "environment", x: 25.5, y: 52 },
  { id: "rag", code: "RAG", name: "RAG + Canary", group: "environment", x: 25.5, y: 76 },
  { id: "collector", code: "COL", name: "Collector", group: "ingest", x: 42, y: 40 },
  { id: "store", code: "DB", name: "Event Store", group: "ingest", x: 42, y: 62 },
  { id: "guard", code: "GUARD", name: "Inj. guard", group: "agent", x: 58, y: 30 },
  { id: "mirage", code: "MIRAGE", name: "Mirage brain", group: "agent", x: 58, y: 58, hero: true },
  { id: "control", code: "CTL", name: "mirage-control", group: "control", x: 75, y: 35 },
  { id: "approvals", code: "HITL", name: "Approvals", group: "control", x: 75, y: 66 },
  { id: "deception", code: "DEC", name: "Deception", group: "output", x: 91, y: 27 },
  { id: "exports", code: "OUT", name: "Exports", group: "output", x: 91, y: 52 },
  { id: "eval", code: "EVAL", name: "Metrics", group: "output", x: 91, y: 77 },
];
const EDGES = [
  ["attacker", "env", "flow", "SSH commands"],
  ["attacker", "mcp", "alert", "tool calls"], ["attacker", "rag", "alert", "retrievals"],
  ["env", "collector", "flow", "logs (read-only)"],
  ["mcp", "collector", "alert", "trap-logs"], ["rag", "collector", "alert", ""],
  ["collector", "store", "flow", "events"], ["collector", "guard", "alert", "untrusted_data only"],
  ["store", "mirage", "flow", "batch · 10 ev / 30 s"], ["guard", "mirage", "flow", "wrapped"],
  ["mirage", "control", "flow", "MCP tool call"],
  ["control", "approvals", "human", "approval request"], ["approvals", "control", "human", "decision"],
  ["control", "deception", "flow", "executed write"], ["control", "exports", "flow", "alerts / IOCs"],
  ["exports", "eval", "idle", "runs"], ["deception", "env", "feedback", "new decoys & wiki pages"],
];
const nodeEls = {};

function buildStatic() {
  const z = $("#zones"); z.innerHTML = "";
  ZONES.forEach(zo => {
    const d = el("div", "zone " + zo.cls, `<div class="zlabel">${esc(zo.label)}</div>`);
    d.style.cssText = `left:${zo.x}%;top:${zo.y}%;width:${zo.w}%;height:${zo.h}%`;
    z.appendChild(d);
  });
  const cl = $("#collabels"); cl.innerHTML = "";
  COLS.forEach(([label, x]) => { const d = el("div", "collabel", label); d.style.cssText = `left:${x}%;top:18%`; cl.appendChild(d); });
  const box = $("#nodes"); box.innerHTML = "";
  NODES.forEach(n => {
    const d = el("div", "node" + (n.hero ? " hero" : ""));
    d.style.left = n.x + "%"; d.style.top = n.y + "%";
    d.innerHTML = `<div class="nhead"><div class="ic">${n.code}</div><div class="nm">${esc(n.name)}</div><div class="sd"></div></div><div class="body"></div>`;
    d.onclick = () => openNodeDetail(n.id);
    box.appendChild(d); nodeEls[n.id] = d;
  });
}

/* ---------------- per-node data ---------------- */
function nodeData(n, o, inc) {
  const c = o.components || {}, m = o.metrics || {}, det = o.detection || {}, env = o.environment || {}, run = o.run || {}, p = inc.profile || {};
  const running = run.running, R = id => c[id] || {};
  const pct = x => x != null ? Math.round(x * 100) + "%" : "0%";
  switch (n.id) {
    case "attacker": {
      const plan = inc.attack_plan;
      return { dot: running ? "hot" : (inc.timeline && inc.timeline.length ? "warn" : ""), hot: running,
        rows: [["Status", running ? "cmd " + (R("attacker").commands || 0) : (inc.timeline && inc.timeline.length ? "captured" : "idle")],
          ["LLM", "Claude Haiku", 1]],
        tags: plan ? plan.vectors.slice(0, 3).map(v => [v, "red"]) : [["idle", "gray"]] };
    }
    case "llm_gateway": return { dot: "ok",
      rows: [["Route", "→ Bedrock"], ["Calls", (R("llm_gateway").calls || 0) + " · " + (R("llm_gateway").refused || 0) + " refused"]],
      tags: [["allowlist", "gray"]] };
    case "env": {
      const touched = (env.hosts || []).some(h => h.touched);
      return { dot: touched ? "hot" : "ok", active: !touched,
        hostrows: (env.hosts || []).map(h => [h.hostname, h.touched ? ["hit", "red"] : h.closed ? ["closed", "gray"] : ["armed", ""]]),
        tags: [[`${(env.hosts || []).length}h · ${R("deception").planted || 0} decoys`, "amber"]] };
    }
    case "wiki": return { dot: "ok", active: true,
      rows: [["Pages", R("wiki").pages || 0], ["Requests", R("wiki").touched || 0]],
      tags: [[`${R("wiki").touched || 0} touched`, "amber"]] };
    case "mcp": return { dot: R("mcp").decoy_calls ? "hot" : "ok", active: !R("mcp").decoy_calls,
      rows: [["Type", "real + decoy"], ["Calls", (R("mcp").calls || 0) + " · " + (R("mcp").decoy_calls || 0) + " decoy"]],
      tags: [["ASI02", "red"]] };
    case "rag": return { dot: (R("rag").doc_retrieval || R("rag").canary) ? "hot" : "ok", active: !(R("rag").doc_retrieval || R("rag").canary),
      rows: [["Docs", R("rag").honey_docs || 0], ["Canary", R("rag").canary || 0]],
      tags: [["ASI03", "red"], ["ASI06", "red"]] };
    case "collector": return { dot: running ? "run" : "ok",
      rows: [["Type", "log → event"], ["Events", R("collector").events || 0]],
      tags: [[`${R("collector").tagged_pct || 0}% tagged`, ""]] };
    case "store": return { dot: "ok",
      rows: [["Store", "MongoDB"], ["Events", m.events || 0]],
      tags: [[`${m.sessions || 0} sessions`, ""]] };
    case "guard": return { dot: R("guard").flagged ? "hot" : "ok",
      rows: [["Scanned", R("guard").scanned || 0], ["Flagged", R("guard").flagged || 0]],
      tags: [["ASI01", "red"]] };
    case "mirage": {
      const conf = p.confidence != null ? p.confidence.toFixed(2) : "—";
      return { dot: running ? "run" : (p.actor ? "ok" : ""), analysing: running,
        rows: [["Status", running ? "planning" : (p.actor ? "analysed" : "ready")],
          ["LLM", (o.learning||{}).defender_model || "Claude Sonnet", 1],
          ["Profile", p.actor ? short(p.actor, 14) : "—"], ["Conf.", conf]],
        tags: [["engaged", ""]] };
    }
    case "evidence": return { dot: "ok",
      rows: [["Type", "code, not LLM"], ["Verified", (R("evidence").verified || 0) + "/" + ((R("evidence").total) || 0)]],
      tags: [[`grounded ${pct(det.grounding_rate)}`, ""]] };
    case "control": return { dot: R("control").pending ? "warn" : "ok",
      rows: [["Type", "MCP tools"], ["Calls", (R("control").exec || 0) + " ok · " + (R("control").blocked || 0) + " blk"]],
      tags: R("control").blocked ? [[R("control").blocked + " blocked", "red"]] : [["allow", "gray"]] };
    case "approvals": return { dot: R("approvals").pending ? "warn" : "ok",
      rows: [["Pending", R("approvals").pending || 0], ["History", (R("approvals").approved || 0) + " ok · " + (R("approvals").rejected || 0) + " rej", 1]],
      tags: R("approvals").pending ? [[R("approvals").pending + " pending", "amber"]] : [["clear", ""]] };
    case "deception": return { dot: R("deception").touched ? "hot" : "ok",
      rows: [["Planted", R("deception").planted || 0], ["Touched", R("deception").touched || 0]],
      tags: [[`${pct(det.engagement_rate)} eng`, ""]] };
    case "exports": return { dot: (m.alerts || 0) ? "ok" : "",
      rows: [["Alerts", R("exports").alerts || 0], ["IOCs", R("exports").iocs || 0]],
      tags: [["ECS · SIEM", "gray"]] };
    case "eval": return { dot: "ok",
      rows: [["Type", "static vs agent"], ["Runs", R("eval").runs || 0]],
      tags: [["results →", ""]] };
  }
  return { rows: [] };
}

function updateNodes() {
  const o = overviewCache, inc = incidentCache;
  NODES.forEach(n => {
    const d = nodeData(n, o, inc), e = nodeEls[n.id]; if (!e) return;
    e.querySelector(".sd").className = "sd " + (d.dot || "");
    e.classList.toggle("hot", !!d.hot);
    e.classList.toggle("active", !!d.active && !d.hot);
    e.classList.toggle("analysing", !!d.analysing);
    e.classList.toggle("dimmed", tab !== "all" && n.group !== tab);
    let h = "";
    (d.hostrows || []).forEach(([host, st]) => { h += `<div class="r host"><span>${esc(host)}</span><span class="pill ${st[1]}">${esc(st[0])}</span></div>`; });
    if (d.hostrows && d.hostrows.length) h = `<div class="rows">${h}</div>`;
    h += `<div class="rows">${(d.rows || []).map(([k, v, meta]) => `<div class="r"><span class="k">${esc(k)}</span><span class="v ${meta ? "meta" : ""}">${esc(v)}</span></div>`).join("")}</div>`;
    if (d.tags && d.tags.length) h += `<div class="tags">${d.tags.map(([t, cls]) => `<span class="pill ${cls || ""}">${esc(t)}</span>`).join("")}</div>`;
    if (d.foot) h += `<div class="foot">${esc(d.foot)}</div>`;
    e.querySelector(".body").innerHTML = h;
  });
  layoutEdges();
}

/* ---------------- edges ---------------- */
function center(id) {
  const c = $("#canvas").getBoundingClientRect(), r = nodeEls[id].getBoundingClientRect();
  return { x: r.left + r.width / 2 - c.left, y: r.top + r.height / 2 - c.top, w: r.width, h: r.height };
}
function layoutEdges() {
  const svg = $("#edges"); [...svg.querySelectorAll("path")].forEach(p => p.remove());
  const lbox = $("#edgelabels"); lbox.innerHTML = "";
  const H = $("#canvas").getBoundingClientRect().height;
  EDGES.forEach(([a, b, kind, label]) => {
    if (!nodeEls[a] || !nodeEls[b]) return;
    const p1 = center(a), p2 = center(b), dx = p2.x - p1.x, dy = p2.y - p1.y;
    let d, lx = (p1.x + p2.x) / 2, ly = (p1.y + p2.y) / 2;
    if (kind === "feedback") {
      const by = H * 0.92;
      d = `M${p1.x} ${p1.y + p1.h / 2} C ${p1.x} ${by}, ${p2.x} ${by}, ${p2.x} ${p2.y + p2.h / 2}`;
      lx = (p1.x + p2.x) / 2; ly = by;
    } else if (Math.abs(dx) >= Math.abs(dy)) {
      d = `M${p1.x} ${p1.y} C ${p1.x + dx * .5} ${p1.y}, ${p2.x - dx * .5} ${p2.y}, ${p2.x} ${p2.y}`;
    } else {
      d = `M${p1.x} ${p1.y} C ${p1.x} ${p1.y + dy * .5}, ${p2.x} ${p2.y - dy * .5}, ${p2.x} ${p2.y}`;
    }
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", d);
    path.setAttribute("class", kind + ((a === "collector" && b === "store") ? " main" : ""));  // collector -> MongoDB, emphasised
    svg.appendChild(path);
    if (label) {
      const e = el("div", "edgelabel " + kind, esc(label));
      e.style.cssText = `left:${lx}px;top:${ly}px`;
      lbox.appendChild(e);
    }
  });
}

/* ---------------- node detail ---------------- */
const DESC = {
  llm_gateway: "The only egress to Bedrock. Enforces a per-caller token, a model allowlist and a max_tokens cap, and logs every call.",
  wiki: "A fake internal wiki Mirage can add pages to as breadcrumbs; links only ever point at world-model hosts.",
  mcp: "The company MCP tool server (real stdio transport). Real tools plus decoys; a decoy call is an ASI02 trap_hit.",
  rag: "Retrieval over a Chroma vector store with Titan embeddings. Pulling a restricted honey-doc is the ASI06 signal; canary values are ASI03.",
  collector: "Tails the Cowrie and trap logs read-only, normalises each line into an event and maps it to an ATT&CK technique.",
  guard: "Wraps every untrusted input and scans it for prompt injection. It can flag but can never mark a session benign (ASI01).",
  evidence: "Re-checks each of Mirage's claims against the raw events in code (not an LLM) and reports grounding / hallucination.",
  eval: "The static-vs-agent experiment harness; opens the results report.",
};
function openNodeDetail(id) {
  if (id === "control" || id === "approvals") return openApprovalsModal();
  openNode = id; $("#drawer").classList.add("open"); renderDrawer();
}
function closeDrawer() { openNode = null; $("#drawer").classList.remove("open"); }
$("#drawerClose").onclick = closeDrawer;

function evRow(e) {
  const crit = e.severity === "crit" || ["canary_use", "egress", "injection_attempt"].includes(e.event_type);
  const tags = [e.technique ? `<span class="tag att">${esc(e.technique)}</span>` : "", e.owasp ? `<span class="tag owasp">${esc(e.owasp)}</span>` : ""].join("");
  return `<div class="ev ${crit ? "crit" : ""}"><div class="eh"><span class="ety">${esc(e.event_type)}</span><span class="ehost">${esc(e.host || "")}</span></div><div class="ec">${esc(e.content || "")}</div>${tags}</div>`;
}
function summaryHtml(s) {
  if (!s || !s.claims || !s.claims.length) return "";
  const icon = { verified: "ok", weak: "~", unsupported: "x" }, col = { verified: "var(--accent)", weak: "var(--amber)", unsupported: "var(--red)" };
  const rows = s.claims.map(c => `<div class="claim"><span class="ci" style="color:${col[c.check] || "var(--muted)"}">[${icon[c.check] || "·"}]</span><span>${esc(c.text)}</span></div>`).join("");
  const h = Math.round((s.hallucination_rate || 0) * 100), g = Math.round((s.grounding_rate || 0) * 100);
  return `<div class="sec">grounded analyst summary</div>${rows}<div class="gstat"><span class="chipm ok">grounded <b>${g}%</b></span><span class="chipm ${h ? "hot" : ""}">hallucination <b>${h}%</b></span></div>`;
}
function genericDrawer(id, o, inc) {
  const d = nodeData(NODES.find(n => n.id === id), o, inc);
  const rows = (d.rows || []).map(([k, v]) => `<span class="k">${esc(k)}</span><span class="v">${esc(v)}</span>`).join("");
  return `<div class="desc">${esc(DESC[id] || "")}</div><div class="kv">${rows}</div>`;
}
function renderDrawer() {
  if (!openNode) return;
  const o = overviewCache, inc = incidentCache, body = $("#drawerBody");
  const node = NODES.find(n => n.id === openNode);
  $("#dtitle").textContent = node ? node.name : openNode;
  const env = o.environment || {}, m = o.metrics || {}, p = inc.profile || {}, det = o.detection || {};
  if (openNode === "attacker") {
    const atk = (inc.story || []).filter(b => b.side === "attacker"), plan = inc.attack_plan;
    body.innerHTML = `<div class="obj">${esc(plan ? plan.narrative : "no active attack")}</div>
      ${plan ? `<div class="gstat">${plan.vectors.map(v => `<span class="tag owasp">${esc(v)}</span>`).join("")}</div>` : ""}
      <div class="kv"><span class="k">agent</span><span class="v">red-team (Bedrock Claude Haiku)</span><span class="k">events</span><span class="v">${(inc.timeline || []).length}</span><span class="k">reached</span><span class="v">${esc(inc.current_phase || "—")}</span></div>
      <div class="sec">attacker moves</div>${atk.map(evRow).join("") || '<div class="empty">no activity yet</div>'}`;
  } else if (openNode === "mirage") {
    const conf = p.confidence != null ? Math.round(p.confidence * 100) : 0;
    const preds = (inc.predicted_next || []).map(x => `<span class="pred"><b>${esc(x.technique)}</b> <span class="p">${Math.round((x.p || 0) * 100)}%</span></span>`).join("") || '<span class="dim">—</span>';
    const decoys = (inc.decoys || []).map(d => `<div class="dcard">${d.touched ? '<span class="tt">touched</span>' : ""}<div class="p">${esc(d.host)}:${esc(d.path)}</div><div class="r">${esc(d.reason)}</div></div>`).join("") || '<div class="empty">no decoys planted</div>';
    body.innerHTML = `<span class="badge ${esc(p.actor || "")}">${esc(p.actor || "unknown")}</span>${inc.injection_detected ? '<span class="badge" style="color:var(--red);border-color:var(--red-line)">injection</span>' : ""}
      <div class="obj">${esc(p.objective || inc.goal || "awaiting an attack")}</div><div class="conf"><i style="width:${conf}%"></i></div>
      <div class="kv"><span class="k">agent</span><span class="v">Mirage (Bedrock ${esc((overviewCache.learning||{}).defender_model||"Claude Sonnet")})</span><span class="k">confidence</span><span class="v">${conf}%</span></div>
      <div class="sec">detection quality</div><div class="gstat"><span class="chipm ok">F1 <b>${numF(det.f1_score)}</b></span><span class="chipm">MTTD <b>${secF(det.mttd_s)}</b></span><span class="chipm">MTTA <b>${secF(det.mtta_s)}</b></span><span class="chipm ok">trap <b>${pctF(det.trap_activation_rate)}</b></span></div>
      ${(inc.memory_cases && inc.memory_cases.length) ? `<div class="sec">learned from ${inc.memory_cases.length} past case${inc.memory_cases.length > 1 ? "s" : ""}</div><div class="gstat">${inc.memory_cases.map(c => `<span class="tag">case ${esc(String(c).split("#").pop())}</span>`).join("")}</div>` : ""}
      <div class="sec">predicted next</div><div class="preds">${preds}</div>${summaryHtml(inc.summary)}
      <div class="sec">decoys planted</div>${decoys}`;
  } else if (openNode === "exports") {
    body.innerHTML = `<div class="kv"><span class="k">alerts</span><span class="v">${m.alerts || 0}</span><span class="k">injection</span><span class="v">${m.injection_alerts || 0}</span></div>
      <div class="sec">generate</div><div class="toolgrid"><button class="btn sm" data-x="export">SIEM export</button><button class="btn sm" data-x="report">Incident report</button><button class="btn sm" data-x="nis2">NIS2 draft</button></div>
      <div class="sec">defender actions</div>${(inc.actions || []).map(a => `<div class="dcard"><div class="p">${esc(a.tool)} · ${esc(a.status)}</div><div class="r">${esc(a.reason || "")}</div></div>`).join("") || '<div class="empty">no actions yet</div>'}`;
    body.querySelectorAll("[data-x]").forEach(b => b.onclick = () => toolbarAction(b.dataset.x));
  } else if (openNode === "store") {
    body.innerHTML = `<div class="kv"><span class="k">events</span><span class="v">${m.events || 0}</span><span class="k">sessions</span><span class="v">${m.sessions || 0}</span><span class="k">techniques</span><span class="v">${m.techniques || 0}</span><span class="k">canary uses</span><span class="v">${m.canary_uses || 0}</span></div>
      <div class="sec">recent events</div>${(inc.timeline || []).slice(-14).reverse().map(evRow).join("") || '<div class="empty">no events</div>'}`;
  } else if (openNode === "env") {
    const hosts = (env.hosts || []).map(h => `<div class="dcard"><div class="p">${esc(h.hostname)} <span class="dim">${esc(h.role || "")}</span></div><div class="r">${h.touched ? "under attack" : h.closed ? "closed" : "armed"}</div></div>`).join("") || '<div class="empty">no environment</div>';
    body.innerHTML = `<div class="kv"><span class="k">company</span><span class="v">${esc(env.company || "—")}</span><span class="k">sector</span><span class="v">${esc(env.sector || "—")}</span></div><div class="sec">decoy hosts (Cowrie format)</div>${hosts}`;
  } else if (openNode === "deception") {
    const decoys = (inc.decoys || []).map(d => `<div class="dcard">${d.touched ? '<span class="tt">touched</span>' : ""}<div class="p">${esc(d.host)}:${esc(d.path)}</div><div class="r">${esc(d.reason)}</div></div>`).join("") || '<div class="empty">no decoys planted yet</div>';
    body.innerHTML = `<div class="desc">Breadcrumb files, wiki pages and decoy services Mirage writes back into the environment to keep the attacker engaged.</div><div class="sec">decoys</div>${decoys}`;
  } else {
    body.innerHTML = genericDrawer(openNode, o, inc);
  }
}

/* ---------------- approvals popup ---------------- */
async function openApprovalsModal() { $("#modalWrap").classList.add("open"); await renderApprovalsModal(); }
function closeModal() { $("#modalWrap").classList.remove("open"); }
$("#modalClose").onclick = closeModal;
$("#modalWrap").onclick = e => { if (e.target === $("#modalWrap")) closeModal(); };
async function renderApprovalsModal() {
  const approvals = await jget("/api/approvals").catch(() => []);
  const body = $("#modalBody");
  $("#modalTitle").textContent = `Pending approvals (${approvals.length})`;
  body.innerHTML = "";
  if (!approvals.length) { body.innerHTML = '<div class="empty">no actions awaiting your approval</div>'; return; }
  approvals.forEach(a => {
    const c = el("div", "acell");
    c.innerHTML = `<div class="atool">${esc(a.tool)} <span class="tag owasp">${esc(a.policy || "agent")}</span></div><div class="ar">${esc(a.reason || "")}</div><div class="ap">${esc(JSON.stringify(a.params || {}))}</div>`;
    const acts = el("div", "acts");
    const ok = el("button", "btn glow sm", "Approve"), no = el("button", "btn sm", "Reject");
    ok.onclick = async () => { const r = await jpost("/api/approve", { action_id: a.action_id, decision: "approve" }); if (r.ok) { toast("approved: " + a.tool); c.remove(); } else toast(r.error, true); renderApprovalsModal(); refreshTop(); };
    no.onclick = async () => { const reason = prompt("Reason to reject " + a.tool + "?"); if (!reason) return; const r = await jpost("/api/approve", { action_id: a.action_id, decision: "reject", reason }); if (r.ok) { toast("rejected"); c.remove(); } else toast(r.error, true); renderApprovalsModal(); refreshTop(); };
    acts.append(ok, no); c.appendChild(acts); body.appendChild(c);
  });
}

/* ---------------- metrics bar ---------------- */
const METRICS = [
  ["f1", "F1", o => numF((o.detection || {}).f1_score), "ok"],
  ["mttd", "MTTD", o => secF((o.detection || {}).mttd_s)],
  ["mtta", "MTTA", o => secF((o.detection || {}).mtta_s)],
  ["trap", "Trap activation", o => pctF((o.detection || {}).trap_activation_rate), "ok"],
  ["eng", "Engagement", o => pctF((o.detection || {}).engagement_rate), "ok"],
  ["grounded", "Grounded", o => pctF((o.detection || {}).grounding_rate), "ok"],
  ["halluc", "Hallucination", o => pctF((o.detection || {}).hallucination_rate), "halluc"],
  ["inj", "Injection caught", o => { const d = o.detection || {}; return (d.injection_caught != null ? d.injection_caught : 0) + "/" + (d.injection_total != null ? d.injection_total : 0); }, "ok"],
  ["blocked", "Blocked calls", o => numF((o.components || {}).control ? o.components.control.blocked : 0), "hot"],
  ["pending", "Pending", o => numF((o.metrics || {}).pending_approvals), "warn"],
];
function renderMetricsBar() {
  const box = $("#metricsbar"), o = overviewCache;
  box.innerHTML = "";
  METRICS.forEach(([k, label, fn, kind]) => {
    const v = fn(o);
    let cls = "mc";
    if (kind === "ok" && v !== "—" && v !== "0%" && v !== "0" && v !== "0/0") cls += " ok";
    if (kind === "hot" && v !== "0" && v !== "—") cls += " hot";
    if (kind === "warn" && v !== "0" && v !== "—") cls += " warn";
    if (kind === "halluc") cls += (v !== "0%" && v !== "—") ? " hot" : " ok";
    box.appendChild(el("span", cls, `<span class="k">${label}</span><b>${v}</b>`));
  });
}

/* ---------------- scroll-down analytics ---------------- */
function stat(v, k, sub, kind) {
  return `<div class="stat ${kind || ""}"><div class="sv">${v}</div><div class="sk">${k}</div>${sub ? `<div class="ss">${sub}</div>` : ""}</div>`;
}
function gauge(k, frac, label, hot) {
  const p = frac == null ? 0 : Math.round(Math.max(0, Math.min(1, frac)) * 100);
  return `<div class="gauge ${hot ? "hot" : ""}"><div class="gl"><span class="gk">${k}</span><span class="gv">${label}</span></div><div class="gb"><i style="width:${p}%"></i></div></div>`;
}
/* ---- self-playing learning animation: draws from zero and climbs, every page load ---- */
let learnSeries = null, learnStart = 0, learnDur = 13000, learnRAF = null, learnLastLen = -1;
const lerp = (a, b, f, k) => (a[k] || 0) + ((b[k] || 0) - (a[k] || 0)) * f;
function prepSeries(history) {
  const maxC = Math.max(1, ...history.map(p => p.cases_used || 0));
  const norm = history.map(p => ({ ...p, _cases: (p.cases_used || 0) / maxC }));
  learnSeries = [{ run: 0, _cases: 0, cases_used: 0, learned: 0, knowledge_coverage: 0 }, ...norm];
}
function startLearnAnim(history) {
  prepSeries(history);
  learnStart = performance.now();
  if (!learnRAF) learnRAF = requestAnimationFrame(learnTick);
}
// Catmull-Rom -> cubic bezier: a smooth curve through the points (not straight segments)
function smoothPath(pts) {
  if (pts.length < 2) return pts.length ? `M${pts[0][0]} ${pts[0][1]}` : "";
  let d = `M${pts[0][0]} ${pts[0][1]}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || pts[i + 1];
    d += ` C ${p1[0] + (p2[0] - p0[0]) / 6} ${p1[1] + (p2[1] - p0[1]) / 6}, ${p2[0] - (p3[0] - p1[0]) / 6} ${p2[1] - (p3[1] - p1[1]) / 6}, ${p2[0]} ${p2[1]}`;
  }
  return d;
}
function learnTick(now) {
  if (!learnSeries) { learnRAF = null; return; }
  const p = Math.min((now - learnStart) / learnDur, 1), e = 1 - Math.pow(1 - p, 2);  // ease-out
  drawLearnFrame(e);
  learnRAF = p < 1 ? requestAnimationFrame(learnTick) : null;
}
function drawLearnFrame(e) {
  const s = learnSeries, N = s.length, L = overviewCache.learning || {};
  const pos = e * (N - 1), i0 = Math.floor(pos), i1 = Math.min(i0 + 1, N - 1), f = pos - i0;
  const cases = Math.round(lerp(s[i0], s[i1], f, "cases_used")), cov = lerp(s[i0], s[i1], f, "knowledge_coverage");
  const learned = Math.round(lerp(s[i0], s[i1], f, "learned"));
  const model = L.defender_model || "model", memtxt = L.memory_on === false ? "memory OFF" : "memory ON";
  $("#anaLearnSub").textContent = `(defender: ${model} · ${memtxt} · ${L.reviewed_cases || 0} reviewed cases · run ${Math.round(e * (L.runs || 0))}/${L.runs || 0})`;
  $("#anaLearnStats").innerHTML = [
    stat(Math.round(cov * 100) + "%", "Knowledge coverage", "of the threat library", "ok"),
    stat(learned + "/" + (L.total || 30), "Techniques learned", "cross-session memory", "ok"),
    stat(cases, "Past cases reused", "case-based reasoning", "ok"),
    stat(L.reviewed_cases || 0, "Cases in memory", "reviewed incidents", "ok"),
  ].join("");
  const Xf = idx => N <= 1 ? 0 : (idx / (N - 1)) * 100, Yf = v => 100 - (v || 0) * 100;
  const line = (key, color) => {
    const pts = [];
    for (let i = 0; i <= i0 && i < N; i++) pts.push([Xf(i), Yf(s[i][key])]);
    if (i0 < N - 1) pts.push([Xf(pos), Yf(lerp(s[i0], s[i1], f, key))]);
    return `<path d="${smoothPath(pts)}" fill="none" stroke="${color}" stroke-width="2.5" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>`;
  };
  let svg = `<svg viewBox="0 0 100 100" preserveAspectRatio="none">`;
  [0, 50, 100].forEach(g => svg += `<line x1="0" y1="${g}" x2="100" y2="${g}" class="grid" vector-effect="non-scaling-stroke"/>`);
  svg += line("knowledge_coverage", "#35d6a6") + line("_cases", "#e8d98a") + `</svg>`;
  $("#anaLearnChart").innerHTML = svg;
}
let learnData = [], learnObserver = null;
function ensureLearnObserver() {
  if (learnObserver || !$("#learnPanel")) return;
  learnObserver = new IntersectionObserver(es => es.forEach(en => {
    if (en.isIntersecting && learnData.length && !learnRAF) startLearnAnim(learnData);   // play when scrolled into view
  }), { threshold: 0.35 });
  learnObserver.observe($("#learnPanel"));
}
function panelVisible() { const el = $("#learnPanel"); if (!el) return false; const r = el.getBoundingClientRect(); return r.top < innerHeight && r.bottom > 0; }
function renderLearning() {
  const L = overviewCache.learning || {}, hist = L.history || [], run = overviewCache.run || {};
  const btn = $("#learnRun");
  if (btn) {
    if (run.learn) { btn.textContent = `building round ${run.learn.round}/${run.learn.total}…`; btn.disabled = true; }
    else { btn.textContent = "▸ run learning demo"; btn.disabled = !!run.running; }
  }
  if (!hist.length) { $("#anaLearnChart").innerHTML = '<div class="empty">click <b>run learning demo</b> to watch Mirage learn the ATT&CK matrix</div>'; $("#anaLearnSub").textContent = ""; learnLastLen = 0; return; }
  learnData = hist;
  ensureLearnObserver();
  if (run.learn) {                              // emulation running: grow the curve live (static full draw each poll)
    prepSeries(hist); drawLearnFrame(1); learnLastLen = hist.length; return;
  }
  if (hist.length !== learnLastLen) {           // finished / page load: reset to zero then animate once
    learnLastLen = hist.length;
    prepSeries(hist);
    if (!learnRAF) drawLearnFrame(0);
    if (panelVisible() && !learnRAF) startLearnAnim(hist);
  }
}
if (document.getElementById("learnReplay")) document.getElementById("learnReplay").onclick = () => { if (learnData.length) startLearnAnim(learnData); };
if (document.getElementById("learnRun")) document.getElementById("learnRun").onclick = async () => {
  const r = await jpost("/api/learn-demo");
  if (r.ok) { toast("learning demo started on a small model — watch the curve build (~2-3 min)"); $("#learnPanel").scrollIntoView({ behavior: "smooth", block: "center" }); }
  else toast(r.error === "busy" ? "already running" : (r.error || "error"), true);
};
function renderAnalytics() {
  const o = overviewCache, m = o.metrics || {};
  renderLearning();
  $("#anaRun").textContent = (o.components && o.components.eval && o.components.eval.latest_run) || "—";
  $("#anaPolicy").textContent = "policy: " + (o.active_policy || "agent");

  // scenarios defended (agent only)
  const scen = o.scenarios || [];
  const totRuns = scen.reduce((s, x) => s + x.runs, 0), defN = scen.filter(x => x.defended).length;
  $("#anaScenRuns").textContent = scen.length ? `(${defN}/${scen.length} defended · ${totRuns} runs)` : "";
  $("#anaScenarios").innerHTML = scen.map(s => `<div class="scrow">
    <div class="scl"><span class="diff ${s.difficulty}">${esc(s.difficulty)}</span><span class="scn">${esc(s.label)}</span><span class="dim">×${s.runs}</span></div>
    <div class="scmid">${[["canary", s.canary], ["trap", s.trap], ["decoys", s.decoys], ["docs", s.docs], ["exfil", s.exfil], ["ATT&CK", s.tech]].filter(x => x[1]).map(x => `<span class="scchip">${x[0]} <b>${x[1]}</b></span>`).join("") || '<span class="dim" style="font-size:10px">observed</span>'}</div>
    <div class="scend"><span class="defbadge ${s.defended ? "" : "no"}">${s.defended ? "defended" : "—"}</span></div>
  </div>`).join("") || '<div class="empty">run the workflow to populate scenarios</div>';

  // effectiveness cards
  $("#anaEffect").innerHTML = [
    stat(m.events || 0, "Events"), stat(m.sessions || 0, "Sessions"), stat(m.hosts_entered || 0, "Hosts entered"),
    stat(m.techniques || 0, "ATT&CK techniques", "distinct", "ok"),
    stat(m.decoys_planted || 0, "Decoys planted"), stat(m.decoys_touched || 0, "Decoys touched", null, m.decoys_touched ? "ok" : ""),
    stat(m.canary_uses || 0, "Canary uses", "ASI03", m.canary_uses ? "hot" : ""),
    stat(m.trap_hits || 0, "Trap hits", "ASI02", m.trap_hits ? "hot" : ""),
    stat(m.doc_retrievals || 0, "Honey-doc reads", "ASI06", m.doc_retrievals ? "hot" : ""),
    stat(m.injection_alerts || 0, "Injection alerts", null, m.injection_alerts ? "hot" : ""),
    stat(m.blocked_calls || 0, "Blocked calls", null, m.blocked_calls ? "hot" : ""),
    stat(m.pending_approvals || 0, "Pending approvals", null, m.pending_approvals ? "warn" : ""),
  ].join("");
}

/* ---------------- header + controls ---------------- */
function renderHeader(o) {
  const net = o.environment && o.environment.company ? o.environment.company + " · " + (o.environment.hosts || []).length + " hosts · attack-net isolated" : "no environment";
  $("#envName").textContent = net;
  const kb = $("#killBtn"); kb.classList.toggle("armed", o.kill_switch); kb.textContent = o.kill_switch ? "ARMED" : "KILL";
  const pend = (o.metrics || {}).pending_approvals || 0;
  $("#apCount").textContent = pend; $("#approvalsBtn").classList.toggle("has", pend > 0);
  const r = o.run || {}, rb = $("#runbar"), lb = $("#launchBtn");
  if (r.running) { rb.className = "runbar live"; rb.textContent = `auto → agent · seed ${r.seed}`; lb.disabled = true; lb.textContent = "running"; }
  else { rb.className = "runbar"; rb.textContent = r.error ? "error" : (r.last ? `done · ${r.attacker} ${r.last.commands} cmds` : "idle"); lb.disabled = false; lb.textContent = "Run Workflow"; }
}
function renderSessionSelect() {
  const sel = $("#sessionSel");
  if (document.activeElement === sel) return;
  const cur = selected;
  sel.innerHTML = sessionsCache.map(s => `<option value="${esc(s.session_id)}" ${s.session_id === cur ? "selected" : ""}>session ${esc(s.session_id.replace(/^att-/, ""))} · ${esc(s.scenario || s.actor || "")}</option>`).join("") || '<option>no sessions</option>';
}
$("#sessionSel").onchange = e => { selected = e.target.value; autoSelect = false; refreshIncident(); };
function pickSession(sessions) { sessionsCache = sessions; if (autoSelect && (!selected || !sessions.find(s => s.session_id === selected)) && sessions.length) selected = sessions[0].session_id; renderSessionSelect(); }

async function toolbarAction(a) {
  if (a === "export") { const r = await jpost("/api/export"); return r.ok ? toast(`exported ${r.alerts} alerts + queries → exports/`) : toast(r.error, true); }
  if (a === "reset") { if (!confirm("Clear attack data (keep environment)?")) return; const r = await jpost("/api/reset"); toast(r.ok ? "attack data cleared" : r.error, !r.ok); selected = null; autoSelect = true; refreshTop(); refreshIncident(); }
  if (a === "report" || a === "nis2") {
    if (!selected) return toast("run an attack first", true);
    const r = await jget("/api/report/" + encodeURIComponent(selected) + "?kind=" + (a === "nis2" ? "nis2" : "incident"));
    return r.ok ? openText(a === "nis2" ? "NIS2 draft" : "Incident report", r.markdown) : toast(r.error, true);
  }
}
function openText(title, md) {
  const w = window.open("", "_blank"); w.document.title = title; w.document.body.style.cssText = "margin:0;background:#0b0d10";
  const pre = w.document.createElement("pre");
  pre.style.cssText = "white-space:pre-wrap;font:13px ui-monospace,Consolas,monospace;color:#eaf2ec;padding:28px;max-width:860px;margin:auto;line-height:1.5";
  pre.textContent = md; w.document.body.appendChild(pre);
}
$("#launchBtn").onclick = async () => { autoSelect = true; const r = await jpost("/api/attack", { seed: +$("#atkSeed").value || 1 }); r.ok ? toast("auto attack launched") : toast(r.error, true); refreshTop(); };
$("#resetBtn").onclick = () => toolbarAction("reset");
$("#approvalsBtn").onclick = openApprovalsModal;
$("#killBtn").onclick = async () => { const r = await jpost("/api/killswitch", { on: !overviewCache.kill_switch }); toast(r.on ? "KILL SWITCH ARMED — agent frozen" : "kill switch released"); refreshTop(); };
$$("#wtabs button").forEach(b => b.onclick = () => { tab = b.dataset.g; $$("#wtabs button").forEach(x => x.classList.toggle("on", x === b)); updateNodes(); });
setInterval(() => $("#clock").textContent = new Date().toISOString().slice(11, 19) + "Z", 1000);
window.addEventListener("resize", layoutEdges);

/* ---------------- polling ---------------- */
async function refreshTop() {
  try {
    overviewCache = await jget("/api/overview"); renderHeader(overviewCache); renderMetricsBar(); renderAnalytics();
    const { sessions } = await jget("/api/sessions"); pickSession(sessions);
    updateNodes();
    if ($("#modalWrap").classList.contains("open")) renderApprovalsModal();
  } catch (e) { }
}
async function refreshIncident() {
  try {
    if (selected) incidentCache = await jget("/api/incident/" + encodeURIComponent(selected));
    updateNodes();
    if (openNode) renderDrawer();
  } catch (e) { }
}

buildStatic();
refreshTop().then(() => { refreshIncident(); setTimeout(layoutEdges, 140); });
setInterval(refreshTop, 1500);
setInterval(refreshIncident, 1500);
