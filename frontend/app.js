const state = {
  activeSessionId: null,
  authToken: null,
  authRole: "Demo Analyst",
  latestReport: null,
  ws: null,
};

const els = {
  sessionSelect: document.getElementById("sessionSelect"),
  newSessionBtn: document.getElementById("newSessionBtn"),
  closeSessionBtn: document.getElementById("closeSessionBtn"),
  verifyEvidenceBtn: document.getElementById("verifyEvidenceBtn"),
  generateReportBtn: document.getElementById("generateReportBtn"),
  rbacLoginBtn: document.getElementById("rbacLoginBtn"),
  authRoleBadge: document.getElementById("authRoleBadge"),
  kpiSessions: document.getElementById("kpiSessions"),
  kpiEvents: document.getElementById("kpiEvents"),
  kpiCanaries: document.getElementById("kpiCanaries"),
  kpiRisk: document.getElementById("kpiRisk"),
  kpiIntegrity: document.getElementById("kpiIntegrity"),
  wsStatus: document.getElementById("wsStatus"),
  terminalOutput: document.getElementById("terminalOutput"),
  terminalForm: document.getElementById("terminalForm"),
  terminalInput: document.getElementById("terminalInput"),
  terminalPrompt: document.getElementById("terminalPrompt"),
  decoyAdminForm: document.getElementById("decoyAdminForm"),
  decoyUser: document.getElementById("decoyUser"),
  decoyPass: document.getElementById("decoyPass"),
  decoyQuery: document.getElementById("decoyQuery"),
  runDecoyQueryBtn: document.getElementById("runDecoyQueryBtn"),
  decoyAdminOutput: document.getElementById("decoyAdminOutput"),
  honeyfilesList: document.getElementById("honeyfilesList"),
  aiNarrative: document.getElementById("aiNarrative"),
  aiMitre: document.getElementById("aiMitre"),
  aiRec: document.getElementById("aiRec"),
  latestRiskBadge: document.getElementById("latestRiskBadge"),
  eventsFeed: document.getElementById("eventsFeed"),
  evidenceList: document.getElementById("evidenceList"),
  vaultCount: document.getElementById("vaultCount"),
  reportModal: document.getElementById("reportModal"),
  reportContent: document.getElementById("reportContent"),
  closeReportModal: document.getElementById("closeReportModal"),
  downloadReportBtn: document.getElementById("downloadReportBtn"),
  authModal: document.getElementById("authModal"),
  closeAuthModal: document.getElementById("closeAuthModal"),
  authForm: document.getElementById("authForm"),
  authUser: document.getElementById("authUser"),
  authPass: document.getElementById("authPass"),
  authStatusMsg: document.getElementById("authStatusMsg"),
  packetDot: document.getElementById("packetDot"),
};

function appendTerminal(text, cls = "") {
  const div = document.createElement("div");
  div.className = `term-line ${cls}`;
  div.textContent = text;
  els.terminalOutput.appendChild(div);
  els.terminalOutput.scrollTop = els.terminalOutput.scrollHeight;
}

function riskClass(level) {
  const allowedLevels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const safeLevel = allowedLevels.includes(level) ? level : "LOW";
  return `risk-${safeLevel.toLowerCase()}`;
}

function makeElement(tag, className = "", text = "") {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text;
  return element;
}

async function requestJson(url, options = {}) {
  let response;
  try {
    response = await fetch(url, options);
  } catch {
    throw new Error("Connection to MirageNet failed. Check that the server is running.");
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.detail || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

function animatePacket(targetNode, isAlert) {
  const targets = {
    "virtual-server": { x: 480, y: 50 },
    "honeyfile-vault": { x: 480, y: 130 },
    "synthetic-db": { x: 480, y: 210 },
    "decoy-admin": { x: 480, y: 210 },
  };
  const dest = targets[targetNode] || targets["virtual-server"];
  els.packetDot.classList.toggle("alert", Boolean(isAlert));

  document.querySelectorAll(".topo-node").forEach((n) => n.classList.remove("node-alert"));
  if (isAlert) {
    const nodeEl = document.getElementById(`node-${targetNode === "decoy-admin" ? "synthetic-db" : targetNode}`);
    if (nodeEl) nodeEl.classList.add("node-alert");
  }

  let step = 0;
  const steps = 20;
  const timer = setInterval(() => {
    step++;
    const t = step / steps;
    if (t < 0.45) {
      const k = t / 0.45;
      els.packetDot.setAttribute("cx", String(110 + (280 - 110) * k));
      els.packetDot.setAttribute("cy", "130");
    } else {
      const k = (t - 0.45) / 0.55;
      els.packetDot.setAttribute("cx", String(280 + (dest.x - 280) * k));
      els.packetDot.setAttribute("cy", String(130 + (dest.y - 130) * k));
    }
    if (step >= steps) clearInterval(timer);
  }, 22);
}

function renderDashboard(snap) {
  if (!snap) return;

  // Sessions dropdown
  const prev = state.activeSessionId;
  els.sessionSelect.replaceChildren();
  snap.sessions.forEach((s) => {
    const opt = document.createElement("option");
    opt.value = s.session_id;
    opt.textContent = `${s.session_id} (${s.tester_label}) — Risk ${s.max_risk_score}`;
    els.sessionSelect.appendChild(opt);
  });
  if (prev && snap.sessions.some((s) => s.session_id === prev)) {
    els.sessionSelect.value = prev;
  } else if (snap.sessions.length) {
    state.activeSessionId = snap.sessions[0].session_id;
    els.sessionSelect.value = state.activeSessionId;
  } else {
    state.activeSessionId = null;
  }
  const activeSession = snap.sessions.find((s) => s.session_id === state.activeSessionId);
  const sessionActive = Boolean(activeSession && activeSession.status === "ACTIVE");
  els.terminalInput.disabled = !sessionActive;
  els.terminalForm.querySelector("button[type=submit]").disabled = !sessionActive;
  els.decoyAdminForm.querySelectorAll("input, button").forEach((control) => { control.disabled = !sessionActive; });
  els.closeSessionBtn.disabled = !sessionActive;
  document.querySelectorAll("[data-scenario]").forEach((button) => { button.disabled = !sessionActive; });
  els.terminalPrompt.textContent = sessionActive
    ? `admin@mirage:${activeSession.cwd}$`
    : "No active session$";

  // KPIs
  const activeCount = snap.sessions.filter((s) => s.status === "ACTIVE").length;
  const maxRisk = snap.sessions.reduce((acc, s) => Math.max(acc, s.max_risk_score), 0);
  els.kpiSessions.textContent = String(activeCount);
  els.kpiEvents.textContent = String(snap.events.length);
  els.kpiCanaries.textContent = String(snap.canary_triggers.length);
  els.kpiRisk.textContent = `${maxRisk} / 100`;
  els.kpiIntegrity.textContent = snap.integrity.integrity_ok
    ? `VERIFIED (${snap.integrity.verified_records})`
    : "TAMPER ALERT";

  // Honeyfiles
  els.honeyfilesList.replaceChildren(...snap.honeyfiles.map((h) => {
    const item = makeElement("div", "honey-item");
    const header = makeElement("div", "event-top");
    header.appendChild(makeElement("strong", "", h.path));

    const actions = makeElement("div");
    actions.style.display = "flex";
    actions.style.gap = "6px";
    actions.style.alignItems = "center";
    actions.appendChild(makeElement("span", `risk-badge ${riskClass(h.sensitivity)}`, `${h.canary_id} · ${h.sensitivity}`));
    const beaconButton = makeElement("button", "btn btn-sm btn-warn", "Test Beacon URL");
    beaconButton.type = "button";
    beaconButton.addEventListener("click", () => fireCanaryBeacon(h.canary_id));
    actions.appendChild(beaconButton);
    header.appendChild(actions);

    item.appendChild(header);
    item.appendChild(makeElement("div", "muted small", h.description));
    item.appendChild(makeElement("div", "mono", `SHA-256: ${h.sha256.slice(0, 28)}...`));
    return item;
  }));

  // Events & AI Panel
  if (snap.events.length) {
    const latest = snap.events[0];
    els.latestRiskBadge.textContent = `${latest.risk_level} (${latest.risk_score})`;
    els.latestRiskBadge.className = `risk-badge ${riskClass(latest.risk_level)}`;
    els.aiNarrative.textContent = latest.explanation;
    els.aiMitre.textContent = `${latest.mitre_id} — ${latest.mitre_name} (${latest.mitre_tactic})`;
    els.aiRec.textContent = latest.recommendation;
  }

  els.eventsFeed.replaceChildren(...snap.events.map((e) => {
    const item = makeElement("div", "event-item");
    const header = makeElement("div", "event-top");
    header.appendChild(makeElement("strong", "", e.category));
    header.appendChild(makeElement("span", `risk-badge ${riskClass(e.risk_level)}`, `${e.risk_level} · ${e.risk_score}`));
    item.appendChild(header);
    item.appendChild(makeElement("div", "mono", `${e.session_id} | ${e.mitre_id} | input: ${e.raw_input}`));
    if (e.canary_trigger) {
      item.appendChild(makeElement("div", "term-alert small", `CANARY: ${e.canary_trigger.message}`));
    }
    return item;
  }));

  // Evidence Vault
  const records = [...snap.evidence_records].reverse();
  els.vaultCount.textContent = `${snap.integrity.total_records} sealed`;
  els.evidenceList.replaceChildren(...records.map((r) => {
    const item = makeElement("div", "evidence-item");
    const header = makeElement("div", "event-top");
    header.appendChild(makeElement("strong", "", `${r.evidence_id} (${r.event_type})`));
    const decryptButton = makeElement("button", "btn btn-sm btn-secondary", "Decrypt");
    decryptButton.type = "button";
    decryptButton.addEventListener("click", () => decryptEvidence(r.evidence_id));
    header.appendChild(decryptButton);
    item.appendChild(header);
    item.appendChild(makeElement("div", "mono", `SHA-256: ${r.record_hash.slice(0, 32)}...`));
    item.appendChild(makeElement("div", "mono", `Sig (Ed25519): ${r.signature_b64.slice(0, 24)}...`));
    return item;
  }));
}

async function fetchInitialState() {
  const snap = await requestJson("/api/dashboard/state");
  renderDashboard(snap);
}

function connectWebSocket() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/soc`);
  state.ws = ws;
  ws.onopen = () => {
    els.wsStatus.textContent = "WebSocket Connected";
    els.wsStatus.className = "pill pill-ok";
  };
  ws.onmessage = (msg) => {
    let data;
    try {
      data = JSON.parse(msg.data);
    } catch {
      return;
    }
    if (data.event) {
      animatePacket(data.event.target_node, data.event.risk_score >= 65 || Boolean(data.event.canary_trigger));
    }
    if (data.state) {
      renderDashboard(data.state);
    }
  };
  ws.onerror = () => {
    els.wsStatus.textContent = "WebSocket interrupted";
    els.wsStatus.className = "pill";
  };
  ws.onclose = () => {
    els.wsStatus.textContent = "Reconnecting...";
    els.wsStatus.className = "pill";
    setTimeout(connectWebSocket, 2000);
  };
}

// Tabs
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.add("active");
  });
});

// Terminal execution
els.terminalForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const cmd = els.terminalInput.value.trim();
  if (!cmd || !state.activeSessionId) return;
  els.terminalInput.value = "";
  appendTerminal(`${els.terminalPrompt.textContent} ${cmd}`, "term-cmd");

  try {
    const data = await requestJson(`/api/sessions/${state.activeSessionId}/terminal`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: cmd }),
    });
    if (data.terminal?.output) appendTerminal(data.terminal.output);
    if (data.terminal?.cwd) els.terminalPrompt.textContent = `admin@mirage:${data.terminal.cwd}$`;
    if (data.terminal?.canary_trigger) {
      appendTerminal(`[CANARY ALERT] ${data.terminal.canary_trigger.message}`, "term-alert");
    }
  } catch (error) {
    appendTerminal(error.message, "term-alert");
  }
});

// Decoy Admin
async function sendDecoyAdmin(queryMode = false) {
  if (!state.activeSessionId) return;
  const payload = queryMode
    ? { username: els.decoyUser.value, password: els.decoyPass.value, query: els.decoyQuery.value || "SELECT * FROM api_tokens" }
    : { username: els.decoyUser.value, password: els.decoyPass.value, query: "" };

  try {
    const data = await requestJson(`/api/sessions/${state.activeSessionId}/decoy-admin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    els.decoyAdminOutput.textContent = JSON.stringify(data.admin_result, null, 2);
  } catch (error) {
    els.decoyAdminOutput.textContent = error.message;
  }
}

els.decoyAdminForm.addEventListener("submit", (e) => {
  e.preventDefault();
  sendDecoyAdmin(false);
});
els.runDecoyQueryBtn.addEventListener("click", () => sendDecoyAdmin(true));

// Guided Scenarios
document.querySelectorAll("[data-scenario]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    if (!state.activeSessionId) return;
    const scenarioId = btn.dataset.scenario;
    appendTerminal(`--- Running Guided Scenario: ${scenarioId} ---`, "term-muted");
    try {
      const data = await requestJson(`/api/sessions/${state.activeSessionId}/scenario`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario_id: scenarioId }),
      });
      (data.results || []).forEach((r) => {
        if (r.command) appendTerminal(`$ ${r.command}`, "term-cmd");
        if (r.output) appendTerminal(r.output);
      });
    } catch (error) {
      appendTerminal(error.message, "term-alert");
    }
  });
});

// New Session
els.newSessionBtn.addEventListener("click", async () => {
  try {
    const data = await requestJson("/api/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tester_label: "Interactive-Tester", source_ip: "198.51.100.77" }),
    });
    state.activeSessionId = data.session_id;
    await fetchInitialState();
  } catch (error) {
    appendTerminal(error.message, "term-alert");
  }
});

els.closeSessionBtn.addEventListener("click", async () => {
  if (!state.activeSessionId) return;
  try {
    await requestJson(`/api/sessions/${state.activeSessionId}/close`, { method: "POST" });
    await fetchInitialState();
  } catch (error) {
    appendTerminal(error.message, "term-alert");
  }
});

els.sessionSelect.addEventListener("change", () => {
  state.activeSessionId = els.sessionSelect.value;
  fetchInitialState().catch((error) => appendTerminal(error.message, "term-alert"));
});

// Fire active Canary Tracking Beacon URL
async function fireCanaryBeacon(canaryId) {
  const sid = state.activeSessionId || "";
  try {
    await requestJson(`/api/canary/beacon/${canaryId}?session_id=${encodeURIComponent(sid)}`);
  } catch (error) {
    appendTerminal(error.message, "term-alert");
  }
}

// Verify Evidence
els.verifyEvidenceBtn.addEventListener("click", async () => {
  try {
    const data = await requestJson("/api/evidence/verify");
    alert(`Evidence Chain Verification:\nTotal Records: ${data.total_records}\nVerified: ${data.verified_records}\nIntegrity OK: ${data.integrity_ok}`);
  } catch (error) {
    alert(error.message);
  }
});

// Decrypt Evidence (RBAC protected)
async function decryptEvidence(evidenceId) {
  const headers = state.authToken ? { "X-Auth-Token": state.authToken } : {};
  try {
    const data = await requestJson(`/api/evidence/${evidenceId}/decrypt`, { headers });
    alert(`Decrypted ${evidenceId} (by ${data.decrypted_by}):\n\n` + JSON.stringify(data.payload, null, 2));
  } catch (error) {
    alert(`${error.message}\nSign in as 'soc_admin' via SOC Auth button to decrypt.`);
    return;
  }
}

// Incident Report
els.generateReportBtn.addEventListener("click", async () => {
  if (!state.activeSessionId) return;
  try {
    const report = await requestJson(`/api/sessions/${state.activeSessionId}/report`);
    state.latestReport = report;
    els.reportContent.textContent = JSON.stringify(report, null, 2);
    els.reportModal.classList.remove("hidden");
  } catch (error) {
    alert(error.message);
  }
});
els.closeReportModal.addEventListener("click", () => els.reportModal.classList.add("hidden"));
els.downloadReportBtn.addEventListener("click", () => {
  if (!state.latestReport) return;
  const blob = new Blob([JSON.stringify(state.latestReport, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${state.latestReport.report_id}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

// RBAC Auth Modal
els.rbacLoginBtn.addEventListener("click", () => els.authModal.classList.remove("hidden"));
els.closeAuthModal.addEventListener("click", () => els.authModal.classList.add("hidden"));
els.authForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const data = await requestJson("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: els.authUser.value, password: els.authPass.value }),
    });
    state.authToken = data.token;
    state.authRole = `${data.display_name}`;
    els.authRoleBadge.textContent = state.authRole;
    els.authStatusMsg.textContent = `Signed in as ${data.display_name}`;
    els.authPass.value = "";
    setTimeout(() => els.authModal.classList.add("hidden"), 600);
  } catch (error) {
    els.authStatusMsg.textContent = error.message;
    return;
  }
});

// Boot
fetchInitialState().catch((error) => {
  els.wsStatus.textContent = error.message;
  els.wsStatus.className = "pill";
});
connectWebSocket();
