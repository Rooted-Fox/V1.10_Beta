/* Perimeter ASVP — platform frontend */

const CAT = {
  "A01:broken_access_control":          { code:"A01", label:"Broken access control" },
  "A02:security_misconfiguration":      { code:"A02", label:"Security misconfiguration" },
  "A03:software_supply_chain_failures": { code:"A03", label:"Supply chain" },
  "A04:cryptographic_failures":         { code:"A04", label:"Cryptographic failures" },
  "A05:injection":                      { code:"A05", label:"Injection" },
  "A06:insecure_design":                { code:"A06", label:"Insecure design" },
  "A07:authentication_failures":        { code:"A07", label:"Authentication failures" },
  "A08:software_data_integrity_failures": { code:"A08", label:"Integrity failures" },
  "A09:logging_alerting_failures":      { code:"A09", label:"Logging & alerting" },
  "A10:mishandling_exceptional_conditions": { code:"A10", label:"Exceptional conditions" },
};

async function api(path, opts={}) {
  const res = await fetch(`/api${path}`, { headers:{"Content-Type":"application/json"}, ...opts });
  if (!res.ok) { const b=await res.json().catch(()=>({})); throw new Error(b.detail||`Error ${res.status}`); }
  return res.status===204 ? null : res.json();
}

function esc(v){ const d=document.createElement("div"); d.textContent=v==null?"":v; return d.innerHTML; }
function showToast(msg){ const t=document.getElementById("toast"); t.textContent=msg; t.classList.add("show"); setTimeout(()=>t.classList.remove("show"),2600); }

/* ---------- tabs ---------- */
let currentTab = "dashboard";
function switchTab(name) {
  currentTab = name;
  document.querySelectorAll(".tab").forEach(t => {
    const a = t.dataset.tab===name;
    t.classList.toggle("active", a);
    t.setAttribute("aria-selected", String(a));
  });
  document.querySelectorAll(".panel").forEach(p => {
    const a = p.id===`panel-${name}`;
    p.classList.toggle("active", a);
    p.hidden = !a;
  });
  if (name==="dashboard") loadDashboard();
  if (name==="scanning") { loadPending(); loadSchedules(); }
  if (name==="findings") loadFindings();
  if (name==="remediation") loadRemediation();
  if (name==="settings") loadSettings();
}
document.querySelectorAll(".tab").forEach(t => t.addEventListener("click", ()=>switchTab(t.dataset.tab)));

/* ---------- app selector ---------- */
let selectedApp = "";
async function populateAppSelectors() {
  const apps = await api("/apps");
  ["appSelectDashboard","appFilterFindings","appFilterRemediation"].forEach(id => {
    const sel = document.getElementById(id);
    if (!sel) return;
    const cur = sel.value;
    sel.innerHTML = '<option value="">All applications</option>' +
      apps.map(a=>`<option value="${esc(a)}">${esc(a)}</option>`).join("");
    sel.value = apps.includes(cur) ? cur : "";
  });
}

document.getElementById("appSelectDashboard").addEventListener("change", e => {
  selectedApp = e.target.value;
  loadDashboard();
});

/* ---------- dashboard ---------- */
async function loadDashboard() {
  await populateAppSelectors();
  document.getElementById("appSelectDashboard").value = selectedApp;
  const qs = selectedApp ? `?app_name=${encodeURIComponent(selectedApp)}` : "";
  const [sev, cat, chains, findings] = await Promise.all([
    api(`/summary/severity${qs}`),
    api(`/summary/category${qs}`),
    api(`/chains${qs}`),
    api(`/findings${qs}`),
  ]);
  renderDashboardMetrics(sev);
  renderCategories(cat);
  renderChainsList(chains);
  renderTopFindings(findings);
  updateReportLinks();
}

function updateReportLinks() {
  const qs = selectedApp ? `?app_name=${encodeURIComponent(selectedApp)}` : "";
  document.getElementById("reportHtmlLink").href = `/api/report/html${qs}`;
  document.getElementById("reportCsvLink").href = `/api/report/csv${qs}`;
}

function renderDashboardMetrics(sev) {
  const items = [
    { label:"Critical", value:sev.critical||0, cls:"critical" },
    { label:"High",     value:sev.high||0,     cls:"high" },
    { label:"Medium",   value:sev.medium||0,   cls:"medium" },
    { label:"Low",      value:sev.low||0,       cls:"low" },
  ];
  document.getElementById("metricGrid").innerHTML = items.map(i=>`
    <div class="metric-card">
      <p class="metric-label">${i.label}</p>
      <p class="metric-value ${i.cls}">${i.value}</p>
    </div>`).join("");
}

function renderCategories(cat) {
  document.getElementById("categoryGrid").innerHTML = Object.entries(CAT).map(([k,v])=>{
    const count = cat[k]||0;
    return `<button class="category-card" data-cat="${k}" type="button">
      <div class="category-row">
        <span class="category-code">${v.code}</span>
        <span class="dot ${count>0?'critical':'info'}"></span>
      </div>
      <p class="category-name">${v.label}</p>
      <p class="category-count">${count} open</p>
    </button>`;
  }).join("");
  document.querySelectorAll(".category-card").forEach(c=>{
    c.addEventListener("click", ()=>{
      document.getElementById("categoryFilterFindings").value = c.dataset.cat;
      switchTab("findings");
    });
  });
}

function renderChainsList(chains) {
  document.getElementById("chainCount").textContent = chains.length;
  if (!chains.length) {
    document.getElementById("chainsList").innerHTML = '<p class="hint">No attack chains detected yet. Run a scan and approve AI triage to identify multi-step attack paths.</p>';
    return;
  }
  document.getElementById("chainsList").innerHTML = chains.slice(0,4).map(c=>`
    <div class="chain-card">
      <p class="chain-title">${esc(c.chain_name)}</p>
      <div class="chain-meta">
        <span>Risk: <strong>${c.risk_score}/10</strong></span>
        <span>Difficulty: ${esc(c.exploitation_difficulty)}</span>
      </div>
      <p class="chain-body">${esc((c.attack_flow||"").substring(0,200))}${(c.attack_flow||"").length>200?"…":""}</p>
    </div>`).join("");
}

function renderTopFindings(findings) {
  const top = findings.filter(f=>["critical","high"].includes(f.severity)).slice(0,5);
  if (!top.length) {
    document.getElementById("topFindingsList").innerHTML = '<div class="empty-state"><p>No critical or high findings yet.</p></div>';
    return;
  }
  document.getElementById("topFindingsList").innerHTML = top.map(f=>findingCard(f, true)).join("");
  wireExpandToggle(document.getElementById("topFindingsList"));
}

/* ---------- findings ---------- */
let allFindings = [];
let catFilterPopulated = false;

function populateCatFilter() {
  if (catFilterPopulated) return;
  catFilterPopulated = true;
  const sel = document.getElementById("categoryFilterFindings");
  Object.entries(CAT).forEach(([k,v])=>{
    const o=document.createElement("option"); o.value=k; o.textContent=`${v.code} ${v.label}`;
    sel.appendChild(o);
  });
}

async function loadFindings() {
  populateCatFilter();
  await populateAppSelectors();
  document.getElementById("appFilterFindings").value = selectedApp;
  const qs = selectedApp ? `?app_name=${encodeURIComponent(selectedApp)}` : "";
  allFindings = await api(`/findings${qs}`);
  renderFindings();
}

function renderFindings() {
  const sev = document.getElementById("severityFilter").value;
  const val = document.getElementById("validationFilter").value;
  const cat = document.getElementById("categoryFilterFindings").value;
  const app = document.getElementById("appFilterFindings").value;

  const filtered = allFindings.filter(f=>
    (!sev || f.severity===sev) &&
    (!val || f.validation_status===val) &&
    (!cat || f.category===cat) &&
    (!app || f.app_name===app)
  );

  const list = document.getElementById("findingsList");
  if (!filtered.length) {
    list.innerHTML = `<div class="empty-state"><p>${allFindings.length===0?"No findings yet. Run a scan and approve AI triage.":"No findings match these filters."}</p></div>`;
    return;
  }
  list.innerHTML = filtered.map(f=>findingCard(f, false)).join("");
  wireExpandToggle(list);
  wireRemediationButtons(list);
}

["severityFilter","validationFilter","categoryFilterFindings","appFilterFindings"].forEach(id=>{
  document.getElementById(id)?.addEventListener("change", renderFindings);
});

function confidenceBar(confidence) {
  const pct = confidence||0;
  return `<span style="font-size:12px;color:var(--text-secondary);">${pct}%
    <span class="confidence-bar-wrap"><span class="confidence-bar" style="width:${pct}%"></span></span>
  </span>`;
}

function findingCard(f, compact) {
  const info = CAT[f.category]||{code:"",label:f.category};
  const cvss = f.cvss_score ? `CVSS ${f.cvss_score}` : "";
  const vstatus = f.validation_status||"potential";
  return `<div class="finding-row" data-id="${f.id}">
    <div class="finding-head" data-toggle>
      <div style="flex:1;min-width:0;">
        <p class="finding-title">${esc(f.vulnerability_name||f.rationale||"Finding")}</p>
        <p class="finding-meta">${esc(info.code)} &middot; ${esc(f.cwe_id||"")} &middot; ${esc(f.url||"n/a")}</p>
      </div>
      <div class="finding-badges">
        <span class="badge ${f.severity}">${f.severity}</span>
        ${cvss ? `<span class="cvss-badge">${cvss}</span>` : ""}
        <span class="badge ${vstatus}">${vstatus}</span>
        ${confidenceBar(f.confidence)}
      </div>
    </div>
    ${compact ? "" : `<div class="finding-body">
      <div class="analysis-grid">
        <div>
          <div class="finding-section"><p class="finding-section-label">Root cause</p><p class="finding-section-value">${esc(f.root_cause||"—")}</p></div>
          <div class="finding-section"><p class="finding-section-label">Technical impact</p><p class="finding-section-value">${esc(f.technical_impact||"—")}</p></div>
          <div class="finding-section"><p class="finding-section-label">Business impact</p><p class="finding-section-value">${esc(f.business_impact||"—")}</p></div>
        </div>
        <div>
          <div class="finding-section"><p class="finding-section-label">Attack scenario</p><p class="finding-section-value">${esc(f.attack_scenario||"—")}</p></div>
          <div class="finding-section"><p class="finding-section-label">Evidence</p><p class="finding-section-value">${esc(f.evidence_summary||"—")}</p></div>
        </div>
      </div>
      <div class="finding-section"><p class="finding-section-label">Reproduction steps</p><pre>${esc(f.reproduction_steps||"—")}</pre></div>
      <div class="finding-section"><p class="finding-section-label">Remediation</p><p class="finding-section-value">${esc(f.remediation||"—")}</p></div>
      <div class="finding-section"><p class="finding-section-label">CVSS vector</p><div class="cvss-vector">${esc(f.cvss_vector||"N/A")}</div></div>
      <div class="finding-actions">
        <button class="btn-ghost" data-rem="in_progress">Mark in progress</button>
        <button class="btn-ghost" data-rem="ready_for_validation">Ready for validation</button>
        <button class="btn-ghost" data-rem="remediated">Mark remediated</button>
        <button class="btn-ghost" data-rem="dismissed" style="color:var(--text-tertiary)">Dismiss</button>
      </div>
    </div>`}
  </div>`;
}

function wireExpandToggle(container) {
  container.querySelectorAll("[data-toggle]").forEach(h=>{
    h.addEventListener("click", ()=>h.closest(".finding-row").classList.toggle("expanded"));
  });
}

function wireRemediationButtons(container) {
  container.querySelectorAll("[data-rem]").forEach(btn=>{
    btn.addEventListener("click", async e=>{
      e.stopPropagation();
      const id = btn.closest(".finding-row").dataset.id;
      await api(`/findings/${id}/remediation`,{method:"PATCH",body:JSON.stringify({status:btn.dataset.rem})});
      showToast("Status updated");
      if (currentTab==="findings") loadFindings();
      if (currentTab==="remediation") loadRemediation();
    });
  });
}

/* ---------- pending & triage ---------- */
async function loadPending() {
  await populateAppSelectors();
  const qs = selectedApp ? `?app_name=${encodeURIComponent(selectedApp)}` : "";
  const [data, settings] = await Promise.all([api(`/pending${qs}`), api("/settings")]);
  renderPendingCard(data, settings);
}

function renderPendingCard(data, settings) {
  const block = document.getElementById("pendingBlock");
  const card  = document.getElementById("pendingCard");
  if (!data.count) { block.hidden=true; return; }
  block.hidden = false;

  const badges = Object.entries(data.by_category)
    .map(([k,n])=>`<span class="badge potential">${CAT[k]?.code||k} · ${n}</span>`).join("");

  const hasCreds = settings.provider==="azure_foundry"
    ? settings.azure_foundry_api_key_set : settings.anthropic_api_key_set;
  let disabled=false, note="";
  if (!settings.ai_enabled) { disabled=true; note="AI analysis is disabled. Enable it in Settings to triage these findings."; }
  else if (!hasCreds) { disabled=true; note="Add your API credentials in Settings to enable AI analysis."; }
  else { note="AI analysis will assign CVSS scores, CWE mappings, root cause analysis, and detect attack chains."; }

  card.innerHTML = `
    <p class="pending-title">${data.count} finding${data.count===1?"":"s"} awaiting intelligence analysis</p>
    <div class="pending-badges">${badges}</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
      <button class="btn-ghost btn-sm" id="dlJson">Download raw (JSON)</button>
      <button class="btn-ghost btn-sm" id="dlCsv">Download raw (CSV)</button>
    </div>
    <button class="btn-primary" id="approveTriageButton" ${disabled?"disabled":""}>Run AI analysis</button>
    <p class="hint" style="margin-top:8px;">${note}</p>`;

  document.getElementById("approveTriageButton").addEventListener("click", approveTriage);
  document.getElementById("dlJson").addEventListener("click", ()=>downloadPending(data.findings,"json"));
  document.getElementById("dlCsv").addEventListener("click", ()=>downloadPending(data.findings,"csv"));
}

function downloadPending(findings, fmt) {
  let blob, name;
  if (fmt==="csv") {
    const cols=["tool","category","title","url","app_name","raw_severity","description"];
    const lines=[cols.join(","),...findings.map(f=>cols.map(c=>`"${String(f[c]||"").replace(/"/g,'""')}"`).join(","))];
    blob=new Blob([lines.join("\n")],{type:"text/csv"}); name="pending.csv";
  } else {
    blob=new Blob([JSON.stringify(findings,null,2)],{type:"application/json"}); name="pending.json";
  }
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a"); a.href=url; a.download=name; a.click();
  URL.revokeObjectURL(url);
}

async function approveTriage() {
  const btn=document.getElementById("approveTriageButton");
  if (btn) btn.disabled=true;
  try {
    await api("/triage",{method:"POST",body:JSON.stringify({app_name:selectedApp||null})});
    showToast("AI analysis started — CVSS scoring, CWE mapping, attack chain detection running");
    pollTriageStatus();
  } catch(err) {
    showToast(err.message);
    if (btn) btn.disabled=false;
  }
}

let triagePoll=null;
async function pollTriageStatus() {
  const s = await api("/triage/status");
  if (s.running) {
    if (!triagePoll) triagePoll=setInterval(pollTriageStatus,2500);
  } else {
    if (triagePoll) { clearInterval(triagePoll); triagePoll=null; }
    if (s.last_error) showToast(s.last_error);
    else if (s.last_result) {
      const r=s.last_result;
      showToast(`Analysis complete: ${r.triaged_count} findings, ${r.chain_count||0} attack chains detected`);
    }
    loadPending();
    if (currentTab==="dashboard") loadDashboard();
    if (currentTab==="findings") loadFindings();
    if (currentTab==="remediation") loadRemediation();
  }
}

/* ---------- remediation ---------- */
async function loadRemediation() {
  await populateAppSelectors();
  document.getElementById("appFilterRemediation").value = selectedApp;
  const qs = selectedApp ? `?app_name=${encodeURIComponent(selectedApp)}` : "";
  const [rem, findings] = await Promise.all([
    api(`/summary/remediation${qs}`),
    api(`/findings${qs}`),
  ]);
  renderRemMetrics(rem);
  renderRemColumns(findings);
}

document.getElementById("appFilterRemediation")?.addEventListener("change", e=>{
  selectedApp=e.target.value; loadRemediation();
});

function renderRemMetrics(rem) {
  const items=[
    {label:"Open",value:rem.open||0,cls:"critical"},
    {label:"In progress",value:rem.in_progress||0,cls:"medium"},
    {label:"Pending review",value:rem.ready_for_validation||0,cls:"low"},
    {label:"Remediated",value:rem.remediated||0,cls:"confirmed"},
    {label:"Reopened",value:rem.reopened||0,cls:"high"},
  ];
  document.getElementById("remMetricGrid").innerHTML = items.map(i=>`
    <div class="metric-card"><p class="metric-label">${i.label}</p><p class="metric-value ${i.cls}">${i.value}</p></div>`).join("");
}

function renderRemColumns(findings) {
  const cols=[
    {key:"open",label:"Open"},
    {key:"in_progress",label:"In Progress"},
    {key:"ready_for_validation",label:"Ready for Validation"},
    {key:"remediated",label:"Remediated"},
    {key:"reopened",label:"Reopened"},
  ];
  document.getElementById("remColumns").innerHTML = cols.map(col=>{
    const items=findings.filter(f=>f.remediation_status===col.key);
    return `<div class="rem-column">
      <h3>${col.label} <span class="badge-count">${items.length}</span></h3>
      ${items.length===0?`<p style="font-size:12px;color:var(--text-tertiary)">None</p>`:
        items.map(f=>`<div class="rem-item" onclick="openFindingDetail(${f.id})">
          <p class="rem-item-title">${esc((f.vulnerability_name||f.rationale||"Finding").substring(0,50))}</p>
          <p class="rem-item-meta">
            <span class="badge ${f.severity}" style="font-size:9px;">${f.severity}</span>
            ${f.cvss_score?`<span style="margin-left:6px;">CVSS ${f.cvss_score}</span>`:""}
          </p>
        </div>`).join("")}
    </div>`;
  }).join("");
}

async function openFindingDetail(id) {
  const f = await api(`/findings/${id}`);
  // switch to findings tab and expand the finding
  switchTab("findings");
  await loadFindings();
  const row = document.querySelector(`.finding-row[data-id="${id}"]`);
  if (row) { row.classList.add("expanded"); row.scrollIntoView({behavior:"smooth",block:"start"}); }
}

/* ---------- scheduling ---------- */
async function loadSchedules() {
  const schedules = await api("/schedules");
  const el = document.getElementById("schedulesList");
  if (!schedules.length) {
    el.innerHTML = `<p class="hint">No scheduled assessments. Add one below to run automatic scans.</p>`;
    return;
  }
  el.innerHTML = schedules.map(s=>`
    <div class="schedule-row">
      <div class="schedule-info">
        <p>${esc(s.app_name||s.target_url)}</p>
        <p class="sub">${esc(s.cron)} &middot; ${s.enabled?'Enabled':'Disabled'}</p>
      </div>
      <div class="schedule-actions">
        <button class="btn-ghost btn-sm" onclick="toggleSchedule('${s.id}',${!s.enabled})">${s.enabled?"Disable":"Enable"}</button>
        <button class="btn-danger" onclick="deleteSchedule('${s.id}')">Delete</button>
      </div>
    </div>`).join("");
}

document.getElementById("scheduleForm").addEventListener("submit", async e=>{
  e.preventDefault();
  await api("/schedules",{method:"POST",body:JSON.stringify({
    target_url: document.getElementById("scheduleUrl").value.trim(),
    app_name: document.getElementById("scheduleAppName").value.trim()||null,
    cron: document.getElementById("scheduleCron").value.trim()||"0 2 * * *",
  })});
  showToast("Schedule added");
  loadSchedules();
});

async function deleteSchedule(id) {
  if (!confirm("Delete this schedule?")) return;
  await api(`/schedules/${id}`,{method:"DELETE"});
  loadSchedules();
}

async function toggleSchedule(id, enabled) {
  await api(`/schedules/${id}`,{method:"PATCH",body:JSON.stringify({enabled})});
  loadSchedules();
}

/* ---------- settings ---------- */
function applyProviderVisibility(p) {
  document.getElementById("anthropicKeyField").hidden = p==="azure_foundry";
  document.getElementById("azureEndpointField").hidden = p!=="azure_foundry";
  document.getElementById("azureKeyField").hidden = p!=="azure_foundry";
}
document.getElementById("providerSelect").addEventListener("change", e=>applyProviderVisibility(e.target.value));

async function loadSettings() {
  const s = await api("/settings");
  document.getElementById("providerSelect").value = s.provider;
  applyProviderVisibility(s.provider);
  document.getElementById("aiEnabledToggle").checked = !!s.ai_enabled;
  document.getElementById("skipInfoToggle").checked = !!s.skip_info_findings;
  document.getElementById("apiKeyStatus").textContent = s.anthropic_api_key_set ? `Saved (${s.anthropic_api_key_masked})` : "Not set";
  document.getElementById("azureEndpointInput").value = s.azure_foundry_endpoint||"";
  document.getElementById("azureKeyStatus").textContent = s.azure_foundry_api_key_set ? `Saved (${s.azure_foundry_api_key_masked})` : "Not set";
  document.getElementById("modelInput").value = s.agent_model||"";
  document.getElementById("zapUrlInput").value = s.zap_api_url||"";
  document.getElementById("zapKeyStatus").textContent = s.zap_api_key_set ? "Saved" : "Not set";
  document.getElementById("slackStatus").textContent = s.slack_webhook_url_set ? "Saved" : "Not set";
  loadTokenUsage();
}

document.getElementById("settingsForm").addEventListener("submit", async e=>{
  e.preventDefault();
  await api("/settings",{method:"POST",body:JSON.stringify({
    provider: document.getElementById("providerSelect").value,
    ai_enabled: document.getElementById("aiEnabledToggle").checked,
    anthropic_api_key: document.getElementById("apiKeyInput").value||null,
    azure_foundry_endpoint: document.getElementById("azureEndpointInput").value||null,
    azure_foundry_api_key: document.getElementById("azureKeyInput").value||null,
    agent_model: document.getElementById("modelInput").value||null,
  })});
  document.getElementById("apiKeyInput").value="";
  document.getElementById("azureKeyInput").value="";
  showToast("AI settings saved");
  loadSettings();
  loadPending();
});

document.getElementById("scannerSettingsForm").addEventListener("submit", async e=>{
  e.preventDefault();
  await api("/settings",{method:"POST",body:JSON.stringify({
    zap_api_url: document.getElementById("zapUrlInput").value||null,
    zap_api_key: document.getElementById("zapKeyInput").value||null,
    slack_webhook_url: document.getElementById("slackInput").value||null,
    skip_info_findings: document.getElementById("skipInfoToggle").checked,
  })});
  document.getElementById("zapKeyInput").value="";
  document.getElementById("slackInput").value="";
  showToast("Scanner settings saved");
  loadSettings();
});

async function loadTokenUsage() {
  const d = await api("/tokens");
  document.getElementById("tokenLimitInput").value = d.limit||"";
  document.getElementById("tokenMetricGrid").innerHTML = [
    {label:"Used",value:d.used,cls:""},
    {label:"Limit",value:d.limit||"Unlimited",cls:"accent"},
    {label:"Remaining",value:d.remaining===null?"—":d.remaining,cls:"confirmed"},
  ].map(i=>`<div class="metric-card"><p class="metric-label">${i.label}</p><p class="metric-value ${i.cls}">${i.value}</p></div>`).join("");
}

document.getElementById("saveTokenLimitButton").addEventListener("click", async ()=>{
  const v = parseInt(document.getElementById("tokenLimitInput").value.trim()||"0",10);
  await api("/settings",{method:"POST",body:JSON.stringify({token_limit:isNaN(v)?0:v,skip_info_findings:document.getElementById("skipInfoToggle").checked})});
  showToast("Token settings saved");
  loadTokenUsage();
});

document.getElementById("resetTokensButton").addEventListener("click", async ()=>{
  if (!confirm("Reset token usage counter to zero?")) return;
  await api("/tokens/reset",{method:"POST"});
  showToast("Usage reset");
  loadTokenUsage();
});

/* ---------- scan flow ---------- */
let pollHandle=null;

document.getElementById("scanForm").addEventListener("submit", async e=>{
  e.preventDefault();
  const url=document.getElementById("targetUrlInput").value.trim();
  const name=document.getElementById("appNameInput").value.trim();
  const errEl=document.getElementById("scanError");
  errEl.hidden=true;
  try {
    await api("/scan",{method:"POST",body:JSON.stringify({target_url:url,app_name:name||null})});
    showToast("Assessment started");
    pollStatus();
  } catch(err) { errEl.textContent=err.message; errEl.hidden=false; }
});

async function pollStatus() {
  const s=await api("/scan/status");
  updateStatusUI(s);
  if (s.running) {
    if (!pollHandle) pollHandle=setInterval(pollStatus,3000);
  } else {
    if (pollHandle) { clearInterval(pollHandle); pollHandle=null; }
    if (s.scanner_log?.length) {
      const el=document.getElementById("scannerLog");
      if (el) el.innerHTML=s.scanner_log.map(l=>
        `<p class="hint" style="margin:2px 0;color:${l.includes("[error]")?"var(--critical)":"var(--text-tertiary)"};">${esc(l)}</p>`
      ).join("");
    }
    loadPending();
    if (currentTab==="dashboard") loadDashboard();
  }
}

function updateStatusUI(s) {
  const pill=document.getElementById("statusPill");
  const topbar=document.getElementById("topbar");
  const btn=document.getElementById("scanButton");
  topbar.classList.toggle("scanning",s.running);
  if (btn) btn.disabled=s.running;
  if (s.running) {
    pill.textContent=`scanning ${s.app_name||s.target_url||""}`;
    pill.className="status-pill running";
  } else if (s.last_error) {
    pill.textContent="last scan failed";
    pill.className="status-pill error";
    pill.title=s.last_error;
  } else if (s.last_raw_count!=null) {
    pill.textContent=`${s.app_name||""}: ${s.last_raw_count} discovered`.replace(/^: /,"");
    pill.className="status-pill";
  } else {
    pill.textContent="idle";
    pill.className="status-pill";
  }
}

/* ---------- init ---------- */
loadDashboard();
loadPending();
pollStatus();
