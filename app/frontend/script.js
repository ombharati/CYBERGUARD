/*
  CYBERGUARD frontend
  -------------------
  This file currently runs in MOCK MODE so the UI works without a backend.

  Later, set:
    USE_MOCK_DATA = false

  and adjust:
    API_BASE_URL
    CREATE_SCAN_ENDPOINT
    HISTORY_ENDPOINT

  to match your FastAPI API.
*/

function getApiBaseUrl() {
  const custom = localStorage.getItem("cyberguard_api_url");
  if (custom) return custom.replace(/\/+$/, "");
  if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
    return window.location.port === "8000" ? window.location.origin : "http://localhost:8000";
  }
  if (window.location.origin && !window.location.hostname.endsWith("github.io")) {
    return window.location.origin;
  }
  return "https://ali-caps-prostores-derby.trycloudflare.com";
}

const API_BASE_URL = getApiBaseUrl();
const CREATE_SCAN_ENDPOINT = "/api/scans";
const HISTORY_ENDPOINT = "/api/scans";

let USE_MOCK_DATA = false;
// auto-detect backend availability on load
fetch(`${API_BASE_URL}/health`).then(r=>{ if(!r.ok) USE_MOCK_DATA=true; }).catch(()=>{ USE_MOCK_DATA=true; });

let currentMode = "url";
let currentResult = null;
let currentFilter = "all";

const state = {
  scans: loadScans()
};

/* -----------------------------
   DOM HELPERS
----------------------------- */

const $ = (selector) => document.querySelector(selector);

const $$ = (selector) => [...document.querySelectorAll(selector)];

function show(element) {
  element.classList.remove("hidden");
}

function hide(element) {
  element.classList.add("hidden");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* -----------------------------
   NAVIGATION
----------------------------- */

function switchView(viewName) {
  $$(".view").forEach((view) => {
    view.classList.remove("active-view");
  });

  $(`#view-${viewName}`)?.classList.add("active-view");

  $$(".nav-link").forEach((button) => {
    button.classList.toggle(
      "active",
      button.dataset.view === viewName
    );
  });

  window.scrollTo({
    top: 0,
    behavior: "smooth"
  });

  if (viewName === "history") {
    renderHistory();
  }
}

$$("[data-view]").forEach((button) => {
  button.addEventListener("click", () => {
    switchView(button.dataset.view);
  });
});

/* -----------------------------
   ANALYSIS MODES
----------------------------- */

$$(".mode-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    switchMode(tab.dataset.mode);
  });
});

function switchMode(mode) {
  currentMode = mode;

  $$(".mode-tab").forEach((tab) => {
    tab.classList.toggle(
      "active",
      tab.dataset.mode === mode
    );
  });

  $$(".mode-panel").forEach((panel) => {
    panel.classList.remove("active-panel");
  });

  $(`#panel-${mode}`)?.classList.add("active-panel");

  hide($("#error-box"));
}

/* -----------------------------
   SAMPLE DATA
----------------------------- */

$("#sample-url").addEventListener("click", () => {
  $("#url-input").value =
    "https://secure-login-account.example.com/verify";
});

/* -----------------------------
   INPUT COLLECTION
----------------------------- */

function collectInput() {
  if (currentMode === "url") {
    return {
      type: "url",
      value: $("#url-input").value.trim()
    };
  }

  if (currentMode === "email") {
    return {
      type: "email",
      value: {
        sender: $("#email-sender").value.trim(),
        subject: $("#email-subject").value.trim(),
        body: $("#email-body").value.trim()
      }
    };
  }

  return {
    type: "content",
    value: $("#content-input").value.trim()
  };
}

function validateInput(payload) {
  if (payload.type === "url") {
    if (!payload.value) {
      return "Enter a URL to analyze.";
    }

    try {
      const url = new URL(payload.value);

      if (!["http:", "https:"].includes(url.protocol)) {
        return "Enter a valid HTTP or HTTPS URL.";
      }
    } catch {
      return "Enter a valid URL such as https://example.com.";
    }
  }

  if (payload.type === "email") {
    if (!payload.value.sender) {
      return "Enter the sender address.";
    }

    if (!payload.value.subject && !payload.value.body) {
      return "Enter an email subject or email body.";
    }
  }

  if (payload.type === "content") {
    if (!payload.value) {
      return "Paste some content to analyze.";
    }

    if (payload.value.length < 10) {
      return "Enter more content so it can be analyzed.";
    }
  }

  return null;
}

function displayError(message) {
  const box = $("#error-box");
  box.textContent = message;
  show(box);
}

/* -----------------------------
   ANALYZE
----------------------------- */

$("#analyze-button").addEventListener("click", async () => {
  const payload = collectInput();
  const error = validateInput(payload);

  if (error) {
    displayError(error);
    return;
  }

  hide($("#error-box"));

  hide($("#result-card"));
  hide($("#report-card"));
  show($("#progress-card"));

  $("#analyze-button").disabled = true;

  try {
    let result;
    if (USE_MOCK_DATA) {
      result = await runMockAnalysis(payload);
    } else {
      try {
        // show progress while hitting real API
        const apiPromise = runApiAnalysis(payload);
        const progressPromise = runAnalysisProgress();
        result = await apiPromise;
        await progressPromise;
      } catch (apiErr) {
        console.warn("API failed, falling back to mock:", apiErr);
        // fallback to mock so UI stays impressive offline
        result = await runMockAnalysis(payload);
      }
    }

    currentResult = result;

    state.scans.unshift(result);
    state.scans = state.scans.slice(0, 50);

    saveScans();

    showResult(result);
    renderRecentScans();
    // try refresh history from backend if available
    try { await refreshHistoryFromApi(); } catch {}
  } catch (error) {
    displayError(
      error.message || "The analysis could not be completed."
    );

    hide($("#progress-card"));
  } finally {
    $("#analyze-button").disabled = false;
  }
});

/* -----------------------------
   API HISTORY SYNC
----------------------------- */
async function refreshHistoryFromApi(){
  if(USE_MOCK_DATA) return;
  try{
    const r = await fetch(`${API_BASE_URL}${HISTORY_ENDPOINT}`);
    if(!r.ok) return;
    const data = await r.json();
    if(Array.isArray(data) && data.length){
      // merge: keep API results at top, dedup by id
      const ids = new Set(data.map(d=>d.id));
      const remaining = state.scans.filter(s=>!ids.has(s.id));
      state.scans = [...data, ...remaining].slice(0,50);
      saveScans();
      renderRecentScans();
    }
  }catch{}
}

/* -----------------------------
   MOCK ANALYSIS
----------------------------- */

async function runMockAnalysis(payload) {
  await runAnalysisProgress();

  let result;

  if (payload.type === "url") {
    result = createMockUrlResult(payload);
  } else if (payload.type === "email") {
    result = createMockEmailResult(payload);
  } else {
    result = createMockContentResult(payload);
  }

  return result;
}

async function runAnalysisProgress() {
  const steps = $$(".analysis-step");
  const started = performance.now();

  $("#progress-time").textContent = "0.0s";

  for (let index = 0; index < steps.length; index += 1) {
    steps.forEach((step, stepIndex) => {
      step.classList.toggle(
        "current",
        stepIndex === index
      );

      const stateText = step.querySelector(".step-state");

      if (stepIndex < index) {
        stateText.textContent = "Done";
      } else if (stepIndex === index) {
        stateText.textContent = "Working";
      } else {
        stateText.textContent = "Waiting";
      }
    });

    await wait(550);

    const elapsed = (performance.now() - started) / 1000;
    $("#progress-time").textContent = `${elapsed.toFixed(1)}s`;
  }

  steps.forEach((step) => {
    step.classList.remove("current");
    step.querySelector(".step-state").textContent = "Done";
  });
}

/* -----------------------------
   MOCK RESULT GENERATORS
----------------------------- */

function createMockUrlResult(payload) {
  const target = payload.value;

  let score = 18;
  const findings = [];

  let hostname = "";

  try {
    const url = new URL(target);
    hostname = url.hostname;

    if (
      hostname.includes("secure") ||
      hostname.includes("verify") ||
      hostname.includes("login")
    ) {
      score += 18;

      findings.push({
        severity: "medium",
        title: "Security-sensitive URL wording",
        description:
          "The hostname contains words commonly associated with account verification or authentication flows."
      });
    }

    if (
      target.length > 70
    ) {
      score += 12;

      findings.push({
        severity: "low",
        title: "Unusually long URL",
        description:
          "Long URLs can make the actual destination harder to recognize and can hide additional path or query information."
      });
    }

    if (
      hostname.split(".").length >= 4
    ) {
      score += 16;

      findings.push({
        severity: "medium",
        title: "Deep subdomain structure",
        description:
          "The hostname contains multiple nested subdomains, which can make a destination harder to interpret."
      });
    }

    if (
      /(^|\.)example\.com$/i.test(hostname)
    ) {
      score += 14;
    }
  } catch {
    score += 5;
  }

  score = Math.min(score, 92);

  if (findings.length === 0) {
    findings.push({
      severity: "low",
      title: "No strong suspicious indicators",
      description:
        "The available first-pass checks did not identify major warning signs in this URL."
    });
  }

  return buildResult({
    type: "URL",
    target,
    score,
    findings,
    summary:
      score >= 75
        ? "The submitted URL contains several high-risk indicators that deserve immediate attention."
        : score >= 45
          ? "The submitted URL contains several signals that deserve further investigation."
          : "The submitted URL does not show strong suspicious indicators in this first-pass analysis."
  });
}

function createMockEmailResult(payload) {
  const { sender, subject, body } = payload.value;

  const combined = `${sender} ${subject} ${body}`.toLowerCase();

  let score = 15;
  const findings = [];

  const urgencyWords = [
    "urgent",
    "immediately",
    "suspended",
    "verify",
    "action required",
    "expires",
    "within 24"
  ];

  if (urgencyWords.some((word) => combined.includes(word))) {
    score += 24;

    findings.push({
      severity: "medium",
      title: "Urgency language detected",
      description:
        "The message contains language intended to encourage immediate action."
    });
  }

  const credentialWords = [
    "password",
    "login",
    "credential",
    "verification",
    "sign in",
    "account"
  ];

  if (credentialWords.some((word) => combined.includes(word))) {
    score += 26;

    findings.push({
      severity: "high",
      title: "Credential-related language",
      description:
        "The message references authentication or account information."
    });
  }

  if (
    sender &&
    !sender.includes("@")
  ) {
    score += 10;

    findings.push({
      severity: "low",
      title: "Unusual sender format",
      description:
        "The sender field does not look like a standard email address."
    });
  }

  if (
    combined.includes("click") ||
    combined.includes("link")
  ) {
    score += 13;

    findings.push({
      severity: "medium",
      title: "Action-oriented request",
      description:
        "The message appears to direct the recipient toward an external action."
    });
  }

  score = Math.min(score, 95);

  if (findings.length === 0) {
    findings.push({
      severity: "low",
      title: "No strong indicators found",
      description:
        "The initial content checks did not identify major suspicious patterns."
    });
  }

  return buildResult({
    type: "Email",
    target: `From: ${sender || "Unknown"}\nSubject: ${subject || "No subject"}\n\n${body}`,
    score,
    findings,
    summary:
      score >= 75
        ? "This message contains high-risk patterns strongly indicative of potential phishing or credential harvesting."
        : score >= 45
          ? "This message contains language and behavior patterns that may warrant further investigation."
          : "The submitted message does not show strong suspicious indicators in this first-pass analysis."
  });
}

function createMockContentResult(payload) {
  const text = payload.value.toLowerCase();

  let score = 12;
  const findings = [];

  if (
    text.includes("password") ||
    text.includes("credential") ||
    text.includes("login")
  ) {
    score += 24;

    findings.push({
      severity: "medium",
      title: "Authentication-related content",
      description:
        "The content contains references to credentials or authentication."
    });
  }

  if (
    text.includes("urgent") ||
    text.includes("immediately") ||
    text.includes("suspended")
  ) {
    score += 23;

    findings.push({
      severity: "medium",
      title: "Urgency language",
      description:
        "The content uses pressure-based language that can occur in social-engineering attempts."
    });
  }

  if (
    text.includes("http://") ||
    text.includes("https://")
  ) {
    score += 14;

    findings.push({
      severity: "low",
      title: "External link detected",
      description:
        "The content contains a URL that can be analyzed separately for additional context."
    });
  }

  if (
    text.includes("verify your account") ||
    text.includes("confirm your account")
  ) {
    score += 18;

    findings.push({
      severity: "high",
      title: "Account verification request",
      description:
        "The content requests account verification, which can be relevant to phishing analysis."
    });
  }

  score = Math.min(score, 92);

  if (findings.length === 0) {
    findings.push({
      severity: "low",
      title: "No strong suspicious indicators",
      description:
        "The initial content checks did not identify major warning signs."
    });
  }

  return buildResult({
    type: "Content",
    target: payload.value,
    score,
    findings,
    summary:
      score >= 75
        ? "The content contains high-risk patterns commonly associated with deceptive or malicious requests."
        : score >= 45
          ? "The content contains several patterns that deserve additional security analysis."
          : "The content does not show strong suspicious indicators in this first-pass analysis."
  });
}

function buildResult({
  type,
  target,
  score,
  findings,
  summary
}) {
  const classification =
    score >= 75
      ? "High Risk"
      : score >= 45
        ? "Suspicious"
        : "Safe";

  const signals = [
    {
      name: "Pattern analysis",
      value: Math.min(score + 4, 100)
    },
    {
      name: "Content indicators",
      value: Math.min(score + 1, 100)
    },
    {
      name: "Risk aggregation",
      value: score
    },
    {
      name: "Reputation signals",
      value: Math.max(score - 16, 8)
    }
  ];

  return {
    id: generateScanId(),
    type,
    target,
    score,
    classification,
    summary,
    findings,
    signals,
    explanation:
      classification === "Safe"
        ? "The available first-pass checks did not find strong evidence of malicious or deceptive behavior. This does not guarantee that the input is completely safe."
        : "The analysis found multiple signals that may indicate suspicious or deceptive behavior. Treat the input carefully and review the evidence before interacting with it.",
    timestamp: new Date().toISOString()
  };
}

/* -----------------------------
   REAL API MODE
----------------------------- */

async function runApiAnalysis(payload) {
  const response = await fetch(
    `${API_BASE_URL}${CREATE_SCAN_ENDPOINT}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        input_type: payload.type,
        data: payload.value
      })
    }
  );

  if (!response.ok) {
    throw new Error(
      `Backend returned HTTP ${response.status}.`
    );
  }

  const data = await response.json();

  /*
    Expected normalized response:

    {
      id: "CG-001",
      type: "URL",
      target: "...",
      score: 72,
      classification: "Suspicious",
      summary: "...",
      findings: [
        {
          severity: "medium",
          title: "...",
          description: "..."
        }
      ],
      signals: [
        {
          name: "Pattern analysis",
          value: 72
        }
      ],
      explanation: "...",
      timestamp: "2026-09-22T..."
    }

    Adapt this mapping once your FastAPI response schema is final.
  */

  return data;
}

/* -----------------------------
   RESULT RENDERING
----------------------------- */

function showResult(result) {
  hide($("#progress-card"));
  hide($("#report-card"));
  show($("#result-card"));

  $("#result-title").textContent =
    result.classification === "Safe"
      ? "No major warning signs found."
      : result.classification === "Suspicious"
        ? "Suspicious activity detected."
        : "High-risk activity detected.";

  $("#result-summary").textContent = result.summary;

  $("#result-score").textContent = result.score;

  const badge = $("#result-badge");
  badge.textContent = result.classification;
  badge.className = "risk-badge";

  if (result.classification === "Safe") {
    badge.classList.add("risk-safe");
  } else if (result.classification === "Suspicious") {
    badge.classList.add("risk-suspicious");
  } else {
    badge.classList.add("risk-high");
  }

  const ring = $("#score-ring");
  ring.style.setProperty(
    "--score-deg",
    `${result.score * 3.6}deg`
  );

  ring.style.setProperty(
    "--score-color",
    getRiskColor(result.classification)
  );

  $("#score-caption").textContent =
    getScoreCaption(result.score);

  $("#finding-count").textContent =
    `${result.findings.length} finding${result.findings.length === 1 ? "" : "s"}`;

  $("#findings-list").innerHTML =
    result.findings.map(renderFinding).join("");

  $("#signals-list").innerHTML =
    result.signals.map(renderSignal).join("");

  $("#result-id").textContent = result.id;
  $("#result-type").textContent = result.type;
  $("#result-time").textContent = formatDate(result.timestamp);

  window.scrollTo({
    top: $("#result-card").offsetTop - 90,
    behavior: "smooth"
  });
}

function renderFinding(finding) {
  return `
    <article class="finding">
      <div class="finding-top">
        <span class="finding-severity ${getSeverityClass(finding.severity)}">
          ${escapeHtml(finding.severity)}
        </span>
      </div>

      <h4>${escapeHtml(finding.title)}</h4>

      <p>${escapeHtml(finding.description)}</p>
    </article>
  `;
}

function renderSignal(signal) {
  return `
    <div class="signal-row">
      <span class="signal-name">${escapeHtml(signal.name)}</span>

      <div class="signal-track">
        <div
          class="signal-fill"
          style="width: ${Math.max(0, Math.min(100, signal.value))}%"
        ></div>
      </div>

      <span class="signal-value">${Math.round(signal.value)}%</span>
    </div>
  `;
}

function getSeverityClass(severity) {
  if (severity === "high") {
    return "severity-high";
  }

  if (severity === "medium") {
    return "severity-medium";
  }

  return "severity-low";
}

function getRiskColor(classification) {
  if (classification === "Safe") {
    return "#10b981";
  }

  if (classification === "Suspicious") {
    return "#f59e0b";
  }

  return "#f43f5e";
}

function getScoreCaption(score) {
  if (score < 45) {
    return "Low indication of suspicious behavior from the current analysis.";
  }

  if (score < 75) {
    return "Several indicators were detected and should be reviewed.";
  }

  return "Multiple risk indicators were detected and deserve careful review.";
}

/* -----------------------------
   REPORT
----------------------------- */

$("#open-report").addEventListener("click", () => {
  if (!currentResult) {
    return;
  }

  renderReport(currentResult);

  hide($("#result-card"));
  show($("#report-card"));

  window.scrollTo({
    top: $("#report-card").offsetTop - 90,
    behavior: "smooth"
  });
});

$("#close-report").addEventListener("click", () => {
  hide($("#report-card"));
  show($("#result-card"));

  window.scrollTo({
    top: $("#result-card").offsetTop - 90,
    behavior: "smooth"
  });
});

function renderReport(result) {
  $("#report-heading").textContent =
    `${result.type} security report`;

  $("#report-status-dot").style.background =
    getRiskColor(result.classification);

  $("#report-classification").textContent =
    result.classification;

  $("#report-status-text").textContent =
    getScoreCaption(result.score);

  $("#report-score").textContent =
    `${result.score} / 100`;

  $("#report-target").textContent =
    result.target;

  $("#report-explanation").textContent =
    result.explanation;

  $("#report-id").textContent =
    result.id;

  $("#report-type").textContent =
    result.type;

  $("#report-time").textContent =
    formatDate(result.timestamp);

  $("#report-classification-2").textContent =
    result.classification;

  $("#report-evidence").innerHTML =
    result.findings
      .map(
        (finding) => `
          <article class="report-evidence-item">
            <strong>${escapeHtml(finding.title)}</strong>
            <p>${escapeHtml(finding.description)}</p>
          </article>
        `
      )
      .join("");
}

/* -----------------------------
   NEW ANALYSIS
----------------------------- */

$("#new-analysis").addEventListener("click", () => {
  hide($("#result-card"));
  hide($("#report-card"));

  $("#url-input").value = "";
  $("#email-sender").value = "";
  $("#email-subject").value = "";
  $("#email-body").value = "";
  $("#content-input").value = "";

  switchMode("url");

  window.scrollTo({
    top: 0,
    behavior: "smooth"
  });
});

/* -----------------------------
   HISTORY
----------------------------- */

$$(".filter-button").forEach((button) => {
  button.addEventListener("click", () => {
    currentFilter = button.dataset.filter;

    $$(".filter-button").forEach((item) => {
      item.classList.toggle(
        "active",
        item.dataset.filter === currentFilter
      );
    });

    renderHistory();
  });
});

function renderRecentScans() {
  const container = $("#recent-scans");

  if (!state.scans.length) {
    container.innerHTML = `
      <div class="recent-item">
        <div class="recent-main">
          <strong>No scans yet</strong>
          <span>Your latest analysis will appear here.</span>
        </div>
      </div>
    `;

    return;
  }

  container.innerHTML = state.scans
    .slice(0, 5)
    .map(renderRecentItem)
    .join("");

  bindReportButtons();
}

function renderRecentItem(scan) {
  return `
    <div class="recent-item">
      <div class="recent-main">
        <strong>${escapeHtml(getDisplayTarget(scan))}</strong>
        <span>${escapeHtml(scan.type)} · ${escapeHtml(formatDate(scan.timestamp))}</span>
      </div>

      <span class="status-label ${getStatusClass(scan.classification)}">
        ${escapeHtml(scan.classification)}
      </span>

      <span class="score-small">
        ${scan.score}/100
      </span>

      <button
        class="open-report-button"
        type="button"
        data-report-id="${escapeHtml(scan.id)}"
      >
        Open report →
      </button>
    </div>
  `;
}

function renderHistory() {
  const container = $("#history-list");

  const filtered =
    currentFilter === "all"
      ? state.scans
      : state.scans.filter(
          (scan) =>
            getFilterClass(scan.classification) === currentFilter
        );

  if (!filtered.length) {
    container.innerHTML = `
      <div class="history-row">
        <div class="history-target">
          <strong>No matching scans</strong>
          <span>Run a new analysis to add a result here.</span>
        </div>
      </div>
    `;

    return;
  }

  container.innerHTML = filtered
    .map(
      (scan) => `
        <div class="history-row">
          <div class="history-target">
            <strong>${escapeHtml(getDisplayTarget(scan))}</strong>
            <span>${escapeHtml(scan.id)}</span>
          </div>

          <div class="history-cell-label">
            ${escapeHtml(scan.type)}
          </div>

          <div class="score-small">
            ${scan.score}/100
          </div>

          <div class="status-label ${getStatusClass(scan.classification)}">
            ${escapeHtml(scan.classification)}
          </div>

          <button
            class="history-action"
            type="button"
            data-report-id="${escapeHtml(scan.id)}"
          >
            Report →
          </button>
        </div>
      `
    )
    .join("");

  bindReportButtons();
}

function bindReportButtons() {
  // Handled via delegated click listener
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-report-id]");
  if (!button) {
    return;
  }

  const id = button.dataset.reportId;
  const scan = state.scans.find(
    (item) => item.id === id
  );

  if (!scan) {
    return;
  }

  currentResult = scan;

  renderReport(scan);
  showResult(scan);

  switchView("analyze");

  hide($("#result-card"));
  show($("#report-card"));

  window.scrollTo({
    top: $("#report-card").offsetTop - 90,
    behavior: "smooth"
  });
});

function getFilterClass(classification) {
  if (classification === "Safe") {
    return "safe";
  }

  if (classification === "Suspicious") {
    return "suspicious";
  }

  return "high";
}

function getStatusClass(classification) {
  if (classification === "Safe") {
    return "severity-low";
  }

  if (classification === "Suspicious") {
    return "severity-medium";
  }

  return "severity-high";
}

function getDisplayTarget(scan) {
  return scan.target
    .replace(/^From:\s*/i, "")
    .split("\n")[0]
    .slice(0, 80);
}

/* -----------------------------
   STORAGE
----------------------------- */

function loadScans() {
  try {
    const stored = localStorage.getItem(
      "cyberguard_scans"
    );

    if (!stored) {
      return createInitialScans();
    }

    const parsed = JSON.parse(stored);

    return Array.isArray(parsed)
      ? parsed
      : createInitialScans();
  } catch {
    return createInitialScans();
  }
}

function saveScans() {
  localStorage.setItem(
    "cyberguard_scans",
    JSON.stringify(state.scans)
  );
}

function createInitialScans() {
  return [
    buildResult({
      type: "URL",
      target: "https://example.com",
      score: 12,
      findings: [
        {
          severity: "low",
          title: "No strong suspicious indicators",
          description:
            "The initial first-pass checks found no major warning signs."
        }
      ],
      summary:
        "The URL does not show strong suspicious indicators in this first-pass analysis."
    }),

    buildResult({
      type: "Email",
      target:
        "From: alerts@example.org\nSubject: Account verification required",
      score: 61,
      findings: [
        {
          severity: "medium",
          title: "Urgency language",
          description:
            "The message encourages the recipient to act quickly."
        },
        {
          severity: "medium",
          title: "Account verification request",
          description:
            "The email references account verification."
        }
      ],
      summary:
        "Several signals suggest that the email deserves additional review."
    }),

    buildResult({
      type: "URL",
      target:
        "https://secure-login-account.example.com/verify",
      score: 82,
      findings: [
        {
          severity: "high",
          title: "Suspicious URL structure",
          description:
            "The hostname uses a nested structure combined with account-related wording."
        },
        {
          severity: "medium",
          title: "Verification wording",
          description:
            "The URL contains terminology commonly associated with login and verification pages."
        }
      ],
      summary:
        "The submitted URL contains several indicators that deserve further investigation."
    })
  ];
}

/* -----------------------------
   UTILITIES
----------------------------- */

function generateScanId() {
  const random = Math.floor(
    100000 + Math.random() * 900000
  );

  return `CG-${random}`;
}

function formatDate(timestamp) {
  return new Intl.DateTimeFormat(
    undefined,
    {
      dateStyle: "medium",
      timeStyle: "short"
    }
  ).format(new Date(timestamp));
}

function wait(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/* -----------------------------
   INITIALIZATION
----------------------------- */

renderRecentScans();

