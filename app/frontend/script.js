/* ==============================================================================
   CYBERGUARD Frontend — State-Driven, Asynchronous Network Architecture
   ==============================================================================
   - Renders from state, never from a response
   - Handlers dispatch to scheduler, never await network
   - Single scheduler owns concurrency (max 3), timeouts (15s), abort signals
   - Backpressured polling via setTimeout (zero setInterval)
   - Incremental row updates via Map<id, HTMLElement> (zero innerHTML list wipes)
   - Zero frontend URL parsing/validation (sends raw data to backend)
   - Idempotent submission via crypto.randomUUID() & Idempotency-Key
   - Connection state awareness: Online / Reconnecting / Offline
   ============================================================================== */

/* -----------------------------
   API CONFIGURATION
----------------------------- */
function getApiBaseUrl() {
  const custom = localStorage.getItem("cyberguard_api_url");
  if (custom) return custom.replace(/\/+$/, "");
  if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
    return window.location.port === "8000" ? window.location.origin : "http://localhost:8000";
  }
  if (window.location.origin && !window.location.hostname.endsWith("github.io")) {
    return window.location.origin;
  }
  return "https://possibility-eyed-already-douglas.trycloudflare.com";
}

const API_BASE_URL = getApiBaseUrl();

/* -----------------------------
   DOM SELECTORS & HELPERS
----------------------------- */
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function show(element) {
  if (element) element.classList.remove("hidden");
}

function hide(element) {
  if (element) element.classList.add("hidden");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatDate(timestamp) {
  if (!timestamp) return "Just now";
  try {
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "short"
    }).format(new Date(timestamp));
  } catch (err) {
    console.warn("[formatDate] Could not format timestamp:", timestamp, err);
    return "Recent";
  }
}

function getScoreCaption(score) {
  if (score >= 70) return "High Risk — Immediate Attention";
  if (score >= 40) return "Suspicious — Further Review Recommended";
  return "Low Risk — Routine Security Vigilance";
}

function getRiskColor(classification) {
  const c = String(classification || "").toLowerCase();
  if (c.includes("safe") || c.includes("low")) return "var(--safe, #10b981)";
  if (c.includes("suspicious") || c.includes("medium")) return "var(--warning, #f59e0b)";
  if (c.includes("queued") || c.includes("processing")) return "var(--accent, #6366f1)";
  return "var(--high, #ef4444)";
}

function getStatusClass(classification) {
  const c = String(classification || "").toLowerCase();
  if (c.includes("safe") || c.includes("low")) return "severity-low";
  if (c.includes("suspicious") || c.includes("medium")) return "severity-medium";
  if (c.includes("queued") || c.includes("processing")) return "severity-low";
  return "severity-high";
}

function getFilterClass(classification) {
  const c = String(classification || "").toLowerCase();
  if (c.includes("safe")) return "safe";
  if (c.includes("suspicious")) return "suspicious";
  return "high";
}

function getDisplayTarget(scan) {
  if (!scan || !scan.target) return "Unknown target";
  return String(scan.target)
    .replace(/^From:\s*/i, "")
    .split("\n")[0]
    .slice(0, 80);
}

/* -----------------------------
   CENTRAL STORE & STATE
----------------------------- */
function loadScansFromStorage() {
  try {
    const raw = localStorage.getItem("cyberguard_scans");
    if (!raw) return createInitialScans();
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) && parsed.length ? parsed : createInitialScans();
  } catch (err) {
    console.warn("[storage] Error parsing stored scans from localStorage:", err);
    return createInitialScans();
  }
}

function createInitialScans() {
  return [
    {
      id: "CG-INIT001",
      type: "URL",
      target: "https://example.com",
      status: "completed",
      score: 12,
      classification: "Safe",
      summary: "The URL does not show strong suspicious indicators in baseline analysis.",
      findings: [
        {
          severity: "low",
          title: "Clean Structural Inspection",
          description: "First-pass deterministic URL inspection found no overt structural red flags."
        }
      ],
      signals: [
        { name: "Pattern analysis", value: 12 },
        { name: "Content indicators", value: 10 },
        { name: "Risk aggregation", value: 12 }
      ],
      explanation: "No malicious indicators were triggered during deterministic inspection.",
      report_text: "1. What was analyzed\nInput type: URL\nTarget: https://example.com\n\n2. Verdict\nSafe (12/100)",
      report_generated_by: "template",
      timestamp: new Date().toISOString()
    }
  ];
}

const store = {
  scans: loadScansFromStorage(),
  activeScanId: null,
  currentMode: "url",
  currentView: "analyze",
  currentFilter: "all",
  connection: navigator.onLine ? "online" : "offline",
  error: null
};

// If there are existing scans, default the active scan to the most recent one
if (store.scans.length > 0) {
  store.activeScanId = store.scans[0].id;
}

function updateStore(mutationFn) {
  mutationFn(store);
  try {
    localStorage.setItem("cyberguard_scans", JSON.stringify(store.scans.slice(0, 50)));
  } catch (err) {
    console.warn("[updateStore] Error saving scans to localStorage:", err);
  }
  render();
}

/* -----------------------------
   NETWORK SCHEDULER
   - Global concurrency cap (3)
   - Per-request timeout via AbortController (15s)
   - Exponential backoff on transient failure
   - Cancellation on visibilitychange/navigation
----------------------------- */
class NetworkScheduler {
  constructor(concurrency = 3, defaultTimeoutMs = 15000) {
    this.concurrency = concurrency;
    this.defaultTimeoutMs = defaultTimeoutMs;
    this.queue = [];
    this.activeCount = 0;
    this.activeControllers = new Set();
    this.failureStreak = 0;
  }

  enqueue(taskFn, { priority = 0, signal = null, timeout = this.defaultTimeoutMs } = {}) {
    return new Promise((resolve, reject) => {
      this.queue.push({
        taskFn,
        priority,
        signal,
        timeout,
        resolve,
        reject,
        retries: 0
      });
      this.queue.sort((a, b) => b.priority - a.priority);
      this.pump();
    });
  }

  pump() {
    if (this.activeCount >= this.concurrency || this.queue.length === 0) {
      return;
    }

    const item = this.queue.shift();
    this.activeCount++;

    const controller = new AbortController();
    this.activeControllers.add(controller);

    const timeoutId = setTimeout(() => {
      controller.abort("Request timeout");
    }, item.timeout);

    if (item.signal) {
      item.signal.addEventListener("abort", () => controller.abort(item.signal.reason), { once: true });
    }

    item.taskFn(controller.signal)
      .then((result) => {
        clearTimeout(timeoutId);
        this.failureStreak = 0;
        if (store.connection !== "online" && navigator.onLine) {
          updateStore((s) => { s.connection = "online"; });
        }
        item.resolve(result);
      })
      .catch((error) => {
        clearTimeout(timeoutId);
        const isAbort = controller.signal.aborted;

        if (!isAbort && item.retries < 2 && navigator.onLine) {
          item.retries++;
          this.failureStreak++;
          if (this.failureStreak >= 2) {
            updateStore((s) => { s.connection = "reconnecting"; });
          }
          const backoffDelay = Math.min(1000 * Math.pow(2, item.retries), 10000);
          setTimeout(() => {
            this.queue.unshift(item);
            this.pump();
          }, backoffDelay);
        } else {
          if (!isAbort && !navigator.onLine) {
            updateStore((s) => { s.connection = "offline"; });
          }
          item.reject(error);
        }
      })
      .finally(() => {
        this.activeControllers.delete(controller);
        this.activeCount--;
        this.pump();
      });

    this.pump();
  }

  cancelAll(reason = "Scheduler cancellation") {
    for (const controller of this.activeControllers) {
      try {
        controller.abort(reason);
      } catch (err) {
        console.warn("[scheduler] Error aborting controller:", err);
      }
    }
    this.activeControllers.clear();
    while (this.queue.length > 0) {
      const item = this.queue.shift();
      item.reject(new DOMException("Cancelled by scheduler", "AbortError"));
    }
    this.activeCount = 0;
  }
}

const scheduler = new NetworkScheduler(3, 15000);

/* -----------------------------
   BACKPRESSURED POLLING LOOP
   - Single poll loop using setTimeout
   - Polls queued/processing scans
   - Drops terminal scans permanently
   - Widens interval & flips connection on repeated errors
----------------------------- */
let pollTimerId = null;
let pollIntervalMs = 2000;
let consecutivePollFailures = 0;
let isPollLoopRunning = false;

function scheduleNextPoll(delay = pollIntervalMs) {
  if (pollTimerId) clearTimeout(pollTimerId);
  pollTimerId = setTimeout(runPollIteration, delay);
}

async function runPollIteration() {
  if (isPollLoopRunning) return;
  isPollLoopRunning = true;

  try {
    const pendingScans = store.scans.filter(
      (s) => s.status === "queued" || s.status === "processing"
    );

    const activeScan = store.scans.find((s) => s.id === store.activeScanId);
    const needNarrative =
      activeScan &&
      activeScan.status === "completed" &&
      activeScan.report_generated_by === "template" &&
      (activeScan._narrativePollAttempts || 0) < 10;

    if (pendingScans.length === 0 && !needNarrative) {
      pollIntervalMs = 2000;
      isPollLoopRunning = false;
      return;
    }

    const scansToPoll = [...pendingScans];
    if (needNarrative && !scansToPoll.some((s) => s.id === activeScan.id)) {
      scansToPoll.push(activeScan);
    }

    for (const scan of scansToPoll) {
      try {
        const updated = await scheduler.enqueue(
          (signal) =>
            fetch(`${API_BASE_URL}/api/v1/scans/${encodeURIComponent(scan.id)}`, { signal }).then(
              (r) => {
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                return r.json();
              }
            ),
          { priority: 1, timeout: 10000 }
        );

        consecutivePollFailures = 0;
        pollIntervalMs = 2000;
        if (store.connection !== "online" && navigator.onLine) {
          updateStore((s) => { s.connection = "online"; });
        }

        updateStore((s) => {
          const idx = s.scans.findIndex((item) => item.id === scan.id);
          if (idx !== -1) {
            const prev = s.scans[idx];
            s.scans[idx] = {
              ...prev,
              ...updated,
              _narrativePollAttempts: (prev._narrativePollAttempts || 0) + 1
            };
          }
        });
      } catch (err) {
        if (err.name !== "AbortError") {
          consecutivePollFailures++;
          if (consecutivePollFailures >= 2) {
            pollIntervalMs = Math.min(pollIntervalMs * 1.5, 10000);
            updateStore((s) => { s.connection = "reconnecting"; });
          }
        }
      }
    }
  } finally {
    isPollLoopRunning = false;
    const stillPending = store.scans.some(
      (s) => s.status === "queued" || s.status === "processing"
    );
    const activeScan = store.scans.find((s) => s.id === store.activeScanId);
    const needNarrative =
      activeScan &&
      activeScan.status === "completed" &&
      activeScan.report_generated_by === "template" &&
      (activeScan._narrativePollAttempts || 0) < 10;

    if (stillPending || needNarrative) {
      scheduleNextPoll(pollIntervalMs);
    }
  }
}

/* -----------------------------
   INCREMENTAL DOM RENDERING
   - Maintain Map<id, HTMLElement>
   - Zero innerHTML assignment on list containers
----------------------------- */
const recentRowMap = new Map();
const historyRowMap = new Map();

function updateRecentRowElement(row, scan) {
  row.dataset.scanId = scan.id;

  let main = row.querySelector(".recent-main");
  if (!main) {
    main = document.createElement("div");
    main.className = "recent-main";
    main.innerHTML = `<strong></strong><span></span>`;
    row.appendChild(main);
  }
  const strong = main.querySelector("strong");
  const span = main.querySelector("span");
  if (strong) strong.textContent = getDisplayTarget(scan);
  if (span) span.textContent = `${scan.type} · ${formatDate(scan.timestamp)}`;

  let statusLabel = row.querySelector(".status-label");
  if (!statusLabel) {
    statusLabel = document.createElement("span");
    statusLabel.className = "status-label";
    row.appendChild(statusLabel);
  }
  statusLabel.className = `status-label ${getStatusClass(scan.classification)}`;
  statusLabel.textContent = scan.classification || (scan.status === "processing" ? "Analyzing" : "Queued");

  let scoreSmall = row.querySelector(".score-small");
  if (!scoreSmall) {
    scoreSmall = document.createElement("span");
    scoreSmall.className = "score-small";
    row.appendChild(scoreSmall);
  }
  scoreSmall.textContent = scan.status === "completed" ? `${scan.score}/100` : "—";

  let button = row.querySelector(".open-report-button");
  if (!button) {
    button = document.createElement("button");
    button.className = "open-report-button";
    button.type = "button";
    button.textContent = "Open report →";
    row.appendChild(button);
  }
  button.dataset.reportId = scan.id;
}

function renderRecentScansIncremental() {
  const container = $("#recent-scans");
  if (!container) return;

  const currentScans = store.scans.slice(0, 5);
  if (currentScans.length === 0) {
    if (!container.querySelector(".no-scans-item")) {
      container.innerHTML = `
        <div class="recent-item no-scans-item">
          <div class="recent-main">
            <strong>No scans yet</strong>
            <span>Your latest analysis will appear here.</span>
          </div>
        </div>
      `;
      recentRowMap.clear();
    }
    return;
  }

  const placeholder = container.querySelector(".no-scans-item");
  if (placeholder) placeholder.remove();

  const currentIds = new Set(currentScans.map((s) => s.id));
  for (const [id, element] of recentRowMap.entries()) {
    if (!currentIds.has(id)) {
      element.remove();
      recentRowMap.delete(id);
    }
  }

  currentScans.forEach((scan, index) => {
    let row = recentRowMap.get(scan.id);
    if (!row) {
      row = document.createElement("div");
      row.className = "recent-item";
      recentRowMap.set(scan.id, row);
    }
    updateRecentRowElement(row, scan);

    const childAtIndex = container.children[index];
    if (childAtIndex !== row) {
      container.insertBefore(row, childAtIndex || null);
    }
  });
}

function updateHistoryRowElement(row, scan) {
  row.dataset.scanId = scan.id;

  let targetDiv = row.querySelector(".history-target");
  if (!targetDiv) {
    targetDiv = document.createElement("div");
    targetDiv.className = "history-target";
    targetDiv.innerHTML = `<strong></strong><span></span>`;
    row.appendChild(targetDiv);
  }
  const strong = targetDiv.querySelector("strong");
  const span = targetDiv.querySelector("span");
  if (strong) strong.textContent = getDisplayTarget(scan);
  if (span) span.textContent = scan.id;

  let labelDiv = row.querySelector(".history-cell-label");
  if (!labelDiv) {
    labelDiv = document.createElement("div");
    labelDiv.className = "history-cell-label";
    row.appendChild(labelDiv);
  }
  labelDiv.textContent = scan.type;

  let scoreDiv = row.querySelector(".score-small");
  if (!scoreDiv) {
    scoreDiv = document.createElement("div");
    scoreDiv.className = "score-small";
    row.appendChild(scoreDiv);
  }
  scoreDiv.textContent = scan.status === "completed" ? `${scan.score}/100` : "—";

  let statusDiv = row.querySelector(".status-label");
  if (!statusDiv) {
    statusDiv = document.createElement("div");
    statusDiv.className = "status-label";
    row.appendChild(statusDiv);
  }
  statusDiv.className = `status-label ${getStatusClass(scan.classification)}`;
  statusDiv.textContent = scan.classification || (scan.status === "processing" ? "Analyzing" : "Queued");

  let actionBtn = row.querySelector(".history-action");
  if (!actionBtn) {
    actionBtn = document.createElement("button");
    actionBtn.className = "history-action";
    actionBtn.type = "button";
    actionBtn.textContent = "Report →";
    row.appendChild(actionBtn);
  }
  actionBtn.dataset.reportId = scan.id;
}

function renderHistoryIncremental() {
  const container = $("#history-list");
  if (!container) return;

  const filtered =
    store.currentFilter === "all"
      ? store.scans
      : store.scans.filter(
          (scan) => getFilterClass(scan.classification) === store.currentFilter
        );

  if (!filtered.length) {
    if (!container.querySelector(".no-history-item")) {
      container.innerHTML = `
        <div class="history-row no-history-item">
          <div class="history-target">
            <strong>No matching scans</strong>
            <span>Run a new analysis to add a result here.</span>
          </div>
        </div>
      `;
      historyRowMap.clear();
    }
    return;
  }

  const placeholder = container.querySelector(".no-history-item");
  if (placeholder) placeholder.remove();

  const currentIds = new Set(filtered.map((s) => s.id));
  for (const [id, element] of historyRowMap.entries()) {
    if (!currentIds.has(id)) {
      element.remove();
      historyRowMap.delete(id);
    }
  }

  filtered.forEach((scan, index) => {
    let row = historyRowMap.get(scan.id);
    if (!row) {
      row = document.createElement("div");
      row.className = "history-row";
      historyRowMap.set(scan.id, row);
    }
    updateHistoryRowElement(row, scan);

    const childAtIndex = container.children[index];
    if (childAtIndex !== row) {
      container.insertBefore(row, childAtIndex || null);
    }
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
      <div class="signal-meter">
        <div class="signal-fill" style="width: ${Math.min(100, Math.max(0, signal.value || 0))}%"></div>
      </div>
      <span class="signal-val">${signal.value || 0}%</span>
    </div>
  `;
}

function getSeverityClass(severity) {
  const s = String(severity || "").toLowerCase();
  if (s === "high") return "severity-high";
  if (s === "medium") return "severity-medium";
  return "severity-low";
}

/* -----------------------------
   CENTRAL RENDER FUNCTION
   - Pure function of store state
   - Never awaits a promise to decide what to paint
----------------------------- */
function render() {
  // 1. Connection status pill
  const pillText = $("#connection-text");
  const pillDot = $("#connection-dot");
  if (pillText && pillDot) {
    if (store.connection === "online") {
      pillText.textContent = "Online";
      pillDot.className = "state-dot online";
    } else if (store.connection === "reconnecting") {
      pillText.textContent = "Reconnecting…";
      pillDot.className = "state-dot reconnecting";
    } else {
      pillText.textContent = "Offline";
      pillDot.className = "state-dot offline";
    }
  }

  // 2. Error box
  const errorBox = $("#error-box");
  if (errorBox) {
    if (store.error) {
      errorBox.textContent = store.error;
      show(errorBox);
    } else {
      hide(errorBox);
    }
  }

  // 3. Navigation View
  $$(".view").forEach((v) => v.classList.remove("active-view"));
  $(`#view-${store.currentView}`)?.classList.add("active-view");

  $$(".nav-link").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === store.currentView);
  });

  // 4. Input Mode tabs & panels
  $$(".mode-tab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.mode === store.currentMode);
  });
  $$(".mode-panel").forEach((panel) => panel.classList.remove("active-panel"));
  $(`#panel-${store.currentMode}`)?.classList.add("active-panel");

  // 5. Active Result / Progress Presentation
  const activeScan = store.scans.find((s) => s.id === store.activeScanId);
  const resultCard = $("#result-card");
  const progressCard = $("#progress-card");
  const reportCard = $("#report-card");

  if (!activeScan) {
    hide(progressCard);
    hide(resultCard);
    hide(reportCard);
  } else if (activeScan.status === "queued" || activeScan.status === "processing") {
    // Show non-blocking progress card
    show(progressCard);
    hide(resultCard);
    hide(reportCard);

    const progressTime = $("#progress-time");
    if (progressTime) {
      progressTime.textContent = activeScan.status === "processing" ? "Analyzing" : "Queued";
    }

    // Step indicators
    const steps = $$(".analysis-step");
    steps.forEach((step, idx) => {
      const isCurrent = activeScan.status === "queued" ? idx === 0 : idx === 1;
      step.classList.toggle("current", isCurrent);
      const stateText = step.querySelector(".step-state");
      if (stateText) {
        if (activeScan.status === "queued") {
          stateText.textContent = idx === 0 ? "Queued" : "Waiting";
        } else {
          stateText.textContent = idx === 0 ? "Done" : idx === 1 ? "Working" : "Waiting";
        }
      }
    });
  } else {
    // Terminal state: show result card
    hide(progressCard);
    show(resultCard);

    $("#result-title").textContent =
      activeScan.classification === "Safe"
        ? "No major warning signs found."
        : activeScan.classification === "Suspicious"
          ? "Suspicious activity detected."
          : activeScan.classification === "Failed"
            ? "Scan analysis encountered an error."
            : "High-risk activity detected.";

    $("#result-summary").textContent = activeScan.summary || "";
    $("#result-score").textContent = activeScan.score ?? 0;

    const badge = $("#result-badge");
    if (badge) {
      badge.textContent = activeScan.classification || "Completed";
      badge.className = "risk-badge";
      if (activeScan.classification === "Safe") {
        badge.classList.add("risk-safe");
      } else if (activeScan.classification === "Suspicious") {
        badge.classList.add("risk-suspicious");
      } else {
        badge.classList.add("risk-high");
      }
    }

    const ring = $("#score-ring");
    if (ring) {
      ring.style.setProperty("--score-deg", `${(activeScan.score ?? 0) * 3.6}deg`);
      ring.style.setProperty("--score-color", getRiskColor(activeScan.classification));
    }

    $("#score-caption").textContent = getScoreCaption(activeScan.score ?? 0);

    const findings = activeScan.findings || [];
    $("#finding-count").textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
    $("#findings-list").innerHTML = findings.map(renderFinding).join("");

    const signals = activeScan.signals || [];
    $("#signals-list").innerHTML = signals.map(renderSignal).join("");

    $("#result-id").textContent = activeScan.id;
    $("#result-type").textContent = activeScan.type;
    $("#result-time").textContent = formatDate(activeScan.timestamp);

    const exportBtn = $("#export-report-btn");
    if (exportBtn) {
      exportBtn.classList.toggle("hidden", activeScan.status !== "completed");
    }

    // Update Report view data as well
    renderReportCard(activeScan);
  }

  // 6. Incremental Lists
  renderRecentScansIncremental();
  if (store.currentView === "history") {
    renderHistoryIncremental();
  }
}

function renderReportCard(scan) {
  if (!scan) return;
  $("#report-heading").textContent = `${scan.type} security report`;
  const dot = $("#report-status-dot");
  if (dot) dot.style.background = getRiskColor(scan.classification);
  $("#report-classification").textContent = scan.classification || "";
  $("#report-status-text").textContent = getScoreCaption(scan.score ?? 0);
  $("#report-score").textContent = `${scan.score ?? 0} / 100`;
  $("#report-target").textContent = scan.target || "";
  $("#report-explanation").textContent = scan.explanation || "";
  $("#report-id").textContent = scan.id;
  $("#report-type").textContent = scan.type;
  $("#report-time").textContent = formatDate(scan.timestamp);
  $("#report-classification-2").textContent = scan.classification || "";

  const evidenceEl = $("#report-evidence");
  if (evidenceEl) {
    evidenceEl.innerHTML = (scan.findings || [])
      .map(
        (f) => `
          <article class="report-evidence-item">
            <strong>${escapeHtml(f.title)}</strong>
            <p>${escapeHtml(f.description)}</p>
          </article>
        `
      )
      .join("");
  }

  const narrativeCard = $("#narrative-report-card");
  const narrativeBody = $("#narrative-report-body");
  if (narrativeCard && narrativeBody) {
    if (scan.report_text && scan.report_text.trim()) {
      show(narrativeCard);
      narrativeBody.textContent = scan.report_text.trim();
      const genTag = $("#narrative-generated-by");
      if (genTag) {
        genTag.textContent =
          scan.report_generated_by === "qwen" ? "Qwen AI Narrative" : "Deterministic Template";
      }
    } else {
      hide(narrativeCard);
    }
  }
}

/* -----------------------------
   INPUT COLLECTION
   - Zero parsing / normalization: sends raw string to backend
----------------------------- */
function collectRawInput() {
  if (store.currentMode === "url") {
    return $("#url-input").value;
  }
  if (store.currentMode === "email") {
    return {
      sender: $("#email-sender").value,
      subject: $("#email-subject").value,
      body: $("#email-body").value
    };
  }
  return $("#content-input").value;
}

function isInputNonEmpty(data) {
  if (!data) return false;
  if (typeof data === "string") return data.trim().length > 0;
  if (typeof data === "object") {
    return (
      (data.sender && data.sender.trim().length > 0) ||
      (data.subject && data.subject.trim().length > 0) ||
      (data.body && data.body.trim().length > 0)
    );
  }
  return false;
}

function clearCurrentInput() {
  if (store.currentMode === "url") {
    $("#url-input").value = "";
  } else if (store.currentMode === "email") {
    $("#email-sender").value = "";
    $("#email-subject").value = "";
    $("#email-body").value = "";
  } else {
    $("#content-input").value = "";
  }
}

/* -----------------------------
   EVENT HANDLERS
   - Handlers DISPATCH, do not await network
   - Return synchronously in same frame
----------------------------- */
$("#analyze-button").addEventListener("click", () => {
  const rawInput = collectRawInput();
  if (!isInputNonEmpty(rawInput)) {
    updateStore((s) => {
      s.error = "Please enter data to analyze.";
    });
    return;
  }

  // Idempotency: generate UUID client-side
  const idempotencyKey = crypto.randomUUID();
  const tempId = `CG-${idempotencyKey.slice(0, 8).toUpperCase()}`;

  let displayTarget = "";
  if (typeof rawInput === "string") {
    displayTarget = rawInput.trim();
  } else if (typeof rawInput === "object") {
    displayTarget = `${rawInput.subject || "Email"} (from: ${rawInput.sender || "Unknown"})`;
  }

  // 1. Optimistic scan entry created immediately
  const optimisticScan = {
    id: tempId,
    type: store.currentMode.toUpperCase(),
    target: displayTarget,
    status: "queued",
    score: 0,
    classification: "Queued",
    summary: "Scan queued for multi-engine analysis...",
    findings: [],
    signals: [],
    explanation: "Awaiting worker processing.",
    report_text: "",
    report_generated_by: "",
    timestamp: new Date().toISOString(),
    idempotencyKey: idempotencyKey
  };

  // 2. Store updated optimistically & rendered in first frame
  updateStore((s) => {
    s.error = null;
    s.scans.unshift(optimisticScan);
    s.scans = s.scans.slice(0, 50);
    s.activeScanId = tempId;
  });

  // Clear inputs immediately so user can continue working
  clearCurrentInput();

  // 3. Network task dispatched to scheduler (handler does NOT await)
  scheduler
    .enqueue(
      async (signal) => {
        const payload = {
          input_type: store.currentMode,
          data: rawInput
        };

        const response = await fetch(`${API_BASE_URL}/api/v1/scans`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": idempotencyKey
          },
          body: JSON.stringify(payload),
          signal
        });

        if (!response.ok) {
          throw new Error(`Server returned HTTP ${response.status}`);
        }
        return response.json();
      },
      { priority: 2, timeout: 15000 }
    )
    .then((serverScan) => {
      updateStore((s) => {
        const idx = s.scans.findIndex(
          (item) => item.id === tempId || item.idempotencyKey === idempotencyKey
        );
        if (idx !== -1) {
          s.scans[idx] = { ...s.scans[idx], ...serverScan };
        } else {
          s.scans.unshift(serverScan);
        }
        if (s.activeScanId === tempId) {
          s.activeScanId = serverScan.id;
        }
      });
      scheduleNextPoll(100);
    })
    .catch((err) => {
      if (err.name === "AbortError") return;
      updateStore((s) => {
        const idx = s.scans.findIndex((item) => item.id === tempId);
        if (idx !== -1) {
          s.scans[idx].status = "failed";
          s.scans[idx].classification = "Failed";
          s.scans[idx].summary = "Analysis request failed or timed out. Click to retry.";
        }
        s.error = err.message || "Network request failed.";
      });
    });
});

/* -----------------------------
   NAVIGATION & UI CONTROLS
----------------------------- */
function switchView(viewName) {
  updateStore((s) => {
    s.currentView = viewName;
  });
  window.scrollTo({ top: 0, behavior: "smooth" });
}

$$("[data-view]").forEach((button) => {
  button.addEventListener("click", () => {
    switchView(button.dataset.view);
  });
});

$$(".mode-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    updateStore((s) => {
      s.currentMode = tab.dataset.mode;
      s.error = null;
    });
  });
});

$("#sample-url").addEventListener("click", () => {
  $("#url-input").value = "https://secure-login-account.example.com/verify";
});

$("#new-analysis").addEventListener("click", () => {
  clearCurrentInput();
  updateStore((s) => {
    s.currentMode = "url";
    s.activeScanId = null;
    s.error = null;
  });
  window.scrollTo({ top: 0, behavior: "smooth" });
});

$("#open-report").addEventListener("click", () => {
  const active = store.scans.find((s) => s.id === store.activeScanId);
  if (active) {
    renderReportCard(active);
    hide($("#result-card"));
    show($("#report-card"));
    window.scrollTo({
      top: $("#report-card").offsetTop - 90,
      behavior: "smooth"
    });
  }
});

$("#close-report").addEventListener("click", () => {
  hide($("#report-card"));
  show($("#result-card"));
  window.scrollTo({
    top: $("#result-card").offsetTop - 90,
    behavior: "smooth"
  });
});

// Filter chips in History
$$(".filter-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    $$(".filter-chip").forEach((c) => c.classList.remove("active"));
    chip.classList.add("active");
    updateStore((s) => {
      s.currentFilter = chip.dataset.filter || "all";
    });
  });
});

// Delegated report opener on scan list items
document.addEventListener("click", (event) => {
  const btn = event.target.closest("[data-report-id]");
  if (!btn) return;

  const id = btn.dataset.reportId;
  const scan = store.scans.find((s) => s.id === id);
  if (!scan) return;

  updateStore((s) => {
    s.activeScanId = id;
    s.currentView = "analyze";
  });

  const card = scan.status === "completed" ? $("#result-card") : $("#progress-card");
  if (card) {
    window.scrollTo({
      top: card.offsetTop - 90,
      behavior: "smooth"
    });
  }
});

/* -----------------------------
   REPORT EXPORT
----------------------------- */
function downloadScanReport(scanId) {
  const scan = store.scans.find((s) => s.id === scanId);
  if (!scan) return;

  if (scan.report_text) {
    const blob = new Blob([scan.report_text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cyberguard-report-${scanId}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    return;
  }

  const downloadUrl = `${API_BASE_URL}/api/v1/scans/${encodeURIComponent(scanId)}/report`;
  const a = document.createElement("a");
  a.href = downloadUrl;
  a.download = `cyberguard-report-${scanId}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

$("#export-report-btn")?.addEventListener("click", (e) => {
  e.preventDefault();
  if (store.activeScanId) downloadScanReport(store.activeScanId);
});

$("#export-report-from-card")?.addEventListener("click", (e) => {
  e.preventDefault();
  if (store.activeScanId) downloadScanReport(store.activeScanId);
});

/* -----------------------------
   LIFECYCLE & VISIBILITY HANDLERS
   - Cancel in-flight requests when tab is hidden or closing
   - Resume polling when tab becomes visible or online
----------------------------- */
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    scheduler.cancelAll("Visibility hidden");
  } else {
    scheduleNextPoll(100);
  }
});

window.addEventListener("beforeunload", () => {
  scheduler.cancelAll("Page unload");
});

window.addEventListener("online", () => {
  updateStore((s) => { s.connection = "online"; });
  scheduleNextPoll(100);
});

window.addEventListener("offline", () => {
  updateStore((s) => { s.connection = "offline"; });
});

/* -----------------------------
   HEALTH CHECK (FAIL LOUD)
   - 2-second timeout via AbortController
   - Never silently falls back to mock data
   - Surfaces status & failures in UI pill & error banner
----------------------------- */
async function checkHealth(timeoutMs = 2000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort("Health check timeout (2s exceeded)");
  }, timeoutMs);

  try {
    const res = await fetch(`${API_BASE_URL}/health`, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (!res.ok) {
      throw new Error(`Health check returned HTTP ${res.status}`);
    }
    const data = await res.json();
    console.info("[health_check] Backend reported healthy:", data);
    updateStore((s) => {
      s.health = data.status === "ok" ? "healthy" : "degraded";
      s.connection = "online";
      if (s.error && s.error.startsWith("Backend connection failed")) {
        s.error = null;
      }
    });
    return data;
  } catch (err) {
    clearTimeout(timeoutId);
    const msg = err.name === "AbortError" ? `Health check timed out after ${timeoutMs / 1000}s` : (err.message || "Failed to connect to backend");
    console.error("[health_check] Health check failed loudly:", msg, err);
    updateStore((s) => {
      s.health = "unhealthy";
      s.connection = "offline";
      s.error = `Backend connection failed: ${msg}. System is operating in offline mode.`;
    });
    throw err;
  }
}

/* -----------------------------
   INITIAL STARTUP & HISTORY SYNC
----------------------------- */
// 1. Initial synchronous paint from state
render();

// 2. Immediate health check (fail loud with 2s timeout)
checkHealth(2000).catch((err) => {
  console.warn("[startup] Initial health check detected backend offline:", err.message);
});

// 3. Non-blocking initial history sync via scheduler
scheduler
  .enqueue(
    (signal) =>
      fetch(`${API_BASE_URL}/api/v1/scans`, { signal }).then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      }),
    { priority: 0, timeout: 8000 }
  )
  .then((serverScans) => {
    if (Array.isArray(serverScans) && serverScans.length) {
      updateStore((s) => {
        const ids = new Set(serverScans.map((item) => item.id));
        const localRemaining = s.scans.filter((item) => !ids.has(item.id));
        s.scans = [...serverScans, ...localRemaining].slice(0, 50);
        if (!s.activeScanId && s.scans.length) {
          s.activeScanId = s.scans[0].id;
        }
      });
      // Start polling if any server scan is queued or processing
      scheduleNextPoll(500);
    }
  })
  .catch((err) => {
    console.error("[history_sync] Failed to load history from backend:", err);
    updateStore((s) => {
      if (!s.error) {
        s.error = `Unable to load scan history: ${err.message || "Network error"}`;
      }
    });
  });
