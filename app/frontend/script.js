/* ==============================================================================
   CYBERGUARD Frontend — Application Controller & Network Integration
   ==============================================================================
   - Delegates state management to js/store.js (Map<id, Object>)
   - Delegates DOM rendering to js/render.js (incremental Map<id, HTMLElement>)
   - Dispatches requests via NetworkScheduler without awaiting on UI threads
   - Polling loop uses backpressured setTimeout
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
        if (state.connection !== "online" && navigator.onLine) {
          setConnection("online");
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
            setConnection("reconnecting");
          }
          const backoffDelay = Math.min(1000 * Math.pow(2, item.retries), 10000);
          setTimeout(() => {
            this.queue.unshift(item);
            this.pump();
          }, backoffDelay);
        } else {
          if (!isAbort && !navigator.onLine) {
            setConnection("offline");
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
    const scansList = Array.from(state.scans.values());
    const pendingScans = scansList.filter(
      (s) => s.status === "queued" || s.status === "processing"
    );

    const activeScan = state.scans.get(state.activeScanId);
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
        if (state.connection !== "online" && navigator.onLine) {
          setConnection("online");
        }

        setScan({
          ...scan,
          ...updated,
          _narrativePollAttempts: (scan._narrativePollAttempts || 0) + 1
        });
      } catch (err) {
        if (err.name !== "AbortError") {
          consecutivePollFailures++;
          if (consecutivePollFailures >= 2) {
            pollIntervalMs = Math.min(pollIntervalMs * 1.5, 10000);
            setConnection("reconnecting");
          }
        }
      }
    }
  } finally {
    isPollLoopRunning = false;
    const scansList = Array.from(state.scans.values());
    const stillPending = scansList.some(
      (s) => s.status === "queued" || s.status === "processing"
    );
    const activeScan = state.scans.get(state.activeScanId);
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
   FORM INPUT EXTRACTION
----------------------------- */
function getCurrentInputData() {
  switch (state.currentMode) {
    case "url": {
      const val = $("#url-input")?.value?.trim() || "";
      if (!val) throw new Error("Please enter a URL to analyze.");
      return val;
    }
    case "email": {
      const sender = $("#email-sender")?.value?.trim() || "";
      const subject = $("#email-subject")?.value?.trim() || "";
      const body = $("#email-body")?.value?.trim() || "";
      if (!sender && !subject && !body) {
        throw new Error("Please enter email content to analyze.");
      }
      return { sender, subject, body };
    }
    case "content": {
      const val = $("#content-input")?.value?.trim() || "";
      if (!val) throw new Error("Please enter text or message content to inspect.");
      return val;
    }
    default:
      throw new Error("Unknown analysis mode selected.");
  }
}

function clearCurrentInput() {
  const urlIn = $("#url-input");
  if (urlIn) urlIn.value = "";
  const senderIn = $("#email-sender");
  if (senderIn) senderIn.value = "";
  const subjIn = $("#email-subject");
  if (subjIn) subjIn.value = "";
  const bodyIn = $("#email-body");
  if (bodyIn) bodyIn.value = "";
  const contIn = $("#content-input");
  if (contIn) contIn.value = "";
}

/* -----------------------------
   SCAN SUBMIT HANDLER
   - Does NOT await the network
   - Creates optimistic scan row with status "queued"
   - Calls setScan() (triggers render immediately)
   - Button is NEVER disabled: user can submit a second scan while first is running
----------------------------- */
$("#analyze-button").addEventListener("click", () => {
  let rawInput;
  try {
    rawInput = getCurrentInputData();
  } catch (err) {
    setError(err.message);
    return;
  }

  const idempotencyKey = crypto.randomUUID();
  const tempId = "CG-" + Date.now().toString(36).toUpperCase();

  let displayTarget = "Target";
  if (typeof rawInput === "string") {
    displayTarget = rawInput.split("\n")[0].slice(0, 100);
  } else if (typeof rawInput === "object") {
    displayTarget = `${rawInput.subject || "Email"} (from: ${rawInput.sender || "Unknown"})`;
  }

  // 1. Optimistic scan entry created immediately
  const optimisticScan = {
    id: tempId,
    type: state.currentMode.toUpperCase(),
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

  // 2. Add to store optimistically - triggers render() immediately
  setError(null);
  setActiveScan(tempId);
  setScan(optimisticScan);

  // Clear inputs immediately so user can continue working / submit another scan
  clearCurrentInput();

  // 3. Network task dispatched to scheduler (handler does NOT await)
  scheduler
    .enqueue(
      async (signal) => {
        const payload = {
          input_type: state.currentMode,
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
      // In-place update of scan row
      // Remove temp row if ID changed and insert server scan
      if (serverScan.id !== tempId) {
        removeScan(tempId);
      }
      setScan(serverScan);
      if (state.activeScanId === tempId) {
        setActiveScan(serverScan.id);
      }
      scheduleNextPoll(100);
    })
    .catch((err) => {
      if (err.name === "AbortError") return;
      setScan({
        id: tempId,
        status: "failed",
        classification: "Failed",
        summary: "Analysis request failed or timed out. Click to retry."
      });
      setError(err.message || "Network request failed.");
    });
});

/* -----------------------------
   NAVIGATION & UI CONTROLS
----------------------------- */
function switchView(viewName) {
  setCurrentView(viewName);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

$$("[data-view]").forEach((button) => {
  button.addEventListener("click", () => {
    switchView(button.dataset.view);
  });
});

$$(".mode-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    setCurrentMode(tab.dataset.mode);
    setError(null);
  });
});

$("#sample-url")?.addEventListener("click", () => {
  const urlIn = $("#url-input");
  if (urlIn) urlIn.value = "https://secure-login-account.example.com/verify";
});

$("#sample-email")?.addEventListener("click", () => {
  const sender = $("#email-sender");
  const subj = $("#email-subject");
  const body = $("#email-body");
  if (sender) sender.value = "security-alert@paypal-account-notice.com";
  if (subj) subj.value = "Urgent: Your account has been temporarily restricted";
  if (body) body.value = "Dear user,\nPlease verify your identity immediately at http://paypa1-update-login.com to prevent termination.";
});

$("#sample-content")?.addEventListener("click", () => {
  const cont = $("#content-input");
  if (cont) cont.value = "Your wire transfer has been put on hold. Call immediately or click the secure link to release funds: http://wire-transfer-hold.com/auth";
});

$("#new-analysis")?.addEventListener("click", () => {
  clearCurrentInput();
  setCurrentMode("url");
  setActiveScan(null);
  setError(null);
  window.scrollTo({ top: 0, behavior: "smooth" });
});

$("#open-report")?.addEventListener("click", () => {
  const active = state.scans.get(state.activeScanId);
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

$("#close-report")?.addEventListener("click", () => {
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
    setCurrentFilter(chip.dataset.filter || "all");
  });
});

// Delegated report opener on scan list items
document.addEventListener("click", (event) => {
  const btn = event.target.closest("[data-report-id]");
  if (!btn) return;

  const id = btn.dataset.reportId;
  const scan = state.scans.get(id);
  if (!scan) return;

  setActiveScan(id);
  setCurrentView("analyze");

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
  const scan = state.scans.get(scanId);
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
  if (state.activeScanId) downloadScanReport(state.activeScanId);
});

$("#export-report-from-card")?.addEventListener("click", (e) => {
  e.preventDefault();
  if (state.activeScanId) downloadScanReport(state.activeScanId);
});

/* -----------------------------
   LIFECYCLE & VISIBILITY HANDLERS
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
  setConnection("online");
  scheduleNextPoll(100);
});

window.addEventListener("offline", () => {
  setConnection("offline");
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
    setHealth(data.status === "ok" ? "healthy" : "degraded");
    setConnection("online");
    if (state.error && state.error.startsWith("Backend connection failed")) {
      setError(null);
    }
    return data;
  } catch (err) {
    clearTimeout(timeoutId);
    const msg = err.name === "AbortError" ? `Health check timed out after ${timeoutMs / 1000}s` : (err.message || "Failed to connect to backend");
    console.error("[health_check] Health check failed loudly:", msg, err);
    setHealth("unhealthy");
    setConnection("offline");
    setError(`Backend connection failed: ${msg}. System is operating in offline mode.`);
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
      for (const item of serverScans) {
        setScan(item);
      }
      if (!state.activeScanId && serverScans.length) {
        setActiveScan(serverScans[0].id);
      }
      // Start polling if any server scan is queued or processing
      scheduleNextPoll(500);
    }
  })
  .catch((err) => {
    console.error("[history_sync] Failed to load history from backend:", err);
    if (!state.error) {
      setError(`Unable to load scan history: ${err.message || "Network error"}`);
    }
  });
