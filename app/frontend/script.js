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

  const urlParams = new URLSearchParams(window.location.search);
  const paramApi = urlParams.get("api");
  if (paramApi) {
    const clean = paramApi.replace(/\/+$/, "");
    localStorage.setItem("cyberguard_api_url", clean);
    return clean;
  }

  if (
    !window.location.hostname ||
    window.location.protocol === "file:" ||
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1"
  ) {
    return "http://localhost:8000";
  }

  if (window.location.origin && window.location.origin !== "null" && !window.location.hostname.endsWith("github.io")) {
    return window.location.origin;
  }

  return "http://localhost:8000";
}

const API_BASE_URL = getApiBaseUrl();

/* -----------------------------
   CONNECTION STATE MACHINE
   - Online when a request succeeds
   - Reconnecting on first failure
   - Offline after 30 seconds of no successful request
   - Manual Retry button triggers immediate verification
----------------------------- */
let connectionFailureTimestamp = null;
let offlineTransitionTimer = null;

function handleRequestSuccess() {
  connectionFailureTimestamp = null;
  if (offlineTransitionTimer) {
    clearTimeout(offlineTransitionTimer);
    offlineTransitionTimer = null;
  }
  if (state.connection !== "online" && navigator.onLine) {
    setConnection("online");
  }
}

function handleRequestFailure(error) {
  if (!navigator.onLine) {
    setConnection("offline");
    return;
  }
  const now = Date.now();
  if (!connectionFailureTimestamp) {
    connectionFailureTimestamp = now;
  }

  // Transition to Reconnecting on first failure
  if (state.connection === "online") {
    setConnection("reconnecting");
  }

  // Transition to Offline after 30 seconds of no successful request
  if (!offlineTransitionTimer) {
    const elapsed = now - connectionFailureTimestamp;
    const remaining = Math.max(0, 30000 - elapsed);
    offlineTransitionTimer = setTimeout(() => {
      offlineTransitionTimer = null;
      if (connectionFailureTimestamp && (Date.now() - connectionFailureTimestamp >= 30000)) {
        setConnection("offline");
      }
    }, remaining);
  }
}

function formatNetworkError(err, context = "CYBERGUARD backend") {
  if (!navigator.onLine) {
    return "Internet connection is offline.";
  }
  if (err.name === "AbortError") {
    return `Connection to ${context} timed out.`;
  }
  if (err.message && (err.message.startsWith("HTTP ") || err.message.startsWith("Server returned HTTP "))) {
    return `Server error: ${err.message}`;
  }
  return `Cannot reach server at ${API_BASE_URL}. Verify backend service is running.`;
}

async function retryConnection() {
  setConnection("reconnecting");
  connectionFailureTimestamp = Date.now();
  if (offlineTransitionTimer) {
    clearTimeout(offlineTransitionTimer);
    offlineTransitionTimer = null;
  }
  try {
    await checkHealth(3000);
    handleRequestSuccess();
  } catch (err) {
    handleRequestFailure(err);
  }
}

window.handleRequestSuccess = handleRequestSuccess;
window.handleRequestFailure = handleRequestFailure;
window.retryConnection = retryConnection;

/* -----------------------------
   BACKPRESSURED POLLING LOOP
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
        handleRequestSuccess();

        setScan({
          ...scan,
          ...updated,
          _narrativePollAttempts: (scan._narrativePollAttempts || 0) + 1
        });
      } catch (err) {
        if (err.name !== "AbortError") {
          consecutivePollFailures++;
          handleRequestFailure(err);
          if (consecutivePollFailures >= 2) {
            pollIntervalMs = Math.min(pollIntervalMs * 1.5, 10000);
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
    case "identity": {
      const val = $("#identity-input")?.value?.trim() || "";
      if (!val) throw new Error("Please paste email headers to analyze.");
      return val;
    }
    case "logs": {
      const val = $("#logs-input")?.value?.trim() || "";
      if (!val) throw new Error("Please paste authentication or system logs to analyze.");
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
  const identIn = $("#identity-input");
  if (identIn) identIn.value = "";
  const logsIn = $("#logs-input");
  if (logsIn) logsIn.value = "";
}

/* -----------------------------
   SCAN SUBMIT HANDLER
   - Does NOT await the network
   - Creates optimistic scan row with status "queued"
   - Calls setScan() (triggers render immediately)
   - Button is NEVER disabled: user can submit a second scan while first is running
----------------------------- */
let lastSubmissionTime = 0;

$("#analyze-button").addEventListener("click", () => {
  const now = Date.now();
  // Rapid double-click protection (< 400ms): suppress accidental double submit
  if (now - lastSubmissionTime < 400) {
    console.warn("[analyze] Suppressed rapid double-click within 400ms (idempotent submission)");
    return;
  }

  let rawInput;
  try {
    rawInput = getCurrentInputData();
  } catch (err) {
    setError(err.message);
    return;
  }

  lastSubmissionTime = now;
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
          let errDetail = `Server returned HTTP ${response.status}`;
          try {
            const errJson = await response.json();
            if (errJson && errJson.detail) {
              errDetail = typeof errJson.detail === "string" ? errJson.detail : JSON.stringify(errJson.detail);
            }
          } catch (_) {}
          throw new Error(errDetail);
        }
        handleRequestSuccess();
        return response.json();
      },
      { priority: 2, timeout: 15000 }
    )
    .then((serverScan) => {
      // In-place update of scan row: queued row is updated in place with real scan details
      setScan(serverScan, tempId);
      if (state.activeScanId === tempId) {
        setActiveScan(serverScan.id);
      }
      scheduleNextPoll(100);
    })
    .catch((err) => {
      if (err.name === "AbortError") return;
      handleRequestFailure(err);
      setScan({
        id: tempId,
        status: "failed",
        classification: "Failed",
        summary: "Analysis request failed. Click to retry."
      });
      setError(formatNetworkError(err, "CYBERGUARD backend"));
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

$("#sample-identity-spoofed")?.addEventListener("click", () => {
  const ident = $("#identity-input");
  if (ident) {
    ident.value = `Received: from mail.attacker-spoof.net (198.51.100.22) by mx.corp.com
Authentication-Results: mx.corp.com; spf=fail (sender 198.51.100.22 not permitted); dkim=fail; dmarc=fail
From: "Microsoft Security Center" <alert@microsoft-security-verify.com>
Reply-To: phisher@attacker.org
Return-Path: <bounce@unrelated-server.net>
Subject: Critical Security Notice: Verify your Microsoft 365 Account Immediately
Date: Wed, 08 Oct 2026 10:05:00 +0000`;
  }
});

$("#sample-identity-bec")?.addEventListener("click", () => {
  const ident = $("#identity-input");
  if (ident) {
    ident.value = `Received: from mail.legitcorp.com (192.0.2.10) by mx.destination.com
Authentication-Results: mx.destination.com; spf=pass; dkim=pass; dmarc=pass
From: "John Doe - Director of Finance" <john.doe@legitcorp.com>
Reply-To: john.doe.offshore.account@consultant-invoicing.net
Return-Path: <john.doe@legitcorp.com>
Subject: Urgent: Updated Vendor Wire Routing Instructions
Date: Wed, 08 Oct 2026 10:10:00 +0000`;
  }
});

$("#sample-logs-burst")?.addEventListener("click", () => {
  const logs = $("#logs-input");
  if (logs) {
    logs.value = `Jan 15 09:15:01 host sshd[101]: Failed password for admin from 198.51.100.44 port 22 ssh2
Jan 15 09:15:10 host sshd[102]: Failed password for admin from 198.51.100.44 port 22 ssh2
Jan 15 09:15:22 host sshd[103]: Failed password for admin from 198.51.100.44 port 22 ssh2
Jan 15 09:15:35 host sshd[104]: Failed password for admin from 198.51.100.44 port 22 ssh2
Jan 15 09:15:48 host sshd[105]: Failed password for admin from 198.51.100.44 port 22 ssh2
Jan 15 09:16:02 host sshd[106]: Failed password for admin from 198.51.100.44 port 22 ssh2
Jan 15 09:16:15 host sshd[107]: Failed password for admin from 198.51.100.44 port 22 ssh2`;
  }
});

$("#sample-logs-spray")?.addEventListener("click", () => {
  const logs = $("#logs-input");
  if (logs) {
    logs.value = `Jan 15 10:01:00 auth-server sshd[201]: Failed password for alice from 203.0.113.88 port 22 ssh2
Jan 15 10:02:15 auth-server sshd[202]: Failed password for bob from 203.0.113.88 port 22 ssh2
Jan 15 10:03:30 auth-server sshd[203]: Failed password for charlie from 203.0.113.88 port 22 ssh2
Jan 15 10:04:45 auth-server sshd[204]: Failed password for devops from 203.0.113.88 port 22 ssh2
Jan 15 10:05:50 auth-server sshd[205]: Failed password for root from 203.0.113.88 port 22 ssh2`;
  }
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
      throw new Error(`Server returned HTTP ${res.status}`);
    }
    const data = await res.json();
    console.info("[health_check] Backend reported healthy:", data);
    setHealth(data.status === "ok" ? "healthy" : "degraded");
    handleRequestSuccess();
    if (state.error && state.error.includes("Cannot reach server")) {
      setError(null);
    }
    return data;
  } catch (err) {
    clearTimeout(timeoutId);
    handleRequestFailure(err);
    setHealth("unhealthy");
    const msg = formatNetworkError(err, "CYBERGUARD backend");
    console.error("[health_check] Health check failed loudly:", msg, err);
    setError(msg);
    throw err;
  }
}

/* -----------------------------
   INITIAL STARTUP & HISTORY SYNC
----------------------------- */
// 1. Initial synchronous paint from state
render();

// 2. Retry button listener
$("#connection-retry-btn")?.addEventListener("click", (e) => {
  e.preventDefault();
  e.stopPropagation();
  retryConnection();
});

// 3. Immediate health check (fail loud with 2s timeout)
checkHealth(2000).catch((err) => {
  console.warn("[startup] Initial health check detected backend offline:", err.message);
});

// 4. Non-blocking initial history sync via scheduler
scheduler
  .enqueue(
    (signal) =>
      fetch(`${API_BASE_URL}/api/v1/scans`, { signal }).then((r) => {
        if (!r.ok) throw new Error(`Server returned HTTP ${r.status}`);
        return r.json();
      }),
    { priority: 0, timeout: 8000 }
  )
  .then((serverScans) => {
    handleRequestSuccess();
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
    handleRequestFailure(err);
    console.error("[history_sync] Failed to load history from backend:", err);
    if (!state.error) {
      setError(formatNetworkError(err, "CYBERGUARD backend"));
    }
  });
