/* ==============================================================================
   CYBERGUARD Frontend — Render Layer (Single Source of Truth)
   ==============================================================================
   - Single render() reads store and updates DOM incrementally
   - Never assigns innerHTML on scan list containers
   - Maintains Map<id, HTMLElement> of rendered rows
   ============================================================================== */

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
window.$ = $;
window.$$ = $$;

function show(element) {
  if (element) element.classList.remove("hidden");
}
window.show = show;

function hide(element) {
  if (element) element.classList.add("hidden");
}
window.hide = hide;

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
  if (score >= 81) return "Critical — Emergency Containment Required";
  if (score >= 61) return "High Risk — Immediate Action Recommended";
  if (score >= 41) return "Medium Risk — Suspicious Anomalies Detected";
  if (score >= 21) return "Low Risk — Minor Informational Indicators";
  return "Safe — Baseline Security Verified";
}

function getRiskColor(classification) {
  const c = String(classification || "").toLowerCase();
  if (c.includes("critical")) return "var(--critical, #ef4444)";
  if (c.includes("high")) return "var(--high, #f97316)";
  if (c.includes("medium") || c.includes("suspicious")) return "var(--warning, #f59e0b)";
  if (c.includes("low")) return "var(--low, #14b8a6)";
  if (c.includes("queued") || c.includes("processing")) return "var(--accent, #6366f1)";
  return "var(--safe, #10b981)";
}

function getStatusClass(classification) {
  const c = String(classification || "").toLowerCase();
  if (c.includes("critical")) return "severity-critical";
  if (c.includes("high")) return "severity-high";
  if (c.includes("medium") || c.includes("suspicious")) return "severity-medium";
  if (c.includes("low")) return "severity-low";
  if (c.includes("queued") || c.includes("processing")) return "severity-low";
  return "severity-safe";
}

function getFilterClass(classification) {
  const c = String(classification || "").toLowerCase();
  if (c.includes("critical")) return "critical";
  if (c.includes("high")) return "high";
  if (c.includes("medium") || c.includes("suspicious")) return "medium";
  if (c.includes("low")) return "low";
  return "safe";
}

function getDisplayTarget(scan) {
  if (!scan || !scan.target) return "Unknown target";
  return String(scan.target)
    .replace(/^From:\s*/i, "")
    .split("\n")[0]
    .slice(0, 80);
}

function getSeverityClass(severity) {
  const s = String(severity || "").toLowerCase();
  if (s === "high") return "severity-high";
  if (s === "medium") return "severity-medium";
  return "severity-low";
}

/* -----------------------------
   ROW MAPS (INCREMENTAL DOM)
----------------------------- */
const recentRowMap = new Map();
const historyRowMap = new Map();

function updateRowIdInPlace(oldId, newScan) {
  if (recentRowMap.has(oldId)) {
    const el = recentRowMap.get(oldId);
    recentRowMap.delete(oldId);
    recentRowMap.set(newScan.id, el);
    updateRecentRowElement(el, newScan);
  }
  if (historyRowMap.has(oldId)) {
    const el = historyRowMap.get(oldId);
    historyRowMap.delete(oldId);
    historyRowMap.set(newScan.id, el);
    updateHistoryRowElement(el, newScan);
  }
}
window.updateRowIdInPlace = updateRowIdInPlace;


function updateRecentRowElement(row, scan) {
  row.dataset.scanId = scan.id;

  let main = row.querySelector(".recent-main");
  if (!main) {
    main = document.createElement("div");
    main.className = "recent-main";
    const strong = document.createElement("strong");
    const span = document.createElement("span");
    main.appendChild(strong);
    main.appendChild(span);
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

function renderRecentScansIncremental(scanList) {
  const container = $("#recent-scans");
  if (!container) return;

  const currentScans = scanList.slice(0, 5);
  if (currentScans.length === 0) {
    if (!container.querySelector(".no-scans-item")) {
      const emptyDiv = document.createElement("div");
      emptyDiv.className = "recent-item no-scans-item";
      const main = document.createElement("div");
      main.className = "recent-main";
      const strong = document.createElement("strong");
      strong.textContent = "No scans yet";
      const span = document.createElement("span");
      span.textContent = "Your latest analysis will appear here.";
      main.appendChild(strong);
      main.appendChild(span);
      emptyDiv.appendChild(main);
      container.replaceChildren(emptyDiv);
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
    const strong = document.createElement("strong");
    const span = document.createElement("span");
    targetDiv.appendChild(strong);
    targetDiv.appendChild(span);
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

function renderHistoryIncremental(scanList, currentFilter) {
  const container = $("#history-list");
  if (!container) return;

  const filtered =
    currentFilter === "all"
      ? scanList
      : scanList.filter(
          (scan) => getFilterClass(scan.classification) === currentFilter
        );

  if (!filtered.length) {
    if (!container.querySelector(".no-history-item")) {
      const emptyDiv = document.createElement("div");
      emptyDiv.className = "history-row no-history-item";
      const targetDiv = document.createElement("div");
      targetDiv.className = "history-target";
      const strong = document.createElement("strong");
      strong.textContent = "No matching scans";
      const span = document.createElement("span");
      span.textContent = "Run a new analysis to add a result here.";
      targetDiv.appendChild(strong);
      targetDiv.appendChild(span);
      emptyDiv.appendChild(targetDiv);
      container.replaceChildren(emptyDiv);
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

function createFindingElement(finding) {
  const article = document.createElement("article");
  article.className = "finding";

  const top = document.createElement("div");
  top.className = "finding-top";

  const severitySpan = document.createElement("span");
  severitySpan.className = `finding-severity ${getSeverityClass(finding.severity)}`;
  severitySpan.textContent = finding.severity || "info";
  top.appendChild(severitySpan);
  article.appendChild(top);

  const h4 = document.createElement("h4");
  h4.textContent = finding.title || "Untitled Finding";
  article.appendChild(h4);

  const p = document.createElement("p");
  p.textContent = finding.description || "";
  article.appendChild(p);

  return article;
}

function createSignalElement(signal) {
  const row = document.createElement("div");
  row.className = "signal-row";

  const nameSpan = document.createElement("span");
  nameSpan.className = "signal-name";
  nameSpan.textContent = signal.name || "Signal";
  row.appendChild(nameSpan);

  const meter = document.createElement("div");
  meter.className = "signal-meter";

  const fill = document.createElement("div");
  fill.className = "signal-fill";
  const val = Math.min(100, Math.max(0, Number(signal.value) || 0));
  fill.style.width = `${val}%`;
  meter.appendChild(fill);
  row.appendChild(meter);

  const valSpan = document.createElement("span");
  valSpan.className = "signal-val";
  valSpan.textContent = `${val}%`;
  row.appendChild(valSpan);

  return row;
}

function createEvidenceItemElement(finding) {
  const item = document.createElement("div");
  item.className = "evidence-item";

  const topMeta = document.createElement("div");
  topMeta.className = "evidence-top-meta";

  const typeSpan = document.createElement("span");
  typeSpan.className = "evidence-type-badge";
  typeSpan.textContent = finding.signal_type || finding.category || "heuristic";
  topMeta.appendChild(typeSpan);

  const rightGroup = document.createElement("div");
  rightGroup.style.display = "flex";
  rightGroup.style.alignItems = "center";
  rightGroup.style.gap = "8px";

  const srcTag = document.createElement("span");
  srcTag.className = "evidence-source-tag";
  srcTag.textContent = finding.source || "deterministic";
  rightGroup.appendChild(srcTag);

  const sevPill = document.createElement("span");
  const sev = (finding.severity || "low").toLowerCase();
  sevPill.className = `dash-sev-pill ${
    sev === "critical"
      ? "pill-critical"
      : sev === "high"
      ? "pill-high"
      : sev === "medium"
      ? "pill-medium"
      : "pill-safe"
  }`;
  sevPill.textContent = (finding.severity || "low").toUpperCase();
  rightGroup.appendChild(sevPill);

  topMeta.appendChild(rightGroup);
  item.appendChild(topMeta);

  // Title and description
  const title = document.createElement("strong");
  title.style.fontSize = "0.9rem";
  title.style.color = "#f8fafc";
  title.textContent = finding.title;
  item.appendChild(title);

  if (finding.description) {
    const desc = document.createElement("p");
    desc.style.fontSize = "0.82rem";
    desc.style.color = "#94a3b8";
    desc.style.margin = "0";
    desc.textContent = finding.description;
    item.appendChild(desc);
  }

  // Weight progress bar
  const weightVal = Number(finding.weight || 0);
  const weightRow = document.createElement("div");
  weightRow.className = "evidence-weight-row";

  const weightMeta = document.createElement("div");
  weightMeta.className = "evidence-weight-meta";
  weightMeta.innerHTML = `<span>Risk Score Contribution</span><strong>+${weightVal} pts</strong>`;
  weightRow.appendChild(weightMeta);

  const barBg = document.createElement("div");
  barBg.className = "evidence-bar-bg";
  const barFill = document.createElement("div");
  barFill.className = "evidence-bar-fill";
  const pct = Math.min(100, Math.max(8, Math.round((weightVal / 45) * 100)));
  barFill.style.width = `${pct}%`;
  barBg.appendChild(barFill);
  weightRow.appendChild(barBg);
  item.appendChild(weightRow);

  // Triggered Evidence text
  if (finding.evidence) {
    const evBlock = document.createElement("div");
    evBlock.style.display = "flex";
    evBlock.style.flexDirection = "column";
    evBlock.style.gap = "4px";

    const evLabel = document.createElement("span");
    evLabel.style.fontSize = "0.72rem";
    evLabel.style.fontWeight = "600";
    evLabel.style.color = "#64748b";
    evLabel.style.textTransform = "uppercase";
    evLabel.textContent = "Triggering Evidence Input";
    evBlock.appendChild(evLabel);

    const evCode = document.createElement("div");
    evCode.className = "evidence-snippet";
    evCode.textContent = finding.evidence;
    evBlock.appendChild(evCode);

    item.appendChild(evBlock);
  }

  return item;
}

function renderReportCard(scan) {
  if (!scan) return;
  const targetElem = $("#report-target");
  if (targetElem) targetElem.textContent = scan.target || "N/A";

  const typeElem = $("#report-type");
  if (typeElem) typeElem.textContent = scan.type || "N/A";

  const timeElem = $("#report-timestamp");
  if (timeElem) timeElem.textContent = formatDate(scan.timestamp);

  const scoreElem = $("#report-score");
  if (scoreElem) scoreElem.textContent = `${scan.score ?? 0}/100`;

  const classElem = $("#report-classification");
  if (classElem) {
    classElem.textContent = scan.classification || "Unknown";
    classElem.className = `status-label ${getStatusClass(scan.classification)}`;
  }

  const modelBadge = $("#report-model-badge");
  if (modelBadge) {
    if (scan.report_generated_by === "qwen") {
      modelBadge.textContent = "AI Narrative (Qwen System 2 GPU)";
      modelBadge.className = "report-badge ai-badge";
    } else {
      modelBadge.textContent = "Deterministic Template Report";
      modelBadge.className = "report-badge template-badge";
    }
  }

  const contentElem = $("#report-content");
  if (contentElem) {
    contentElem.textContent = scan.report_text || "Report pending or unavailable.";
  }
}

/* -----------------------------
   CENTRAL RENDER FUNCTION
   - Pure function of store state
   - Reads store, updates DOM incrementally
   - Never assigns innerHTML on the full scan list
----------------------------- */
function render() {
  const currentStore = window.store ? window.store.state : state;
  const scansArray = Array.from(currentStore.scans.values());

  // 1. Connection status pill
  const pillText = $("#connection-text");
  const pillDot = $("#connection-dot");
  const retryBtn = $("#connection-retry-btn");
  if (pillText && pillDot) {
    if (currentStore.connection === "online") {
      if (currentStore.health === "degraded") {
        pillText.textContent = "Degraded";
        pillDot.className = "state-dot reconnecting";
      } else {
        pillText.textContent = "Online";
        pillDot.className = "state-dot online";
      }
      if (retryBtn) retryBtn.style.display = "none";
    } else if (currentStore.connection === "reconnecting") {
      pillText.textContent = "Reconnecting…";
      pillDot.className = "state-dot reconnecting";
      if (retryBtn) retryBtn.style.display = "none";
    } else {
      pillText.textContent = "Offline";
      pillDot.className = "state-dot offline";
      if (retryBtn) retryBtn.style.display = "inline-flex";
    }
  }

  // 2. Error box
  const errorBox = $("#error-box");
  if (errorBox) {
    if (currentStore.error) {
      errorBox.textContent = currentStore.error;
      show(errorBox);
    } else {
      hide(errorBox);
    }
  }

  // 3. Navigation View
  $$(".view").forEach((v) => v.classList.remove("active-view"));
  $(`#view-${currentStore.currentView}`)?.classList.add("active-view");

  $$(".nav-link").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === currentStore.currentView);
  });

  // 4. Input Mode tabs & panels
  $$(".mode-tab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.mode === currentStore.currentMode);
  });
  $$(".mode-panel").forEach((panel) => panel.classList.remove("active-panel"));
  $(`#panel-${currentStore.currentMode}`)?.classList.add("active-panel");

  // 5. Active Result / Progress Presentation
  const activeScan = currentStore.scans.get(currentStore.activeScanId);
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

    const classification = activeScan.classification || "Safe";
    $("#result-title").textContent =
      classification === "Critical"
        ? "Critical security threat detected."
        : classification === "High"
          ? "High-risk activity detected."
          : classification === "Medium" || classification === "Suspicious"
            ? "Suspicious anomalies detected."
            : classification === "Low"
              ? "Low risk: minor indicators noted."
              : classification === "Failed"
                ? "Scan analysis encountered an error."
                : "No major warning signs found.";

    $("#result-summary").textContent = activeScan.summary || "";
    $("#result-score").textContent = activeScan.score ?? 0;

    const badge = $("#result-badge");
    if (badge) {
      badge.textContent = classification || "Completed";
      badge.className = "risk-badge";
      if (classification === "Critical") {
        badge.classList.add("risk-critical");
      } else if (classification === "High" || classification === "High Risk") {
        badge.classList.add("risk-high");
      } else if (classification === "Medium" || classification === "Suspicious") {
        badge.classList.add("risk-medium");
      } else if (classification === "Low") {
        badge.classList.add("risk-low");
      } else {
        badge.classList.add("risk-safe");
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
    const findingsList = $("#findings-list");
    if (findingsList) {
      findingsList.replaceChildren(...findings.map(createFindingElement));
    }

    const signals = activeScan.signals || [];
    const signalsList = $("#signals-list");
    if (signalsList) {
      signalsList.replaceChildren(...signals.map(createSignalElement));
    }

    const recActions = activeScan.recommended_actions || [];
    const recCount = $("#recommendations-count");
    if (recCount) {
      recCount.textContent = `${recActions.length} action${recActions.length === 1 ? "" : "s"}`;
    }
    const recList = $("#recommendations-list");
    if (recList) {
      if (recActions.length === 0) {
        const emptyDiv = document.createElement("div");
        emptyDiv.className = "empty-note";
        emptyDiv.textContent = "No containment required; baseline verified.";
        recList.replaceChildren(emptyDiv);
      } else {
        recList.replaceChildren(
          ...recActions.map((action) => {
            const label = document.createElement("label");
            label.className = "recommendation-item";
            const checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.className = "rec-checkbox";
            const text = document.createElement("span");
            text.className = "rec-text";
            text.textContent = action;
            label.appendChild(checkbox);
            label.appendChild(text);
            return label;
          })
        );
      }
    }

    // Evidence panel with weights
    const evidenceList = $("#evidence-panel-content");
    const evidenceCount = $("#evidence-findings-count");
    if (evidenceCount) {
      evidenceCount.textContent = `${findings.length} signal${findings.length === 1 ? "" : "s"}`;
    }
    if (evidenceList) {
      if (findings.length === 0) {
        evidenceList.innerHTML = `<div class="dash-subnote">No signals triggered for this scan.</div>`;
      } else {
        evidenceList.replaceChildren(...findings.map(createEvidenceItemElement));
      }
    }


    const resId = $("#result-id");
    if (resId) resId.textContent = activeScan.id;
    const resType = $("#result-type");
    if (resType) resType.textContent = activeScan.type;
    const resTime = $("#result-time");
    if (resTime) resTime.textContent = formatDate(activeScan.timestamp);

    const explanationEl = $("#result-explanation");
    if (explanationEl) {
      explanationEl.textContent = activeScan.explanation || activeScan.summary || "No specific threat explanation generated.";
    }

    // Report card if open
    if (reportCard && !reportCard.classList.contains("hidden")) {
      renderReportCard(activeScan);
    }
  }

  // 6. Incremental scan lists
  renderRecentScansIncremental(scansArray);
  renderHistoryIncremental(scansArray, currentStore.currentFilter);

  // 7. Command Dashboard
  if (typeof renderCommandDashboard === "function") {
    renderCommandDashboard(scansArray);
  }
}

window.render = render;
window.renderReportCard = renderReportCard;
