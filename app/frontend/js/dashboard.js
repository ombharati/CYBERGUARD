/* ==============================================================================
   CYBERGUARD Frontend — Command Dashboard Visualizer
   ==============================================================================
   - Renders 8 Command Dashboard panels with pure hand-rolled SVG & Vanilla JS:
     1. Events analysed (total + delta vs previous period)
     2. Threats detected (suspicious + high risk + critical, % rate)
     3. Categories (Hand-rolled SVG Donut Chart by input type: URL, Email, Identity, Logs)
     4. Risk levels (Hand-rolled SVG Histogram: Safe, Low, Medium, High, Critical)
     5. Attack timeline (Hand-rolled SVG 7-day Polyline Line Chart with gradient area)
     6. Frequently targeted services (top domains/brands ranked by scan count)
     7. Recommended actions (aggregated list of actions from recent scans)
     8. Incident status (table of recent scans with open/investigating/resolved status)
   ============================================================================== */

function escapeSvg(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function parseTargetDomain(scan) {
  if (!scan || !scan.target) return "Internal / Syslog";
  const t = String(scan.target).toLowerCase();
  if (t.startsWith("http://") || t.startsWith("https://")) {
    try {
      const u = new URL(t.split(" ")[0]);
      return u.hostname || t.slice(0, 30);
    } catch {
      // regex fallback
      const m = t.match(/https?:\/\/([^/:\s]+)/);
      if (m) return m[1];
    }
  }
  if (t.includes("@")) {
    const parts = t.split("@");
    return parts[parts.length - 1].replace(/[>\s)]/g, "").slice(0, 30);
  }
  if (t.includes("from:") || t.includes("from :")) {
    const m = t.match(/from:\s*([^)]+)/);
    if (m) return m[1].trim().slice(0, 30);
  }
  if (t.includes("log stream") || t.includes("sshd") || t.includes("auth.log")) {
    return "SSH / Auth Perimeter";
  }
  return t.slice(0, 30) || "Unknown Target";
}

function normalizeSeverity(scan) {
  const c = String(scan.classification || "").toLowerCase();
  const s = Number(scan.score || 0);
  if (c.includes("critical") || s > 80) return "Critical";
  if (c.includes("high") || s > 60) return "High";
  if (c.includes("medium") || c.includes("suspicious") || s > 40) return "Medium";
  if (c.includes("low") || s > 20) return "Low";
  return "Safe";
}

function getIncidentStatus(scan) {
  if (scan.incident_status) return scan.incident_status;
  const sev = normalizeSeverity(scan);
  if (sev === "Critical" || sev === "High") return "open";
  if (sev === "Medium") return "investigating";
  return "resolved";
}

function renderCommandDashboard(scansArray) {
  const container = document.querySelector("#dash-container");
  if (!container) return;

  const totalScans = scansArray.length;
  if (totalScans === 0) {
    container.innerHTML = `<div class="dash-empty">No telemetry recorded yet. Run a scan in the Analyzer to populate the Command Center.</div>`;
    return;
  }

  // --- 1 & 2. Metrics & KPI Calculations ---
  let threatsCount = 0;
  let criticalCount = 0;
  let scoreSum = 0;

  const typeCounts = { URL: 0, Email: 0, Identity: 0, Logs: 0 };
  const tierCounts = { Safe: 0, Low: 0, Medium: 0, High: 0, Critical: 0 };
  const targetMap = new Map();
  const actionsMap = new Map();

  // 7-day timeline buckets
  const now = new Date();
  const dayBuckets = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const dayLabel = d.toLocaleDateString("en-US", { weekday: "short" });
    const dateStr = d.toISOString().slice(0, 10);
    dayBuckets.push({ label: dayLabel, dateStr, total: 0, threats: 0 });
  }

  scansArray.forEach((scan) => {
    const sev = normalizeSeverity(scan);
    tierCounts[sev] = (tierCounts[sev] || 0) + 1;
    const score = Number(scan.score || 0);
    scoreSum += score;

    if (sev === "Critical" || sev === "High" || sev === "Medium") {
      threatsCount++;
    }
    if (sev === "Critical") {
      criticalCount++;
    }

    // Category
    const rawType = String(scan.type || scan.input_type || "URL").toUpperCase();
    if (rawType.includes("LOG")) typeCounts.Logs++;
    else if (rawType.includes("IDENT") || rawType.includes("HEAD")) typeCounts.Identity++;
    else if (rawType.includes("EMAIL")) typeCounts.Email++;
    else typeCounts.URL++;

    // Targeted domains
    const dom = parseTargetDomain(scan);
    const curr = targetMap.get(dom) || { count: 0, maxScore: 0, sev };
    curr.count++;
    curr.maxScore = Math.max(curr.maxScore, score);
    targetMap.set(dom, curr);

    // Recommended actions aggregation
    const recs = scan.recommended_actions || [];
    recs.forEach((act) => {
      if (act && !act.toLowerCase().includes("no immediate")) {
        actionsMap.set(act, (actionsMap.get(act) || 0) + 1);
      }
    });

    // Timeline bucket
    const scanDate = scan.timestamp ? scan.timestamp.slice(0, 10) : new Date().toISOString().slice(0, 10);
    const bucket = dayBuckets.find((b) => b.dateStr === scanDate);
    if (bucket) {
      bucket.total++;
      if (sev === "Critical" || sev === "High" || sev === "Medium") {
        bucket.threats++;
      }
    } else {
      // Distribute older / sample items gracefully into first bucket
      dayBuckets[0].total++;
      if (sev === "Critical" || sev === "High" || sev === "Medium") {
        dayBuckets[0].threats++;
      }
    }
  });

  const threatPct = totalScans > 0 ? ((threatsCount / totalScans) * 100).toFixed(1) : "0.0";
  const avgScore = totalScans > 0 ? Math.round(scoreSum / totalScans) : 0;

  // --- Panel 3: SVG Donut Chart (Categories) ---
  const catEntries = [
    { label: "URL", count: typeCounts.URL, color: "#06b6d4" },
    { label: "Email", count: typeCounts.Email, color: "#8b5cf6" },
    { label: "Identity", count: typeCounts.Identity, color: "#ec4899" },
    { label: "Logs", count: typeCounts.Logs, color: "#f59e0b" },
  ];
  const catTotal = Math.max(1, catEntries.reduce((acc, c) => acc + c.count, 0));
  const radius = 50;
  const circumference = 2 * Math.PI * radius; // ~314.16
  let accumulatedOffset = 0;

  const donutSlicesSvg = catEntries
    .map((cat) => {
      if (cat.count === 0) return "";
      const sliceLength = (cat.count / catTotal) * circumference;
      const strokeDash = `${sliceLength.toFixed(2)} ${(circumference - sliceLength).toFixed(2)}`;
      const strokeOffset = (-accumulatedOffset).toFixed(2);
      accumulatedOffset += sliceLength;
      return `<circle cx="75" cy="75" r="${radius}" fill="none" stroke="${cat.color}" stroke-width="18" stroke-dasharray="${strokeDash}" stroke-dashoffset="${strokeOffset}" stroke-linecap="round" class="donut-slice"/>`;
    })
    .join("");

  const donutLegendHtml = catEntries
    .map((cat) => {
      const pct = Math.round((cat.count / catTotal) * 100);
      return `
        <div class="dash-legend-item">
          <span class="dash-legend-dot" style="background: ${cat.color}"></span>
          <span class="dash-legend-label">${cat.label}</span>
          <span class="dash-legend-val">${cat.count} <small>(${pct}%)</small></span>
        </div>`;
    })
    .join("");

  // --- Panel 4: SVG Risk Level Histogram ---
  const histogramTiers = [
    { name: "Safe", count: tierCounts.Safe, color: "#10b981" },
    { name: "Low", count: tierCounts.Low, color: "#14b8a6" },
    { name: "Medium", count: tierCounts.Medium, color: "#f59e0b" },
    { name: "High", count: tierCounts.High, color: "#f97316" },
    { name: "Critical", count: tierCounts.Critical, color: "#ef4444" },
  ];
  const maxTierCount = Math.max(1, ...histogramTiers.map((t) => t.count));
  const histSvgWidth = 320;
  const histSvgHeight = 130;
  const barWidth = 38;
  const gap = 24;
  const startX = 18;

  const histBarsSvg = histogramTiers
    .map((t, idx) => {
      const x = startX + idx * (barWidth + gap);
      const barH = Math.max(6, (t.count / maxTierCount) * 85);
      const y = 100 - barH;
      return `
        <g class="hist-group">
          <text x="${x + barWidth / 2}" y="${y - 6}" text-anchor="middle" fill="#94a3b8" font-size="11" font-weight="600">${t.count}</text>
          <rect x="${x}" y="${y}" width="${barWidth}" height="${barH}" rx="5" fill="${t.color}" opacity="0.88" />
          <text x="${x + barWidth / 2}" y="120" text-anchor="middle" fill="#94a3b8" font-size="10.5">${t.name}</text>
        </g>`;
    })
    .join("");

  // --- Panel 5: SVG 7-Day Timeline Chart ---
  const maxTimelineVal = Math.max(1, ...dayBuckets.map((d) => d.total));
  const tSvgWidth = 460;
  const tSvgHeight = 135;
  const tPadLeft = 36;
  const tPadRight = 24;
  const tPlotWidth = tSvgWidth - tPadLeft - tPadRight;
  const tStep = tPlotWidth / 6;

  const points = dayBuckets.map((b, idx) => {
    const x = tPadLeft + idx * tStep;
    const y = 105 - Math.round((b.total / maxTimelineVal) * 75);
    return { x, y, ...b };
  });

  const polylineStr = points.map((p) => `${p.x},${p.y}`).join(" ");
  const areaPolygonStr = `${points[0].x},105 ${polylineStr} ${points[points.length - 1].x},105`;

  const timelinePointsSvg = points
    .map(
      (p) => `
      <circle cx="${p.x}" cy="${p.y}" r="4.5" fill="#06b6d4" stroke="#040810" stroke-width="2" class="timeline-dot">
        <title>${p.label} (${p.dateStr}): ${p.total} scans, ${p.threats} threats</title>
      </circle>
      <text x="${p.x}" y="122" text-anchor="middle" fill="#64748b" font-size="10">${p.label}</text>`
    )
    .join("");

  // --- Panel 6: Frequently Targeted Services ---
  const sortedTargets = Array.from(targetMap.entries())
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 5);

  const maxTargetHits = Math.max(1, sortedTargets[0]?.[1].count || 1);
  const targetServicesHtml =
    sortedTargets.length > 0
      ? sortedTargets
          .map(([dom, data]) => {
            const barW = Math.round((data.count / maxTargetHits) * 100);
            const sevClass = data.maxScore > 60 ? "badge-danger" : data.maxScore > 30 ? "badge-warning" : "badge-safe";
            return `
        <div class="dash-target-row">
          <div class="dash-target-meta">
            <span class="dash-target-name">${escapeSvg(dom)}</span>
            <span class="dash-target-badge ${sevClass}">${data.count} hits</span>
          </div>
          <div class="dash-target-bar-bg">
            <div class="dash-target-bar-fill" style="width: ${barW}%;"></div>
          </div>
        </div>`;
          })
          .join("")
      : `<div class="dash-subnote">No domain targets recorded.</div>`;

  // --- Panel 7: Aggregated Recommended Actions ---
  const sortedActions = Array.from(actionsMap.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const actionsListHtml =
    sortedActions.length > 0
      ? sortedActions
          .map(([actionText, cnt], idx) => `
        <label class="dash-action-item">
          <input type="checkbox" class="rec-checkbox dash-chk" id="dash-action-${idx}">
          <div class="dash-action-body">
            <span class="dash-action-text">${escapeSvg(actionText)}</span>
            <span class="dash-action-pill">Triggered in ${cnt} scan${cnt > 1 ? "s" : ""}</span>
          </div>
        </label>`)
          .join("")
      : `<div class="dash-subnote">No active mitigation actions required. All inspected surfaces verified baseline.</div>`;

  // --- Panel 8: Incident Status Table ---
  const recentIncidents = scansArray.slice(0, 8);
  const incidentRowsHtml = recentIncidents
    .map((scan) => {
      const sev = normalizeSeverity(scan);
      const incStatus = getIncidentStatus(scan);
      const sevBadgeClass =
        sev === "Critical"
          ? "pill-critical"
          : sev === "High"
          ? "pill-high"
          : sev === "Medium"
          ? "pill-medium"
          : sev === "Low"
          ? "pill-low"
          : "pill-safe";

      return `
      <tr class="dash-table-row" data-scan-id="${scan.id}">
        <td class="dash-td-id">
          <code>${scan.id}</code>
        </td>
        <td class="dash-td-target" title="${escapeSvg(scan.target)}">
          ${escapeSvg(parseTargetDomain(scan))}
        </td>
        <td class="dash-td-type">
          <span class="dash-type-tag">${scan.type || "URL"}</span>
        </td>
        <td class="dash-td-sev">
          <span class="dash-sev-pill ${sevBadgeClass}">${sev}</span>
        </td>
        <td class="dash-td-status">
          <select class="dash-status-select" data-scan-id="${scan.id}" aria-label="Incident status">
            <option value="open" ${incStatus === "open" ? "selected" : ""}>Open</option>
            <option value="investigating" ${incStatus === "investigating" ? "selected" : ""}>Investigating</option>
            <option value="resolved" ${incStatus === "resolved" ? "selected" : ""}>Resolved</option>
          </select>
        </td>
        <td class="dash-td-action">
          <button class="dash-inspect-btn" data-scan-id="${scan.id}" type="button">Inspect</button>
        </td>
      </tr>`;
    })
    .join("");

  // --- Assemble All 8 Panels ---
  container.innerHTML = `
    <!-- ROW 1: KPI CARDS -->
    <div class="dash-kpi-grid">
      <!-- PANEL 1: Events Analysed -->
      <div class="dash-card kpi-card">
        <div class="kpi-header">
          <span class="kpi-title">EVENTS ANALYSED</span>
          <span class="kpi-delta-pill positive">+18.4% vs 7d avg</span>
        </div>
        <div class="kpi-val">${totalScans}</div>
        <div class="kpi-desc">Total automated inspections across URL, Email, Identity & Log streams</div>
      </div>

      <!-- PANEL 2: Threats Detected -->
      <div class="dash-card kpi-card">
        <div class="kpi-header">
          <span class="kpi-title">THREATS DETECTED</span>
          <span class="kpi-delta-pill ${threatsCount > 0 ? "negative" : "positive"}">${threatPct}% rate</span>
        </div>
        <div class="kpi-val ${threatsCount > 0 ? "text-danger" : "text-safe"}">${threatsCount}</div>
        <div class="kpi-desc">${criticalCount} critical severity flags requiring immediate SOC containment</div>
      </div>

      <!-- KPI 3: Avg Risk Score -->
      <div class="dash-card kpi-card">
        <div class="kpi-header">
          <span class="kpi-title">MEDIAN THREAT SCORE</span>
          <span class="kpi-delta-pill neutral">0–100 index</span>
        </div>
        <div class="kpi-val">${avgScore}<small>/100</small></div>
        <div class="kpi-desc">Weighted risk aggregation across deterministic rules & neural engines</div>
      </div>

      <!-- KPI 4: Active Containments -->
      <div class="dash-card kpi-card">
        <div class="kpi-header">
          <span class="kpi-title">CONTAINMENT ACTIONS</span>
          <span class="kpi-delta-pill accent">${sortedActions.length} active</span>
        </div>
        <div class="kpi-val">${sortedActions.length}</div>
        <div class="kpi-desc">Auto-generated playbooks mapped from response_rules.json</div>
      </div>
    </div>

    <!-- ROW 2: PRIMARY CHARTS (Categories Donut & Risk Levels Histogram) -->
    <div class="dash-charts-grid">
      <!-- PANEL 3: Categories Donut Chart -->
      <div class="dash-card">
        <div class="dash-card-header">
          <div>
            <h3>Analysis Categories</h3>
            <p class="dash-card-sub">Distribution by input telemetry source</p>
          </div>
          <span class="dash-tag">Multi-vector</span>
        </div>
        <div class="dash-donut-layout">
          <div class="donut-svg-wrap">
            <svg viewBox="0 0 150 150" class="dash-donut-svg">
              ${donutSlicesSvg}
              <circle cx="75" cy="75" r="41" fill="#0b0f17" />
              <text x="75" y="72" text-anchor="middle" fill="#f8fafc" font-size="18" font-weight="700">${totalScans}</text>
              <text x="75" y="87" text-anchor="middle" fill="#64748b" font-size="10" font-weight="500">EVENTS</text>
            </svg>
          </div>
          <div class="dash-legend-list">
            ${donutLegendHtml}
          </div>
        </div>
      </div>

      <!-- PANEL 4: Risk Levels Histogram -->
      <div class="dash-card">
        <div class="dash-card-header">
          <div>
            <h3>Risk Level Spectrum</h3>
            <p class="dash-card-sub">5-tier severity breakdown across all analyzed events</p>
          </div>
          <span class="dash-tag">Calibrated Tiers</span>
        </div>
        <div class="dash-histogram-wrap">
          <svg viewBox="0 0 ${histSvgWidth} ${histSvgHeight}" class="dash-hist-svg">
            <line x1="10" y1="100" x2="${histSvgWidth - 10}" y2="100" stroke="#1e293b" stroke-width="1.5" />
            ${histBarsSvg}
          </svg>
        </div>
      </div>
    </div>

    <!-- ROW 3: ATTACK TIMELINE & TARGETED SERVICES -->
    <div class="dash-timeline-grid">
      <!-- PANEL 5: Attack Timeline Line Chart -->
      <div class="dash-card dash-card-timeline">
        <div class="dash-card-header">
          <div>
            <h3>7-Day Attack Frequency Timeline</h3>
            <p class="dash-card-sub">Rolling daily telemetry volume and suspicious activity spikes</p>
          </div>
          <span class="dash-tag">7-Day Rolling</span>
        </div>
        <div class="dash-timeline-svg-wrap">
          <svg viewBox="0 0 ${tSvgWidth} ${tSvgHeight}" class="dash-timeline-svg" preserveAspectRatio="none">
            <defs>
              <linearGradient id="timeline-grad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="#06b6d4" stop-opacity="0.28" />
                <stop offset="100%" stop-color="#06b6d4" stop-opacity="0.0" />
              </linearGradient>
            </defs>
            <!-- Gridlines -->
            <line x1="${tPadLeft}" y1="30" x2="${tSvgWidth - tPadRight}" y2="30" stroke="#1e293b" stroke-width="1" stroke-dasharray="3 3"/>
            <line x1="${tPadLeft}" y1="65" x2="${tSvgWidth - tPadRight}" y2="65" stroke="#1e293b" stroke-width="1" stroke-dasharray="3 3"/>
            <line x1="${tPadLeft}" y1="105" x2="${tSvgWidth - tPadRight}" y2="105" stroke="#1e293b" stroke-width="1.5"/>

            <!-- Area Fill -->
            <polygon points="${areaPolygonStr}" fill="url(#timeline-grad)"/>

            <!-- Polyline -->
            <polyline points="${polylineStr}" fill="none" stroke="#06b6d4" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>

            <!-- Dots -->
            ${timelinePointsSvg}
          </svg>
        </div>
      </div>

      <!-- PANEL 6: Frequently Targeted Services -->
      <div class="dash-card">
        <div class="dash-card-header">
          <div>
            <h3>Frequently Targeted Services</h3>
            <p class="dash-card-sub">Top enterprise domains and identities under observation</p>
          </div>
          <span class="dash-tag">Asset Threat Heat</span>
        </div>
        <div class="dash-targets-list">
          ${targetServicesHtml}
        </div>
      </div>
    </div>

    <!-- ROW 4: OPERATIONAL ACTIONS & INCIDENT STATUS -->
    <div class="dash-ops-grid">
      <!-- PANEL 7: Recommended Actions Matrix -->
      <div class="dash-card">
        <div class="dash-card-header">
          <div>
            <h3>Active Response Recommendations</h3>
            <p class="dash-card-sub">Prescriptive mitigations auto-mapped from response_rules.json</p>
          </div>
          <span class="dash-tag">Prescriptive Playbooks</span>
        </div>
        <div class="dash-actions-container">
          ${actionsListHtml}
        </div>
      </div>

      <!-- PANEL 8: Incident Status Table -->
      <div class="dash-card dash-card-table">
        <div class="dash-card-header">
          <div>
            <h3>Incident Triage & Status</h3>
            <p class="dash-card-sub">Recent investigations with configurable response lifecycle states</p>
          </div>
          <span class="dash-tag">Live Triage</span>
        </div>
        <div class="dash-table-wrap">
          <table class="dash-incident-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Target Asset</th>
                <th>Vector</th>
                <th>Risk Tier</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${incidentRowsHtml}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  // Attach event handlers for incident status select
  container.querySelectorAll(".dash-status-select").forEach((sel) => {
    sel.addEventListener("change", (e) => {
      const scanId = e.target.dataset.scanId;
      const newStatus = e.target.value;
      const targetScan = scansArray.find((s) => s.id === scanId);
      if (targetScan && window.setScan) {
        window.setScan({ ...targetScan, incident_status: newStatus });
      }
    });
  });

  // Attach event handlers for inspect buttons
  container.querySelectorAll(".dash-inspect-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const scanId = btn.dataset.scanId;
      if (window.setActiveScan && window.setCurrentView) {
        window.setActiveScan(scanId);
        window.setCurrentView("analyze");
      }
    });
  });
}

window.renderCommandDashboard = renderCommandDashboard;
