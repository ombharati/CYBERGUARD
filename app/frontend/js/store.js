/* ==============================================================================
   CYBERGUARD Frontend — Central Store (Single Source of Truth)
   ==============================================================================
   - state.scans: Map<id, ScanObject>
   - state.connection: 'online' | 'reconnecting' | 'offline'
   - state.health: 'healthy' | 'degraded' | 'unhealthy'
   - Mutation functions: setScan, removeScan, setConnection, setHealth, etc.
   - Every mutation automatically triggers render()
   ============================================================================== */

const state = {
  scans: new Map(),
  connection: navigator.onLine ? "online" : "offline",
  health: "healthy",
  activeScanId: null,
  currentMode: "url",
  currentView: "analyze",
  currentFilter: "all",
  error: null
};

function createDefaultScans() {
  const map = new Map();
  const initScan = {
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
    report_text: "1. What was analyzed\nInput type: URL\nTarget: https://example.com\n\n2. Verdict\nSafe (12/100)\n\n3. Key findings\nClean Structural Inspection",
    report_generated_by: "template",
    timestamp: new Date().toISOString()
  };
  map.set(initScan.id, initScan);
  return map;
}

function loadStoredScans() {
  try {
    const raw = localStorage.getItem("cyberguard_scans");
    if (!raw) return createDefaultScans();
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length > 0) {
      const map = new Map();
      for (const item of parsed) {
        if (item && item.id) {
          map.set(item.id, item);
        }
      }
      return map.size > 0 ? map : createDefaultScans();
    }
  } catch (err) {
    console.warn("[store] Error parsing localStorage scans:", err);
  }
  return createDefaultScans();
}

state.scans = loadStoredScans();
if (state.scans.size > 0) {
  state.activeScanId = Array.from(state.scans.keys())[0];
}

function persistScans() {
  try {
    const arr = Array.from(state.scans.values()).slice(0, 50);
    localStorage.setItem("cyberguard_scans", JSON.stringify(arr));
  } catch (err) {
    console.warn("[store] Error persisting scans to localStorage:", err);
  }
}

/* -----------------------------
   MUTATION FUNCTIONS
   - Every mutation triggers render()
----------------------------- */
function setScan(scan) {
  if (!scan || !scan.id) return;
  const existing = state.scans.get(scan.id);
  const merged = existing ? { ...existing, ...scan } : { ...scan };

  if (existing) {
    state.scans.set(scan.id, merged);
  } else {
    // Prepend new scan at top of Map
    const nextMap = new Map();
    nextMap.set(scan.id, merged);
    for (const [k, v] of state.scans.entries()) {
      if (k !== scan.id) nextMap.set(k, v);
    }
    state.scans = nextMap;
  }

  persistScans();
  if (typeof render === "function") {
    render();
  }
}

function removeScan(id) {
  if (state.scans.has(id)) {
    state.scans.delete(id);
    if (state.activeScanId === id) {
      state.activeScanId = state.scans.size > 0 ? Array.from(state.scans.keys())[0] : null;
    }
    persistScans();
    if (typeof render === "function") {
      render();
    }
  }
}

function setConnection(connectionStatus) {
  state.connection = connectionStatus;
  if (typeof render === "function") {
    render();
  }
}

function setHealth(healthStatus) {
  state.health = healthStatus;
  if (typeof render === "function") {
    render();
  }
}

function setActiveScan(id) {
  state.activeScanId = id;
  if (typeof render === "function") {
    render();
  }
}

function setCurrentView(view) {
  state.currentView = view;
  if (typeof render === "function") {
    render();
  }
}

function setCurrentMode(mode) {
  state.currentMode = mode;
  if (typeof render === "function") {
    render();
  }
}

function setCurrentFilter(filter) {
  state.currentFilter = filter;
  if (typeof render === "function") {
    render();
  }
}

function setError(err) {
  state.error = err;
  if (typeof render === "function") {
    render();
  }
}

// Global exposure for cross-script access
window.store = {
  state,
  setScan,
  removeScan,
  setConnection,
  setHealth,
  setActiveScan,
  setCurrentView,
  setCurrentMode,
  setCurrentFilter,
  setError
};
