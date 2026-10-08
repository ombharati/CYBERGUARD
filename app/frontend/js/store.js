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

function loadStoredScans() {
  try {
    const raw = localStorage.getItem("cyberguard_scans");
    if (!raw) return new Map();
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length > 0) {
      const map = new Map();
      for (const item of parsed) {
        // Exclude legacy demo items starting with CG-SEC
        if (item && item.id && !item.id.startsWith("CG-SEC")) {
          map.set(item.id, item);
        }
      }
      return map;
    }
  } catch (err) {
    console.warn("[store] Error parsing localStorage scans:", err);
  }
  return new Map();
}

state.scans = loadStoredScans();
if (state.scans.size > 0) {
  state.activeScanId = Array.from(state.scans.keys())[0];
}

function clearHistory() {
  state.scans = new Map();
  state.activeScanId = null;
  try {
    localStorage.removeItem("cyberguard_scans");
  } catch (err) {
    console.warn("[store] Error clearing localStorage:", err);
  }
  if (typeof render === "function") {
    render();
  }
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
function setScan(scan, replaceId) {
  if (!scan || !scan.id) return;

  if (replaceId && replaceId !== scan.id && state.scans.has(replaceId)) {
    // In-place replacement of optimistic temporary scan in state.scans
    const nextMap = new Map();
    for (const [k, v] of state.scans.entries()) {
      if (k === replaceId) {
        nextMap.set(scan.id, { ...v, ...scan });
      } else {
        nextMap.set(k, v);
      }
    }
    state.scans = nextMap;
    if (state.activeScanId === replaceId) {
      state.activeScanId = scan.id;
    }
    // Update render layer row maps in place BEFORE render()
    if (typeof updateRowIdInPlace === "function") {
      updateRowIdInPlace(replaceId, scan);
    }
  } else {
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
window.state = state;
window.setScan = setScan;
window.removeScan = removeScan;
window.setConnection = setConnection;
window.setHealth = setHealth;
window.setActiveScan = setActiveScan;
window.setCurrentMode = setCurrentMode;
window.setCurrentView = setCurrentView;
window.setCurrentFilter = setCurrentFilter;
window.clearHistory = clearHistory;
window.setError = setError;

window.store = {
  state,
  setScan,
  removeScan,
  clearHistory,
  setConnection,
  setHealth,
  setActiveScan,
  setCurrentView,
  setCurrentMode,
  setCurrentFilter,
  setError
};
