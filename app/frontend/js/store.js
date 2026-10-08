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
  const now = Date.now();

  const samples = [
    {
      id: "CG-SEC001",
      type: "LOGS",
      target: "SSH Auth Perimeter (198.51.100.44)",
      status: "completed",
      score: 88,
      classification: "Critical",
      summary: "High-frequency failed authentication burst (8 attempts in 90 seconds) targeting admin user.",
      findings: [
        {
          severity: "high",
          title: "Failed Login Burst (8 attempts / 90s)",
          description: "Rapid credential brute-forcing detected from external IP 198.51.100.44.",
          category: "log_anomaly",
          signal_type: "failed_login_burst",
          weight: 40,
          evidence: "8 failed attempts for admin from 198.51.100.44 in 90s",
          source: "deterministic"
        }
      ],
      signals: [
        { name: "Pattern analysis", value: 88 },
        { name: "Content indicators", value: 75 },
        { name: "Risk aggregation", value: 88 },
        { name: "Reputation signals", value: 65 }
      ],
      explanation: "Volumetric authentication failures from an untrusted source IP indicating targeted automated brute-force.",
      recommended_actions: [
        "Lock the targeted account",
        "Block the source IP at edge firewall",
        "Force MFA re-enrollment",
        "Notify the SOC"
      ],
      incident_status: "open",
      timestamp: new Date(now - 1000 * 60 * 25).toISOString()
    },
    {
      id: "CG-SEC002",
      type: "IDENTITY",
      target: "alert@microsoft-security-verify.com",
      status: "completed",
      score: 85,
      classification: "High",
      summary: "Spoofed inbound identity: SPF failure and display name impersonating Microsoft Security Center.",
      findings: [
        {
          severity: "high",
          title: "Email Authentication Failure (SPF=fail)",
          description: "Inbound SPF check rejected sending IP 198.51.100.22 as unauthorized for Microsoft.",
          category: "identity",
          signal_type: "spf_fail",
          weight: 35,
          evidence: "Authentication-Results: spf=fail (sender 198.51.100.22 not permitted)",
          source: "deterministic"
        },
        {
          severity: "high",
          title: "Brand Lookalike Domain Impersonation (Microsoft)",
          description: "Domain mimics Microsoft brand without matching official registration.",
          category: "identity",
          signal_type: "lookalike_domain",
          weight: 35,
          evidence: "From: 'Microsoft Security Center' <alert@microsoft-security-verify.com>",
          source: "deterministic"
        }
      ],
      signals: [
        { name: "Pattern analysis", value: 85 },
        { name: "Content indicators", value: 80 },
        { name: "Risk aggregation", value: 85 }
      ],
      explanation: "Critical identity spoofing: sender forged Microsoft security brand with failed cryptographic SPF.",
      recommended_actions: [
        "Block the sender domain at gateway",
        "Quarantine related emails across mailboxes",
        "Warn the recipient",
        "Report to brand protection"
      ],
      incident_status: "open",
      timestamp: new Date(now - 1000 * 60 * 120).toISOString()
    },
    {
      id: "CG-SEC003",
      type: "URL",
      target: "https://paypaI-security-update.com/login",
      status: "completed",
      score: 92,
      classification: "Critical",
      summary: "Punycode brand impersonation and sensitive credential harvesting path targeting PayPal.",
      findings: [
        {
          severity: "high",
          title: "Brand Lookalike Impersonation (PayPal)",
          description: "Registered domain mimics PayPal with homograph substitution.",
          category: "heuristic",
          signal_type: "lookalike_domain",
          weight: 35,
          evidence: "paypaI-security-update.com mimics paypal.com",
          source: "deterministic"
        },
        {
          severity: "high",
          title: "Sensitive Path on Lookalike Host",
          description: "/login path present on unauthorized lookalike domain.",
          category: "heuristic",
          signal_type: "credential_harvesting",
          weight: 25,
          evidence: "/login",
          source: "deterministic"
        }
      ],
      signals: [
        { name: "Pattern analysis", value: 92 },
        { name: "Content indicators", value: 90 },
        { name: "Risk aggregation", value: 92 }
      ],
      explanation: "Active phishing infrastructure mimicking financial services login portal.",
      recommended_actions: [
        "Block the URL at the gateway",
        "Quarantine related emails",
        "Warn the user",
        "Report to brand protection"
      ],
      incident_status: "investigating",
      timestamp: new Date(now - 1000 * 60 * 360).toISOString()
    },
    {
      id: "CG-SEC004",
      type: "EMAIL",
      target: "Urgent: Wire Routing Instructions (john.doe@legitcorp.com)",
      status: "completed",
      score: 55,
      classification: "Medium",
      summary: "Executive persona with mismatched Reply-To routing diverting to external inbox.",
      findings: [
        {
          severity: "medium",
          title: "Reply-To Routing Mismatch",
          description: "Replies diverted to offshore invoicing consultant address.",
          category: "identity",
          signal_type: "reply_to_mismatch",
          weight: 25,
          evidence: "Reply-To: john.doe.offshore@consultant-invoicing.net",
          source: "deterministic"
        }
      ],
      signals: [
        { name: "Pattern analysis", value: 55 },
        { name: "Content indicators", value: 50 },
        { name: "Risk aggregation", value: 55 }
      ],
      explanation: "BEC indicators detected: corporate domain matches From header but response vector is diverted.",
      recommended_actions: [
        "Warn recipient of diverted Reply-To destination",
        "Conduct out-of-band identity verification with sender",
        "Monitor mailbox rules"
      ],
      incident_status: "investigating",
      timestamp: new Date(now - 1000 * 60 * 720).toISOString()
    },
    {
      id: "CG-SEC005",
      type: "URL",
      target: "https://google.com/search?q=cybersecurity",
      status: "completed",
      score: 10,
      classification: "Safe",
      summary: "Verified legitimate Google domain with standard search parameters.",
      findings: [
        {
          severity: "low",
          title: "Verified Official Domain (Google)",
          description: "Host belongs to authenticated official Google infrastructure.",
          category: "heuristic",
          signal_type: "clean_url",
          weight: 0,
          evidence: "google.com is verified official",
          source: "deterministic"
        }
      ],
      signals: [
        { name: "Pattern analysis", value: 10 },
        { name: "Content indicators", value: 8 },
        { name: "Risk aggregation", value: 10 }
      ],
      explanation: "Legitimate domain verified against official registry. Zero threats detected.",
      recommended_actions: [
        "No containment required; verified legitimate security baseline"
      ],
      incident_status: "resolved",
      timestamp: new Date(now - 1000 * 60 * 1440).toISOString()
    }
  ];

  for (const s of samples) {
    map.set(s.id, s);
  }
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
window.setError = setError;

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
