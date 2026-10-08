"""Deterministic Log Analysis and Anomaly Detection Engine.

Covers Scenario 3: Technical threat and abnormal behavior detection in authentication
and system logs (Linux auth.log, generic syslog, and JSON structured logs).
"""
import re
import json
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set

from detection.url.detector import Finding

# Strict maximum input size bound (1MB)
MAX_LOG_INPUT_BYTES = 1024 * 1024  # 1MB


@dataclass
class LogEvent:
    raw_line: str
    timestamp: Optional[datetime] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    action: Optional[str] = None  # e.g., "login_failed", "login_success", "user_created", "ssh_key_added"
    device: Optional[str] = None
    location: Optional[str] = None
    is_admin: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LogAnalysisResult:
    is_valid: bool
    events: List[LogEvent] = field(default_factory=list)
    signals: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    error_message: Optional[str] = None


# --- Regex Parsers for Linux auth.log & Syslog ---
# Example: "Jan 15 09:15:23 host sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2"
AUTH_FAILED_RE = re.compile(
    r"(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE
)
# Example: "Jan 15 09:16:10 host sshd[1234]: Accepted password for admin from 192.168.1.100 port 22 ssh2"
# Example: "Jan 15 09:16:10 host sshd[1234]: Accepted publickey for alice from 192.168.1.100 port 22 ssh2"
AUTH_ACCEPTED_RE = re.compile(
    r"(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+Accepted\s+(?P<auth_type>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE
)
# User creation / privilege escalation: "useradd[567]: new user: name=badadmin, UID=1001, GID=1001" or "sudo ... USER=root"
USERADD_RE = re.compile(
    r"(?:new\s+user:\s*name=(?P<user>\S+)|useradd(?:\[\d+\])?:\s*(?:add\s+user\s+`(?P<user2>\S+)'|new\s+user:\s*name=(?P<user3>\S+))|(?:usermod|gpasswd).*?(?:wheel|sudo|admin|root).*?(?P<user4>\S+))",
    re.IGNORECASE
)
# SSH key operations: "authorized_keys", "ssh-copy-id"
SSH_KEY_RE = re.compile(
    r"(?:authorized_keys|ssh-copy-id|Accepted\s+publickey\s+.*?new\s+key|installed\s+ssh\s+key)",
    re.IGNORECASE
)

MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12
}


def _parse_syslog_timestamp(month_str: str, day_str: str, time_str: str, ref_year: int = 2026) -> Optional[datetime]:
    """Parse standard syslog timestamp (e.g., 'Jan 15 09:15:23')."""
    try:
        month = MONTH_MAP.get(month_str.lower(), 1)
        day = int(day_str)
        parts = [int(p) for p in time_str.split(":")]
        return datetime(ref_year, month, day, parts[0], parts[1], parts[2], tzinfo=timezone.utc)
    except Exception:
        return None


def _parse_iso_timestamp(ts_val: Any) -> Optional[datetime]:
    """Parse ISO8601 string or numeric timestamp."""
    if isinstance(ts_val, (int, float)):
        try:
            return datetime.fromtimestamp(ts_val, tzinfo=timezone.utc)
        except Exception:
            return None
    if isinstance(ts_val, str):
        clean = ts_val.strip()
        try:
            # Handle ISO string (e.g. 2026-10-07T12:00:00Z)
            return datetime.fromisoformat(clean.replace("Z", "+00:00"))
        except Exception:
            try:
                # Try standard format '%Y-%m-%d %H:%M:%S'
                return datetime.strptime(clean, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except Exception:
                pass
    return None


def parse_log_line(line: str, line_idx: int) -> Optional[LogEvent]:
    """Parse a single raw log line into a LogEvent object."""
    clean = line.strip()
    if not clean:
        return None

    # 1. Attempt JSON parsing
    if clean.startswith("{") and clean.endswith("}"):
        try:
            data = json.loads(clean)
            ts = _parse_iso_timestamp(data.get("timestamp") or data.get("time") or data.get("@timestamp"))
            user = data.get("user") or data.get("username") or data.get("account")
            ip = data.get("source_ip") or data.get("ip") or data.get("src_ip") or data.get("client_ip")
            action = str(data.get("action") or data.get("event") or data.get("status") or "").lower()
            device = data.get("device") or data.get("device_id") or data.get("user_agent")
            location = data.get("location") or data.get("geo") or data.get("country") or data.get("city")
            is_admin = bool(data.get("is_admin") or data.get("role") in ("admin", "root", "administrator"))

            # Normalize action
            if any(term in action for term in ("fail", "invalid", "rejected", "denied", "error")):
                normalized_action = "login_failed"
            elif any(term in action for term in ("success", "accepted", "logged_in", "session_opened")):
                normalized_action = "login_success"
            elif any(term in action for term in ("user_create", "useradd", "add_user", "new_user")):
                normalized_action = "user_created"
            elif any(term in action for term in ("ssh_key", "key_added", "authorized_keys")):
                normalized_action = "ssh_key_added"
            else:
                normalized_action = action or "unknown"

            return LogEvent(
                raw_line=clean,
                timestamp=ts,
                user=str(user) if user else None,
                source_ip=str(ip) if ip else None,
                action=normalized_action,
                device=str(device) if device else None,
                location=str(location) if location else None,
                is_admin=is_admin,
                metadata=data
            )
        except Exception:
            # Fall through to syslog parsing if not valid JSON
            pass

    # 2. Linux auth.log - Failed Login
    failed_match = AUTH_FAILED_RE.search(clean)
    if failed_match:
        ts = _parse_syslog_timestamp(
            failed_match.group("month"),
            failed_match.group("day"),
            failed_match.group("time"),
        )
        return LogEvent(
            raw_line=clean,
            timestamp=ts,
            user=failed_match.group("user"),
            source_ip=failed_match.group("ip"),
            action="login_failed"
        )

    # 3. Linux auth.log - Accepted Login
    accepted_match = AUTH_ACCEPTED_RE.search(clean)
    if accepted_match:
        ts = _parse_syslog_timestamp(
            accepted_match.group("month"),
            accepted_match.group("day"),
            accepted_match.group("time"),
        )
        return LogEvent(
            raw_line=clean,
            timestamp=ts,
            user=accepted_match.group("user"),
            source_ip=accepted_match.group("ip"),
            action="login_success"
        )

    # 4. User creation
    useradd_match = USERADD_RE.search(clean)
    if useradd_match:
        u = (
            useradd_match.group("user")
            or useradd_match.group("user2")
            or useradd_match.group("user3")
            or useradd_match.group("user4")
            or "admin"
        )
        is_adm = any(term in clean.lower() for term in ("admin", "sudo", "wheel", "root", "uid=0", "gid=0"))
        return LogEvent(
            raw_line=clean,
            action="user_created",
            user=u,
            is_admin=is_adm
        )

    # 5. SSH key modification
    if SSH_KEY_RE.search(clean):
        # Extract user if mentioned
        user_match = re.search(r"for\s+user\s+(\S+)|for\s+(\S+)", clean, re.IGNORECASE)
        u = user_match.group(1) or user_match.group(2) if user_match else None
        return LogEvent(
            raw_line=clean,
            action="ssh_key_added",
            user=u
        )

    # 6. Generic syslog fallback
    return LogEvent(raw_line=clean, action="log_entry")


def analyze_logs(raw_input: str) -> LogAnalysisResult:
    """
    Perform deterministic log analysis against 8 cybersecurity rules:
    1. Failed login burst: > 5 failed attempts from one IP within 5 minutes
    2. Password spraying: > 3 distinct usernames attempted from one IP within 10 minutes
    3. Impossible travel: Same user logged in from two geolocations within impossible travel window
    4. Unknown device: Login from a device/user-agent not seen for that user before
    5. Off-hours access: Login outside user's normal business hours (22:00-06:00 or flagged)
    6. Successful login after repeated failures: Success after 3+ consecutive failures
    7. New admin account created: User created with administrative/sudo privileges
    8. SSH key added: SSH authorized_keys or publickey installation
    """
    if not raw_input or not isinstance(raw_input, str) or not raw_input.strip():
        return LogAnalysisResult(
            is_valid=False,
            error_message="Log input is empty",
            findings=[Finding(
                severity="low",
                title="Empty Log Input",
                description="No log content was provided for analysis.",
                category="log_anomaly",
                signal_type="empty_input",
                source="deterministic"
            )]
        )

    # Enforce strict 1MB input ceiling
    bounded_input = raw_input[:MAX_LOG_INPUT_BYTES]
    lines = bounded_input.splitlines()

    events: List[LogEvent] = []
    for idx, line in enumerate(lines):
        parsed = parse_log_line(line, idx)
        if parsed:
            events.append(parsed)

    findings: List[Finding] = []
    signals: Dict[str, Any] = {
        "total_lines_analyzed": len(lines),
        "total_parsed_events": len(events),
        "failed_login_burst": False,
        "password_spraying": False,
        "impossible_travel": False,
        "unknown_device": False,
        "off_hours_access": False,
        "success_after_failures": False,
        "new_admin_created": False,
        "ssh_key_added": False,
        # RiskEngine compatibility signals
        "auth_failure": False,
        "credential_matches": 0,
        "secrecy_demanded": False,
        "unusual_payment": False,
        "brand_mismatch": False,
    }

    # Groupings for stateful temporal checks
    ip_failed_events: Dict[str, List[LogEvent]] = {}
    ip_users_attempted: Dict[str, Dict[str, List[datetime]]] = {}
    user_logins_by_time: Dict[str, List[LogEvent]] = {}
    user_devices_seen: Dict[str, Set[str]] = {}
    user_history_failures: Dict[str, int] = {}
    ip_history_failures: Dict[str, int] = {}

    # Sort events by timestamp if available for accurate sequence analysis
    time_sorted_events = sorted(
        [e for e in events if e.timestamp is not None],
        key=lambda x: x.timestamp
    )
    events_to_process = time_sorted_events if len(time_sorted_events) >= len(events) * 0.5 else events

    for ev in events_to_process:
        user = ev.user
        ip = ev.source_ip
        action = ev.action
        ts = ev.timestamp

        # Track failure counts
        if action == "login_failed":
            signals["auth_failure"] = True
            if ip:
                ip_failed_events.setdefault(ip, []).append(ev)
                ip_history_failures[ip] = ip_history_failures.get(ip, 0) + 1
                if user:
                    user_dict = ip_users_attempted.setdefault(ip, {})
                    user_dict.setdefault(user, []).append(ts or datetime.now(timezone.utc))
            if user:
                user_history_failures[user] = user_history_failures.get(user, 0) + 1

        # Track successful logins
        elif action == "login_success":
            # Rule 6: Successful login after repeated failures
            failures_for_user = user_history_failures.get(user, 0) if user else 0
            failures_for_ip = ip_history_failures.get(ip, 0) if ip else 0
            if failures_for_user >= 3 or failures_for_ip >= 3:
                signals["success_after_failures"] = True
                signals["credential_matches"] += 1
                findings.append(Finding(
                    severity="high",
                    title="Successful Login After Repeated Failures",
                    description=(
                        f"Account '{user or 'unknown'}' successfully authenticated after "
                        f"{max(failures_for_user, failures_for_ip)} consecutive failed attempts from IP {ip or 'unknown'}."
                    ),
                    category="log_anomaly",
                    signal_type="success_after_failures",
                    evidence=ev.raw_line,
                    source="deterministic",
                    recommended_actions=[
                        "Confirm session legitimacy with the account owner",
                        "Review subsequent command history or audit trail",
                        "Force credential rotation if account takeover is suspected"
                    ]
                ))
                # Reset failure counter after alerting
                if user:
                    user_history_failures[user] = 0
                if ip:
                    ip_history_failures[ip] = 0

            # Rule 4: Unknown device
            device_id = ev.device or ev.metadata.get("device_id") or ev.metadata.get("user_agent")
            if user and device_id:
                seen_devices = user_devices_seen.setdefault(user, set())
                # If explicit "new_device: true" flag or device not in established baseline
                is_flagged_new = bool(ev.metadata.get("new_device") or ev.metadata.get("is_new_device"))
                if is_flagged_new or (len(seen_devices) > 0 and device_id not in seen_devices):
                    signals["unknown_device"] = True
                    findings.append(Finding(
                        severity="medium",
                        title="Unrecognized Device Login",
                        description=f"User '{user}' authenticated from an unrecognized device identifier ('{device_id}').",
                        category="log_anomaly",
                        signal_type="unknown_device",
                        evidence=ev.raw_line,
                        source="deterministic",
                        recommended_actions=[
                            "Prompt user for device verification via secondary factor",
                            "Inspect device telemetry and source network ASN",
                            "Revoke active device authorization if unverified"
                        ]
                    ))
                seen_devices.add(device_id)

            # Rule 5: Off-hours access
            if ts:
                # Normal office window: 07:00 to 20:00 local/UTC
                hour = ts.hour
                is_off_hours = (hour < 6 or hour >= 22) or ev.metadata.get("off_hours") is True
                if is_off_hours:
                    signals["off_hours_access"] = True
                    findings.append(Finding(
                        severity="low",
                        title="Off-Hours Access Detected",
                        description=f"User '{user or 'unknown'}' accessed resources at {ts.strftime('%H:%M:%S UTC')}, outside standard operational hours.",
                        category="log_anomaly",
                        signal_type="off_hours_access",
                        evidence=ev.raw_line,
                        source="deterministic",
                        recommended_actions=[
                            "Verify legitimate business requirement with account holder",
                            "Monitor for unauthorized privilege escalation or data staging"
                        ]
                    ))

            # Rule 3: Impossible travel check
            if user and ev.location:
                prev_logins = user_logins_by_time.setdefault(user, [])
                for prev in prev_logins:
                    if prev.location and prev.location.lower() != ev.location.lower():
                        # Calculate time difference
                        if ts and prev.timestamp:
                            delta_hours = abs((ts - prev.timestamp).total_seconds()) / 3600.0
                            # If different locations within < 3 hours
                            if delta_hours < 3.0:
                                signals["impossible_travel"] = True
                                signals["brand_mismatch"] = True  # High risk trigger
                                findings.append(Finding(
                                    severity="high",
                                    title="Impossible Travel Geolocation Anomaly",
                                    description=(
                                        f"User '{user}' logged in from '{prev.location}' and '{ev.location}' "
                                        f"within {delta_hours:.1f} hours, violating physical travel constraints."
                                    ),
                                    category="log_anomaly",
                                    signal_type="impossible_travel",
                                    evidence=f"{prev.raw_line}\n{ev.raw_line}",
                                    source="deterministic",
                                    recommended_actions=[
                                        "Immediately terminate all concurrent sessions for user",
                                        "Trigger automated account lock and notify security team",
                                        "Require step-up hardware token or in-person MFA reset"
                                    ]
                                ))
                                break
                        else:
                            # Without timestamps, different locations back-to-back in log sequence
                            signals["impossible_travel"] = True
                            findings.append(Finding(
                                severity="high",
                                title="Impossible Travel Geolocation Anomaly",
                                description=f"User '{user}' logged in from divergent locations '{prev.location}' and '{ev.location}' in rapid sequence.",
                                category="log_anomaly",
                                signal_type="impossible_travel",
                                evidence=f"{prev.raw_line}\n{ev.raw_line}",
                                source="deterministic",
                                recommended_actions=[
                                    "Terminate active user sessions",
                                    "Require MFA re-enrollment",
                                    "Notify user and SOC"
                                ]
                            ))
                            break
                prev_logins.append(ev)

        # Rule 7: New admin account created
        elif action == "user_created" or ev.is_admin:
            is_admin_flag = ev.is_admin or any(term in ev.raw_line.lower() for term in ("sudo", "wheel", "admin", "root", "uid=0"))
            if is_admin_flag:
                signals["new_admin_created"] = True
                signals["credential_matches"] += 1
                findings.append(Finding(
                    severity="high",
                    title="Privileged Administrator Account Created",
                    description=f"A new administrative or privileged user account ('{user or 'unknown'}') was provisioned or elevated to admin rights.",
                    category="log_anomaly",
                    signal_type="new_admin_created",
                    evidence=ev.raw_line,
                    source="deterministic",
                    recommended_actions=[
                        "Verify administrative change request ticket",
                        "Audit provisioning origin IP and operator identity",
                        "Revoke unapproved root/admin credentials"
                    ]
                ))

        # Rule 8: SSH key added
        elif action == "ssh_key_added":
            signals["ssh_key_added"] = True
            findings.append(Finding(
                severity="high",
                title="SSH Public Key Added to System",
                description=f"An SSH public key was installed or appended to authorized_keys (user: '{user or 'system'}').",
                category="log_anomaly",
                signal_type="ssh_key_added",
                evidence=ev.raw_line,
                source="deterministic",
                recommended_actions=[
                    "Inspect ~/.ssh/authorized_keys for unexpected cryptographic keys",
                    "Verify key fingerprint with authorized personnel",
                    "Quarantine host if modification was unauthorized"
                ]
            ))

    # --- Rule 1: Failed login burst (> 5 failed attempts from one IP within 5 minutes) ---
    for ip, fails in ip_failed_events.items():
        if len(fails) > 5:
            # Check 5-minute sliding window if timestamps present
            burst_detected = False
            burst_lines = []
            has_timestamps = any(f.timestamp is not None for f in fails)
            if has_timestamps:
                sorted_fails = sorted([f for f in fails if f.timestamp is not None], key=lambda x: x.timestamp)
                for i in range(len(sorted_fails)):
                    window = [
                        f for f in sorted_fails[i:]
                        if (f.timestamp - sorted_fails[i].timestamp).total_seconds() <= 300
                    ]
                    if len(window) > 5:
                        burst_detected = True
                        burst_lines = [f.raw_line for f in window[:6]]
                        break
            else:
                burst_detected = True
                burst_lines = [f.raw_line for f in fails[:6]]

            if burst_detected:
                signals["failed_login_burst"] = True
                signals["auth_failure"] = True
                signals["credential_matches"] += 1
                findings.append(Finding(
                    severity="high",
                    title="Failed Login Burst Detected",
                    description=f"More than 5 failed login attempts were observed from IP '{ip}' within 5 minutes ({len(fails)} total attempts).",
                    category="log_anomaly",
                    signal_type="brute_force",
                    evidence="\n".join(burst_lines[:3]),
                    source="deterministic",
                    recommended_actions=[
                        f"Block source IP {ip} at edge firewall / perimeter",
                        "Enforce rate-limiting and temporary account lockout",
                        "Notify SOC incident responders of brute-force attempt"
                    ]
                ))

    # --- Rule 2: Password spraying (> 3 distinct usernames from one IP within 10 minutes) ---
    for ip, user_attempts in ip_users_attempted.items():
        if len(user_attempts) > 3:
            # Check 10-minute sliding window if timestamps present
            spray_detected = False
            distinct_users = list(user_attempts.keys())
            has_ts = any(any(ts is not None for ts in ts_list) for ts_list in user_attempts.values())
            if has_ts:
                all_ts_pairs = []
                for u, tss in user_attempts.items():
                    for t in tss:
                        if t:
                            all_ts_pairs.append((t, u))
                all_ts_pairs.sort(key=lambda x: x[0])
                for i in range(len(all_ts_pairs)):
                    window_users = {
                        u for t, u in all_ts_pairs[i:]
                        if (t - all_ts_pairs[i][0]).total_seconds() <= 600
                    }
                    if len(window_users) > 3:
                        spray_detected = True
                        break
            else:
                spray_detected = True

            if spray_detected:
                signals["password_spraying"] = True
                signals["auth_failure"] = True
                signals["credential_matches"] += 2
                findings.append(Finding(
                    severity="high",
                    title="Password Spraying Attack Detected",
                    description=(
                        f"Single source IP '{ip}' targeted {len(distinct_users)} distinct user accounts "
                        f"({', '.join(distinct_users[:5])}) within 10 minutes."
                    ),
                    category="log_anomaly",
                    signal_type="password_spraying",
                    evidence=f"Targeted usernames from IP {ip}: {', '.join(distinct_users)}",
                    source="deterministic",
                    recommended_actions=[
                        f"Enact automated IP block on {ip}",
                        "Temporarily lock targeted accounts pending password review",
                        "Conduct threat hunting for successful logins from this subnet"
                    ]
                ))

    # Clean default finding if no anomalies found
    if not findings:
        findings.append(Finding(
            severity="low",
            title="Clean Log Inspection",
            description="Analyzed log entries showed no suspicious authentication anomalies, brute force, or escalation patterns.",
            category="log_anomaly",
            signal_type="clean_logs",
            source="deterministic"
        ))

    return LogAnalysisResult(
        is_valid=True,
        events=events,
        signals=signals,
        findings=findings
    )
