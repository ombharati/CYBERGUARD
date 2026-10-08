"""Unit tests for Scenario 3: Log Analysis and Anomaly Detection."""
import json
import pytest
from detection.logs.detector import analyze_logs, parse_log_line, MAX_LOG_INPUT_BYTES


def test_empty_log_input():
    res1 = analyze_logs("")
    assert res1.is_valid is False
    assert any("Empty Log" in f.title for f in res1.findings)

    res2 = analyze_logs("    \n   ")
    assert res2.is_valid is False


def test_malformed_log_lines():
    garbage = """
    This is not a syslog line at all!
    Random text 12345 {not: valid json}
    ??? ::: !!!
    Jan 15 InvalidLineWithNoMatch
    """
    res = analyze_logs(garbage)
    assert res.is_valid is True
    # Should not crash and should produce clean inspection or handle gracefully
    assert len(res.findings) >= 1


def test_failed_login_burst_rule():
    # 6 failed password attempts from 192.168.1.50 within 2 minutes
    logs = """
Jan 15 09:00:10 host sshd[101]: Failed password for invalid user admin from 192.168.1.50 port 4001 ssh2
Jan 15 09:00:20 host sshd[102]: Failed password for invalid user admin from 192.168.1.50 port 4002 ssh2
Jan 15 09:00:30 host sshd[103]: Failed password for invalid user admin from 192.168.1.50 port 4003 ssh2
Jan 15 09:00:40 host sshd[104]: Failed password for invalid user admin from 192.168.1.50 port 4004 ssh2
Jan 15 09:00:50 host sshd[105]: Failed password for invalid user admin from 192.168.1.50 port 4005 ssh2
Jan 15 09:01:00 host sshd[106]: Failed password for invalid user admin from 192.168.1.50 port 4006 ssh2
"""
    res = analyze_logs(logs)
    assert res.signals["failed_login_burst"] is True
    assert res.signals["auth_failure"] is True
    burst_findings = [f for f in res.findings if "Burst" in f.title]
    assert len(burst_findings) >= 1
    assert "192.168.1.50" in burst_findings[0].description
    assert burst_findings[0].severity in ("high", "critical")


def test_password_spraying_rule():
    # 4 distinct usernames targeted from same IP within 5 minutes
    logs = """
Jan 15 10:00:10 host sshd[201]: Failed password for alice from 10.0.0.99 port 5001 ssh2
Jan 15 10:00:30 host sshd[202]: Failed password for bob from 10.0.0.99 port 5002 ssh2
Jan 15 10:01:00 host sshd[203]: Failed password for charlie from 10.0.0.99 port 5003 ssh2
Jan 15 10:01:30 host sshd[204]: Failed password for dave from 10.0.0.99 port 5004 ssh2
"""
    res = analyze_logs(logs)
    assert res.signals["password_spraying"] is True
    spray_findings = [f for f in res.findings if "Password Spraying" in f.title]
    assert len(spray_findings) >= 1
    assert "10.0.0.99" in spray_findings[0].description
    assert spray_findings[0].severity in ("high", "critical")


def test_impossible_travel_rule():
    # Same user logged in from New York then Tokyo within 30 minutes in JSON logs
    logs = """
{"timestamp": "2026-10-07T10:00:00Z", "user": "sarah", "source_ip": "198.51.100.1", "action": "login_success", "location": "New York, US"}
{"timestamp": "2026-10-07T10:25:00Z", "user": "sarah", "source_ip": "203.0.113.5", "action": "login_success", "location": "Tokyo, JP"}
"""
    res = analyze_logs(logs)
    assert res.signals["impossible_travel"] is True
    travel_findings = [f for f in res.findings if "Impossible Travel" in f.title]
    assert len(travel_findings) >= 1
    assert "sarah" in travel_findings[0].description
    assert travel_findings[0].severity in ("high", "critical")


def test_unknown_device_rule():
    # User logs in with known device, then a completely new device
    logs = """
{"timestamp": "2026-10-07T08:00:00Z", "user": "marcus", "action": "login_success", "device": "macbook-pro-corp"}
{"timestamp": "2026-10-07T09:00:00Z", "user": "marcus", "action": "login_success", "device": "unknown-linux-arm"}
"""
    res = analyze_logs(logs)
    assert res.signals["unknown_device"] is True
    device_findings = [f for f in res.findings if "Device" in f.title]
    assert len(device_findings) >= 1
    assert "unknown-linux-arm" in device_findings[0].description


def test_off_hours_access_rule():
    # Login at 02:30 AM UTC
    logs = """
Jan 15 02:30:15 host sshd[301]: Accepted password for engineering_user from 192.168.1.200 port 22 ssh2
"""
    res = analyze_logs(logs)
    assert res.signals["off_hours_access"] is True
    off_hours = [f for f in res.findings if "Off-Hours" in f.title]
    assert len(off_hours) >= 1
    assert off_hours[0].severity == "low"


def test_successful_login_after_repeated_failures_rule():
    # 3 failures followed by success
    logs = """
Jan 15 14:00:01 host sshd[401]: Failed password for root from 192.168.10.15 port 3001 ssh2
Jan 15 14:00:15 host sshd[402]: Failed password for root from 192.168.10.15 port 3002 ssh2
Jan 15 14:00:30 host sshd[403]: Failed password for root from 192.168.10.15 port 3003 ssh2
Jan 15 14:00:45 host sshd[404]: Accepted password for root from 192.168.10.15 port 3004 ssh2
"""
    res = analyze_logs(logs)
    assert res.signals["success_after_failures"] is True
    success_findings = [f for f in res.findings if "Successful Login After" in f.title]
    assert len(success_findings) >= 1
    assert "root" in success_findings[0].description
    assert success_findings[0].severity == "high"


def test_new_admin_account_created_rule():
    logs = """
Jan 15 11:20:00 host useradd[501]: new user: name=backdoor_admin, UID=0, GID=0, home=/root, shell=/bin/bash
"""
    res = analyze_logs(logs)
    assert res.signals["new_admin_created"] is True
    admin_findings = [f for f in res.findings if "Admin" in f.title or "Privileged" in f.title]
    assert len(admin_findings) >= 1
    assert admin_findings[0].severity == "high"


def test_ssh_key_added_rule():
    logs = """
Jan 15 12:00:00 host sshd[601]: Accepted publickey for user deploy from 192.168.1.10: authorized_keys modified
"""
    res = analyze_logs(logs)
    assert res.signals["ssh_key_added"] is True
    ssh_findings = [f for f in res.findings if "SSH" in f.title]
    assert len(ssh_findings) >= 1
    assert ssh_findings[0].severity == "high"


def test_very_large_log_bound():
    # Generate 1.5MB log stream, verify it is bounded to 1MB and executes safely
    single_line = "Jan 15 08:00:00 host sshd[1]: Failed password for test from 1.1.1.1 port 22 ssh2\n"
    repeat_count = int(1.5 * MAX_LOG_INPUT_BYTES / len(single_line))
    huge_input = single_line * repeat_count
    assert len(huge_input) > MAX_LOG_INPUT_BYTES

    res = analyze_logs(huge_input)
    assert res.is_valid is True
    # Verify input was bounded and parsed safely without OOM
    assert res.signals["failed_login_burst"] is True
