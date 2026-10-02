"""SSRF Protection and Private/Local Network Validation."""
import ipaddress
import socket
from typing import Tuple, Optional


PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # "This" network
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 private
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (Carrier-grade NAT)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / AWS metadata
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 private
    ipaddress.ip_network("198.18.0.0/15"),      # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("fc00::/7"),           # Unique local
    ipaddress.ip_network("fe80::/10"),          # Link-local
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

RESERVED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "local",
    "internal",
    "lan",
    "home",
    "corp",
    "metadata.google.internal",
}


def is_ip_private_or_restricted(ip_str: str) -> bool:
    """Check if an IP string belongs to a private, loopback, or cloud metadata network."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return True
        for network in PRIVATE_NETWORKS:
            if ip in network:
                return True
        return False
    except ValueError:
        return False


def validate_hostname_ssrf(hostname: str) -> Tuple[bool, Optional[str]]:
    """
    Validate hostname against SSRF and private address spaces.
    Returns (is_restricted, reason).
    """
    cleaned = hostname.strip().lower().rstrip(".")
    if not cleaned:
        return True, "Empty hostname"

    if cleaned in RESERVED_HOSTNAMES:
        return True, f"Reserved hostname: {cleaned}"

    if cleaned.endswith(".localhost") or cleaned.endswith(".local") or cleaned.endswith(".internal"):
        return True, f"Internal domain name suffix: {cleaned}"

    # Check if hostname itself is directly an IP
    if is_ip_private_or_restricted(cleaned):
        return True, f"Direct private or reserved IP address: {cleaned}"

    # Check for AWS/GCP metadata IP tricks (e.g., decimal/octal/hex IP notations)
    try:
        # If string is a decimal integer representation of an IP
        if cleaned.isdigit():
            val = int(cleaned)
            if 0 <= val <= 0xFFFFFFFF:
                ip = ipaddress.IPv4Address(val)
                if is_ip_private_or_restricted(str(ip)):
                    return True, f"Encoded private IP address: {ip}"
    except Exception:
        pass

    return False, None
