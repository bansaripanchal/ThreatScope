"""
ThreatScope V2 - Target Validator & SSRF Protection
Validates domains, hostnames, IPv4, IPv6, and URLs.
Enforces SSRF prevention against private, loopback, link-local, and reserved IP ranges.
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, Optional

class TargetValidator:
    # Domain regex matching RFC 1035 / RFC 1123
    DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    
    # Private / dangerous network ranges for SSRF protection
    DISALLOWED_NETWORKS = [
        ipaddress.ip_network("0.0.0.0/8"),          # Current network
        ipaddress.ip_network("10.0.0.0/8"),         # Private RFC 1918
        ipaddress.ip_network("100.64.0.0/10"),      # Carrier-grade NAT
        ipaddress.ip_network("127.0.0.0/8"),        # Loopback
        ipaddress.ip_network("169.254.0.0/16"),     # Link-local / Cloud metadata
        ipaddress.ip_network("172.16.0.0/12"),      # Private RFC 1918
        ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
        ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
        ipaddress.ip_network("192.168.0.0/16"),     # Private RFC 1918
        ipaddress.ip_network("198.18.0.0/15"),      # Network benchmark tests
        ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
        ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
        ipaddress.ip_network("224.0.0.0/4"),        # Multicast
        ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use
        ipaddress.ip_network("255.255.255.255/32"), # Broadcast
        # IPv6
        ipaddress.ip_network("::/128"),             # Unspecified
        ipaddress.ip_network("::1/128"),            # Loopback
        ipaddress.ip_network("fc00::/7"),           # Unique local
        ipaddress.ip_network("fe80::/10"),          # Link-local
        ipaddress.ip_network("ff00::/8"),           # Multicast
    ]

    @classmethod
    def normalize_and_validate(cls, raw_target: str, allow_private: bool = False) -> Dict[str, Any]:
        """
        Normalizes and thoroughly validates a target input.
        Returns a dictionary with validation status, target type, normalized name, and SSRF status.
        """
        if not raw_target or not isinstance(raw_target, str):
            return {
                "valid": False,
                "error": "Target cannot be empty",
                "raw_target": raw_target or "",
                "normalized_target": "",
                "target_type": "UNKNOWN",
                "is_private": False
            }

        target = raw_target.strip()
        port = None
        path = "/"
        target_type = "UNKNOWN"
        normalized = ""

        # Check if URL format (e.g., http://, https://)
        if target.startswith(("http://", "https://", "ftp://")):
            try:
                parsed = urlparse(target)
                host = parsed.hostname or ""
                port = parsed.port
                path = parsed.path or "/"
                target = host
                target_type = "URL"
            except Exception as e:
                return {
                    "valid": False,
                    "error": f"Malformed URL: {str(e)}",
                    "raw_target": raw_target,
                    "normalized_target": "",
                    "target_type": "URL",
                    "is_private": False
                }
        
        # Strip trailing colon/slash if any
        if ":" in target and not target.startswith("["):
            parts = target.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                target = parts[0]
                port = int(parts[1])

        target = target.strip("/").lower()

        # Check IPv4
        try:
            ip_obj = ipaddress.IPv4Address(target)
            target_type = "IPV4" if target_type != "URL" else "URL"
            normalized = str(ip_obj)
            is_priv = cls.is_private_ip(ip_obj)
            if is_priv and not allow_private:
                return {
                    "valid": False,
                    "error": f"Target resolves to private or restricted IP range ({normalized}) which is blocked by SSRF protection policy",
                    "raw_target": raw_target,
                    "normalized_target": normalized,
                    "target_type": "IPV4",
                    "is_private": True,
                    "port": port,
                    "path": path
                }
            return {
                "valid": True,
                "error": None,
                "raw_target": raw_target,
                "normalized_target": normalized,
                "target_type": "IPV4",
                "is_private": is_priv,
                "port": port,
                "path": path
            }
        except ipaddress.AddressValueError:
            pass

        # Check IPv6
        ipv6_candidate = target.strip("[]")
        try:
            ip_obj = ipaddress.IPv6Address(ipv6_candidate)
            target_type = "IPV6" if target_type != "URL" else "URL"
            normalized = str(ip_obj)
            is_priv = cls.is_private_ip(ip_obj)
            if is_priv and not allow_private:
                return {
                    "valid": False,
                    "error": f"Target resolves to private or restricted IPv6 range ({normalized}) which is blocked by SSRF protection policy",
                    "raw_target": raw_target,
                    "normalized_target": normalized,
                    "target_type": "IPV6",
                    "is_private": True,
                    "port": port,
                    "path": path
                }
            return {
                "valid": True,
                "error": None,
                "raw_target": raw_target,
                "normalized_target": normalized,
                "target_type": "IPV6",
                "is_private": is_priv,
                "port": port,
                "path": path
            }
        except ipaddress.AddressValueError:
            pass

        # Check Domain / FQDN
        if cls.DOMAIN_REGEX.match(target):
            normalized = target
            # Verify if domain resolves to a private IP (SSRF prevention via DNS rebinding)
            resolved_ips = cls.resolve_host(normalized)
            has_private_ip = False
            private_ip_found = None
            
            for ip_str in resolved_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if cls.is_private_ip(ip_obj):
                        has_private_ip = True
                        private_ip_found = str(ip_obj)
                        break
                except Exception:
                    continue

            if has_private_ip and not allow_private:
                return {
                    "valid": False,
                    "error": f"Domain '{normalized}' resolves to private/internal IP address ({private_ip_found}) blocked by SSRF policy",
                    "raw_target": raw_target,
                    "normalized_target": normalized,
                    "target_type": "DOMAIN",
                    "is_private": True,
                    "resolved_ips": resolved_ips,
                    "port": port,
                    "path": path
                }

            return {
                "valid": True,
                "error": None,
                "raw_target": raw_target,
                "normalized_target": normalized,
                "target_type": "DOMAIN" if target_type != "URL" else "URL",
                "is_private": has_private_ip,
                "resolved_ips": resolved_ips,
                "port": port,
                "path": path
            }

        return {
            "valid": False,
            "error": "Target must be a valid Domain name (e.g. example.com), IPv4, or IPv6 address",
            "raw_target": raw_target,
            "normalized_target": target,
            "target_type": "INVALID",
            "is_private": False
        }

    @classmethod
    def is_private_ip(cls, ip_obj: ipaddress._BaseAddress) -> bool:
        """Checks if an IP address belongs to any restricted or private network."""
        for network in cls.DISALLOWED_NETWORKS:
            if ip_obj in network:
                return True
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved

    @classmethod
    def resolve_host(cls, hostname: str) -> list:
        """Safely gets IP addresses for a host without throwing exceptions."""
        try:
            results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = []
            for r in results:
                sockaddr = r[4]
                ip = sockaddr[0]
                if ip not in ips:
                    ips.append(ip)
            return ips
        except Exception:
            return []
