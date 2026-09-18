"""
ThreatScope V2 - SSL / TLS Intelligence Service
Performs in-depth TLS handshakes to extract X.509 certificates, Subject Alternative Names (SANs),
validity windows, cipher suites, TLS protocol versions, and security condition flags.
"""

import ssl
import socket
import datetime
from typing import Dict, Any, List
from config import Config

class SslService:
    @classmethod
    def inspect(cls, host: str, port: int = 443) -> Dict[str, Any]:
        start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        host_clean = host.strip().lower()

        result = {
            "status": "PENDING",
            "source": "Direct TLS Handshake (RFC 8446)",
            "collection_time": start_time,
            "target": f"{host_clean}:{port}",
            "subject": {"common_name": None, "organization": None, "country": None},
            "issuer": {"common_name": None, "organization": None, "country": None},
            "serial_number": None,
            "valid_from": None,
            "valid_until": None,
            "days_remaining": None,
            "sans": [],
            "tls_version": None,
            "cipher": None,
            "hostname_verified": False,
            "conditions": [],
            "certificate_chain": [],
            "limitations": "Direct TLS handshake retrieves leaf certificate presented by the target server for the specified SNI."
        }

        # Setup TLS Context
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # Manual verification allows collecting cert even if name mismatches
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host_clean, port), timeout=Config.SOCKET_TIMEOUT * 2) as sock:
                with ctx.wrap_socket(sock, server_hostname=host_clean) as ssock:
                    # Negotiated Protocol & Cipher
                    result["tls_version"] = ssock.version()
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        result["cipher"] = {
                            "name": cipher_info[0],
                            "protocol": cipher_info[1],
                            "bits": cipher_info[2]
                        }

                    # Fetch certificate dictionary
                    cert = ssock.getpeercert(binary_form=False)
                    
                    if not cert:
                        # Re-connect with cert verification to parse DER if unverified returned empty
                        cert = cls._fetch_verified_cert(host_clean, port)

                    if cert:
                        cls._parse_certificate(cert, host_clean, result)
                        result["status"] = "SUCCESS"
                    else:
                        result["status"] = "NO_DATA"
                        result["limitations"] += " Server did not present a decodable X.509 certificate."

        except ssl.SSLError as e:
            result["status"] = "TLS_FAILURE"
            result["conditions"].append(f"TLS Handshake Error: {str(e)}")
            result["limitations"] += f" SSL Error: {str(e)}"
        except socket.timeout:
            result["status"] = "TIMEOUT"
            result["limitations"] += f" Connection to {host_clean}:{port} timed out."
        except ConnectionRefusedError:
            result["status"] = "UNAVAILABLE"
            result["limitations"] += f" Port {port} connection refused."
        except Exception as e:
            result["status"] = "NETWORK_ERROR"
            result["limitations"] += f" TLS connection error: {str(e)}"

        return result

    @classmethod
    def _fetch_verified_cert(cls, host: str, port: int) -> Dict[str, Any]:
        """Fetch certificate using default verified context to retrieve parsed fields."""
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=Config.SOCKET_TIMEOUT * 2) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.getpeercert()
        except Exception:
            return {}

    @classmethod
    def _parse_certificate(cls, cert: Dict[str, Any], host: str, result: Dict[str, Any]):
        # Subject extraction
        subject_dict = {}
        for rdn in cert.get("subject", []):
            for key, val in rdn:
                subject_dict[key] = val
        result["subject"] = {
            "common_name": subject_dict.get("commonName"),
            "organization": subject_dict.get("organizationName"),
            "country": subject_dict.get("countryName"),
            "raw": subject_dict
        }

        # Issuer extraction
        issuer_dict = {}
        for rdn in cert.get("issuer", []):
            for key, val in rdn:
                issuer_dict[key] = val
        result["issuer"] = {
            "common_name": issuer_dict.get("commonName"),
            "organization": issuer_dict.get("organizationName"),
            "country": issuer_dict.get("countryName"),
            "raw": issuer_dict
        }

        # Serial Number
        result["serial_number"] = cert.get("serialNumber")

        # Dates & Expiry
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        result["valid_from"] = not_before
        result["valid_until"] = not_after

        # SANs (Subject Alternative Names)
        sans = []
        for san_type, san_val in cert.get("subjectAltName", []):
            if san_type == "DNS":
                sans.append(san_val)
        result["sans"] = sans

        # Condition checks
        conditions = []
        if not_after:
            try:
                # Format: 'May 15 12:00:00 2025 GMT'
                exp_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                delta = exp_date - now
                result["days_remaining"] = delta.days

                if delta.days < 0:
                    conditions.append(f"EXPIRED (Certificate expired {abs(delta.days)} days ago)")
                elif delta.days <= 14:
                    conditions.append(f"CRITICAL_EXPIRING_SOON (Expires in {delta.days} days)")
                elif delta.days <= 30:
                    conditions.append(f"EXPIRING_SOON (Expires in {delta.days} days)")
            except Exception:
                pass

        if not_before:
            try:
                start_date = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                if datetime.datetime.now(datetime.timezone.utc) < start_date:
                    conditions.append("NOT_YET_VALID (Certificate start date is in the future)")
            except Exception:
                pass

        # Hostname verification check against Common Name & SANs
        cn = subject_dict.get("commonName", "").lower()
        matched = False
        all_names = [cn] + [s.lower() for s in sans]
        
        for name in all_names:
            if not name:
                continue
            if name == host:
                matched = True
                break
            if name.startswith("*."):
                wildcard_base = name[2:]
                if host.endswith(wildcard_base) and host.count(".") == name.count("."):
                    matched = True
                    break

        result["hostname_verified"] = matched
        if not matched:
            conditions.append(f"HOSTNAME_MISMATCH (Server presents cert for '{cn}', requested '{host}')")

        # Weak protocol detection
        tls_ver = result.get("tls_version", "")
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            conditions.append(f"DEPRECATED_PROTOCOL ({tls_ver} is cryptographically insecure)")

        result["conditions"] = conditions
