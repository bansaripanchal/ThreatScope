"""
ThreatScope V2 - WHOIS & RDAP Intelligence Service
Retrieves authoritative registration data using RFC 7480 RDAP and port 43 WHOIS fallback.
Never invents data; clearly marks privacy-redacted fields.
"""

import json
import socket
import datetime
import requests
from typing import Dict, Any
from config import Config

class WhoisService:
    RDAP_BASE_URL = "https://rdap.org/domain"
    
    @classmethod
    def query(cls, domain: str) -> Dict[str, Any]:
        start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # Clean domain
        domain = domain.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]

        result = {
            "status": "PENDING",
            "source": "RDAP (RFC 7480) / WHOIS",
            "collection_time": start_time,
            "target": domain,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "nameservers": [],
            "domain_status": [],
            "dnssec": "Unsigned / Unknown",
            "registrant": {
                "organization": "REDACTED_FOR_PRIVACY",
                "country": "REDACTED_FOR_PRIVACY",
                "state": "REDACTED_FOR_PRIVACY"
            },
            "raw_data": None,
            "limitations": "RDAP responses reflect public ICANN/Registry databases. Personally Identifiable Information (PII) is masked by GDPR and Registrar Privacy Services."
        }

        # 1. Try RDAP query first (modern, structured, reliable)
        try:
            url = f"{cls.RDAP_BASE_URL}/{domain}"
            headers = {"User-Agent": Config.USER_AGENT, "Accept": "application/rdap+json, application/json"}
            resp = requests.get(url, headers=headers, timeout=Config.RDAP_TIMEOUT)
            
            if resp.status_code == 200:
                rdap_json = resp.json()
                result["raw_data"] = rdap_json
                
                # Extract Registrar
                entities = rdap_json.get("entities", [])
                for entity in entities:
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for prop in vcard[1]:
                                if prop[0] == "fn":
                                    result["registrar"] = prop[3]
                                    break
                
                # Extract Events (dates)
                events = rdap_json.get("events", [])
                for ev in events:
                    action = ev.get("eventAction")
                    date_str = ev.get("eventDate")
                    if action == "registration":
                        result["creation_date"] = date_str
                    elif action == "expiration":
                        result["expiration_date"] = date_str
                    elif action == "last changed" or action == "last update":
                        result["updated_date"] = date_str
                        
                # Extract Nameservers
                ns_list = rdap_json.get("nameservers", [])
                for ns in ns_list:
                    ldh_name = ns.get("ldhName")
                    if ldh_name and ldh_name.lower() not in result["nameservers"]:
                        result["nameservers"].append(ldh_name.lower())
                        
                # Extract Statuses
                status_list = rdap_json.get("status", [])
                result["domain_status"] = status_list
                
                # Extract DNSSEC
                secure_dns = rdap_json.get("secureDNS", {})
                if secure_dns:
                    delegation_signed = secure_dns.get("delegationSigned")
                    result["dnssec"] = "Signed (Active)" if delegation_signed else "Unsigned"

                result["status"] = "SUCCESS"
                return result
            elif resp.status_code == 404:
                result["status"] = "NO_DATA"
                result["limitations"] = "Target domain not found in authoritative RDAP registry."
            else:
                result["status"] = f"API_ERROR_HTTP_{resp.status_code}"
        except requests.Timeout:
            result["status"] = "TIMEOUT"
            result["limitations"] = "RDAP request timed out."
        except requests.RequestException as e:
            result["status"] = "NETWORK_ERROR"
            result["limitations"] = f"RDAP query failed: {str(e)}"
        except Exception as e:
            result["status"] = "ERROR"
            result["limitations"] = f"RDAP processing error: {str(e)}"

        # 2. Fallback to raw WHOIS socket if RDAP was inconclusive
        try:
            raw_whois = cls._query_socket_whois(domain)
            if raw_whois:
                result["raw_data"] = raw_whois
                cls._parse_raw_whois(raw_whois, result)
                result["status"] = "SUCCESS"
                result["source"] = "WHOIS (Port 43 Socket)"
        except Exception:
            pass

        if result["status"] == "PENDING":
            result["status"] = "UNAVAILABLE"

        return result

    @classmethod
    def _query_socket_whois(cls, domain: str) -> str:
        """Fallback to querying IANA or whois.verisign-grs.com over TCP port 43."""
        server = "whois.iana.org"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(Config.SOCKET_TIMEOUT * 2)
        try:
            s.connect((server, 43))
            s.sendall((domain + "\r\n").encode("utf-8"))
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            return response.decode("utf-8", errors="ignore")
        finally:
            s.close()

    @classmethod
    def _parse_raw_whois(cls, text: str, result: Dict[str, Any]):
        for line in text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip().lower()
            v = v.strip()
            if not v:
                continue
            if ("registrar" in k and not result["registrar"]):
                result["registrar"] = v
            elif ("creation date" in k or "created" in k) and not result["creation_date"]:
                result["creation_date"] = v
            elif ("expir" in k or "registry expiry date" in k) and not result["expiration_date"]:
                result["expiration_date"] = v
            elif ("updated date" in k or "last updated" in k) and not result["updated_date"]:
                result["updated_date"] = v
            elif "name server" in k:
                ns = v.lower().rstrip(".")
                if ns not in result["nameservers"]:
                    result["nameservers"].append(ns)
            elif "dnssec" in k:
                result["dnssec"] = v
