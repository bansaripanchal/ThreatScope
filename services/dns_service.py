"""
ThreatScope V2 - DNS Intelligence Service
Resolves authoritative DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA).
Performs in-depth analysis of email security TXT records (SPF, DMARC, DKIM) and CAA policies.
"""

import datetime
from typing import Dict, List, Any
from config import Config

# Try to import dnspython, with graceful socket fallback
try:
    import dns.resolver
    import dns.rdatatype
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

class DnsService:
    RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]
    COMMON_DKIM_SELECTORS = ["default", "google", "k1", "selector1", "mail", "s1", "s2017"]

    @classmethod
    def resolve(cls, target_domain: str) -> Dict[str, Any]:
        start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        domain = target_domain.strip().lower().rstrip(".")
        
        result = {
            "status": "PENDING",
            "source": "DNS Resolver (UDP/53 & RFC 1035)",
            "collection_time": start_time,
            "target": domain,
            "records": [],
            "records_by_type": {rt: [] for rt in cls.RECORD_TYPES},
            "spf": None,
            "dmarc": None,
            "dkim_indicators": [],
            "caa_records": [],
            "limitations": "Queries sent to system configured authoritative resolvers. Some record types may be omitted by upstream DNS caching or internal firewall rules."
        }

        if not HAS_DNSPYTHON:
            cls._fallback_socket_resolve(domain, result)
            return result

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = getattr(Config, "DNS_NAMESERVERS", ["8.8.8.8", "1.1.1.1"])
        resolver.timeout = Config.DNS_TIMEOUT
        resolver.lifetime = Config.DNS_TIMEOUT * 1.5

        total_records_found = 0

        # Query main record types
        for rtype in cls.RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
                if answers.rrset:
                    ttl = answers.rrset.ttl
                    for rdata in answers:
                        val = rdata.to_text().strip('"')
                        record_entry = {
                            "type": rtype,
                            "name": domain,
                            "value": val,
                            "ttl": ttl,
                            "source": "Authoritative/Recursive DNS",
                            "collection_time": start_time
                        }
                        result["records"].append(record_entry)
                        result["records_by_type"][rtype].append(record_entry)
                        total_records_found += 1
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except dns.exception.Timeout:
                pass
            except Exception:
                pass

        # Query DMARC record explicitly at _dmarc.<domain>
        try:
            dmarc_host = f"_dmarc.{domain}"
            answers = resolver.resolve(dmarc_host, "TXT", raise_on_no_answer=False)
            if answers.rrset:
                for rdata in answers:
                    txt_val = rdata.to_text().strip('"')
                    if "v=DMARC1" in txt_val.upper():
                        dmarc_record = {
                            "type": "TXT",
                            "name": dmarc_host,
                            "value": txt_val,
                            "ttl": answers.rrset.ttl,
                            "source": "Authoritative/Recursive DNS",
                            "collection_time": start_time
                        }
                        result["records"].append(dmarc_record)
                        total_records_found += 1
        except Exception:
            pass

        # Check DKIM selectors
        for selector in cls.COMMON_DKIM_SELECTORS:
            try:
                dkim_host = f"{selector}._domainkey.{domain}"
                answers = resolver.resolve(dkim_host, "TXT", raise_on_no_answer=False)
                if answers.rrset:
                    for rdata in answers:
                        txt_val = rdata.to_text().strip('"')
                        if "v=DKIM1" in txt_val.upper() or "p=" in txt_val:
                            result["dkim_indicators"].append({
                                "selector": selector,
                                "host": dkim_host,
                                "value": txt_val,
                                "status": "FOUND"
                            })
            except Exception:
                pass

        # Analyze SPF
        for r in result["records_by_type"].get("TXT", []):
            val = r["value"]
            if val.startswith("v=spf1") or "v=spf1 " in val:
                result["spf"] = cls._analyze_spf(val)
                break

        # Analyze DMARC
        for r in result["records"]:
            if r["type"] == "TXT" and "_dmarc" in r["name"].lower():
                val = r["value"]
                if "v=DMARC1" in val.upper():
                    result["dmarc"] = cls._analyze_dmarc(val)
                    break

        # Populate CAA records
        result["caa_records"] = [r["value"] for r in result["records_by_type"].get("CAA", [])]

        if total_records_found > 0:
            result["status"] = "SUCCESS"
        else:
            result["status"] = "NO_DATA"

        return result

    @classmethod
    def _analyze_spf(cls, spf_text: str) -> Dict[str, Any]:
        mechanisms = spf_text.split()
        all_mech = "None"
        for m in mechanisms:
            if m.endswith("all"):
                all_mech = m
                break
        
        strength = "WEAK"
        if all_mech == "-all":
            strength = "STRICT_HARDFAIL (-all)"
        elif all_mech == "~all":
            strength = "SOFTFAIL (~all)"
        elif all_mech == "+all":
            strength = "DANGEROUS (+all permits any host)"
        elif all_mech == "?all":
            strength = "NEUTRAL (?all)"

        return {
            "raw": spf_text,
            "mechanisms": mechanisms,
            "all_policy": all_mech,
            "strength": strength,
            "is_valid": spf_text.startswith("v=spf1")
        }

    @classmethod
    def _analyze_dmarc(cls, dmarc_text: str) -> Dict[str, Any]:
        parts = [p.strip() for p in dmarc_text.split(";") if p.strip()]
        tags = {}
        for p in parts:
            if "=" in p:
                k, v = p.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        policy = tags.get("p", "none").lower()
        subdomain_policy = tags.get("sp", policy)
        percentage = tags.get("pct", "100")
        rua = tags.get("rua", None)
        ruf = tags.get("ruf", None)

        enforcement = "NONE (Monitoring only)"
        if policy == "reject":
            enforcement = "REJECT (Strict enforcement - unauthorized mail dropped)"
        elif policy == "quarantine":
            enforcement = "QUARANTINE (Unauthorized mail flagged/sent to spam)"

        return {
            "raw": dmarc_text,
            "tags": tags,
            "policy": policy,
            "subdomain_policy": subdomain_policy,
            "percentage": percentage,
            "rua": rua,
            "ruf": ruf,
            "enforcement": enforcement
        }

    @classmethod
    def _fallback_socket_resolve(cls, domain: str, result: Dict[str, Any]):
        import socket
        try:
            ips = socket.gethostbyname_ex(domain)
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            for ip in ips[2]:
                entry = {
                    "type": "A",
                    "name": domain,
                    "value": ip,
                    "ttl": 300,
                    "source": "Standard Socket Resolver",
                    "collection_time": now
                }
                result["records"].append(entry)
                result["records_by_type"]["A"].append(entry)
            result["status"] = "PARTIAL"
        except Exception as e:
            result["status"] = "NO_DATA"
            result["limitations"] = f"Socket fallback DNS resolution failed: {str(e)}"
