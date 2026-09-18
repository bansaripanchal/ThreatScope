"""
ThreatScope V2 - IP Intelligence Service
Gathers IP metadata: Reverse DNS (PTR), Autonomous System Number (ASN),
Internet Service Provider (ISP), Country, Region, City, and Network blocks.
"""

import socket
import datetime
import requests
from typing import Dict, Any, List
from config import Config

class IpInfoService:
    @classmethod
    def lookup(cls, ip_address: str) -> Dict[str, Any]:
        start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        ip = ip_address.strip()

        result = {
            "status": "PENDING",
            "source": "BGP / IP Geolocation & DNS PTR",
            "collection_time": start_time,
            "ip": ip,
            "reverse_dns": None,
            "asn": None,
            "as_name": None,
            "isp": None,
            "organization": None,
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "postal": None,
            "latitude": None,
            "longitude": None,
            "timezone": None,
            "network_range": None,
            "limitations": "IP Geolocation indicates administrative allocation and approximate routing point; it does not represent physical hardware position."
        }

        # 1. Reverse DNS (PTR Lookup)
        try:
            import dns.reversename
            import dns.resolver
            rev_name = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = getattr(Config, "DNS_NAMESERVERS", ["8.8.8.8", "1.1.1.1"])
            resolver.timeout = 1.0
            resolver.lifetime = 1.5
            answers = resolver.resolve(rev_name, "PTR")
            if answers:
                result["reverse_dns"] = str(answers[0]).rstrip(".")
        except Exception:
            result["reverse_dns"] = "No PTR Record Found"

        # 2. Query Public IP Intelligence API
        try:
            # ip-api.com returns comprehensive ASN, org, city, country data
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query"
            headers = {"User-Agent": Config.USER_AGENT}
            resp = requests.get(url, headers=headers, timeout=Config.HTTP_TIMEOUT)
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    result["country"] = data.get("country")
                    result["country_code"] = data.get("countryCode")
                    result["region"] = data.get("regionName")
                    result["city"] = data.get("city")
                    result["postal"] = data.get("zip")
                    result["latitude"] = data.get("lat")
                    result["longitude"] = data.get("lon")
                    result["timezone"] = data.get("timezone")
                    result["isp"] = data.get("isp")
                    result["organization"] = data.get("org")
                    result["asn"] = data.get("as")
                    result["as_name"] = data.get("asname")
                    result["status"] = "SUCCESS"
                    return result
                else:
                    result["status"] = "PARTIAL"
                    result["limitations"] += f" Provider note: {data.get('message', 'No details available')}"
            else:
                result["status"] = f"API_ERROR_HTTP_{resp.status_code}"
        except requests.Timeout:
            result["status"] = "TIMEOUT"
            result["limitations"] += " IP Intelligence query timed out."
        except requests.RequestException as e:
            result["status"] = "NETWORK_ERROR"
            result["limitations"] += f" Network request failed: {str(e)}"
        except Exception as e:
            result["status"] = "PARTIAL"
            result["limitations"] += f" Error: {str(e)}"

        if result["reverse_dns"] and result["reverse_dns"] != "No PTR Record Found":
            result["status"] = "PARTIAL"
        elif result["status"] == "PENDING":
            result["status"] = "UNAVAILABLE"

        return result

    @classmethod
    def lookup_multiple(cls, ip_addresses: List[str]) -> List[Dict[str, Any]]:
        results = []
        for ip in ip_addresses[:5]:  # Bound to top 5 IPs to avoid rate limits
            results.append(cls.lookup(ip))
        return results
