"""
ThreatScope V2 - Port & Service Enumeration Service
Safe, non-destructive, bounded TCP port scanning with passive service banner acquisition.
Enforces strict connection timeouts and concurrency limits.
"""

import socket
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any
from config import Config

class PortScannerService:
    KNOWN_SERVICES = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP Submission",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "Microsoft RDP",
        5432: "PostgreSQL",
        8000: "HTTP-Dev",
        8080: "HTTP-Proxy / Alt",
        8443: "HTTPS-Alt",
        8888: "HTTP-Alt"
    }

    @classmethod
    def scan_target(cls, host: str, ports: List[int] = None) -> Dict[str, Any]:
        start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        target_ports = ports or Config.DEFAULT_SCAN_PORTS

        result = {
            "status": "PENDING",
            "source": "Safe Bounded TCP Connect (RFC 793)",
            "collection_time": start_time,
            "target": host,
            "ports_scanned_count": len(target_ports),
            "open_ports_count": 0,
            "open_ports": [],
            "closed_ports": 0,
            "filtered_ports": 0,
            "limitations": "Safe non-destructive TCP connect scan bounded to standard critical service ports. UDP and stealth/SYN scanning are excluded to maintain ethical audit boundaries."
        }

        # Resolve target IP first
        try:
            target_ip = socket.gethostbyname(host)
            result["target_ip"] = target_ip
        except Exception as e:
            result["status"] = "NETWORK_ERROR"
            result["limitations"] += f" Failed to resolve host '{host}': {str(e)}"
            return result

        open_ports_list = []
        closed_count = 0
        filtered_count = 0

        # Scan using thread pool
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKER_THREADS) as executor:
            future_to_port = {
                executor.submit(cls._probe_port, target_ip, port): port
                for port in target_ports
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    port_res = future.result()
                    state = port_res["state"]
                    if state == "OPEN":
                        open_ports_list.append(port_res)
                    elif state == "CLOSED":
                        closed_count += 1
                    else:
                        filtered_count += 1
                except Exception:
                    filtered_count += 1

        # Sort open ports numerically
        open_ports_list.sort(key=lambda x: x["port"])

        result["open_ports"] = open_ports_list
        result["open_ports_count"] = len(open_ports_list)
        result["closed_ports"] = closed_count
        result["filtered_ports"] = filtered_count
        result["status"] = "SUCCESS"

        return result

    @classmethod
    def _probe_port(cls, ip: str, port: int) -> Dict[str, Any]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(Config.SOCKET_TIMEOUT)
        service_name = cls.KNOWN_SERVICES.get(port, f"Custom-{port}")

        try:
            res = sock.connect_ex((ip, port))
            if res == 0:
                banner = cls._grab_banner(sock, port)
                sock.close()
                return {
                    "port": port,
                    "protocol": "TCP",
                    "state": "OPEN",
                    "service": service_name,
                    "banner": banner
                }
            elif res in (111, 10061):  # Connection refused (Linux/Windows)
                sock.close()
                return {
                    "port": port,
                    "protocol": "TCP",
                    "state": "CLOSED",
                    "service": service_name,
                    "banner": None
                }
            else:
                sock.close()
                return {
                    "port": port,
                    "protocol": "TCP",
                    "state": "FILTERED",
                    "service": service_name,
                    "banner": None
                }
        except socket.timeout:
            sock.close()
            return {
                "port": port,
                "protocol": "TCP",
                "state": "FILTERED",
                "service": service_name,
                "banner": None
            }
        except Exception:
            sock.close()
            return {
                "port": port,
                "protocol": "TCP",
                "state": "FILTERED",
                "service": service_name,
                "banner": None
            }

    @classmethod
    def _grab_banner(cls, sock: socket.socket, port: int) -> str:
        """Safely attempt to read passive greeting banner."""
        sock.settimeout(0.6)
        try:
            # For HTTP/HTTPS ports, don't read raw banner on raw TCP socket to avoid hang
            if port in (80, 443, 8080, 8443):
                return None
            
            # Non-web ports often broadcast banner upon connect (SSH, FTP, SMTP)
            data = sock.recv(512)
            if data:
                # Clean and sanitize banner
                clean_banner = data.decode("utf-8", errors="ignore").strip()
                clean_banner = "".join(c for c in clean_banner if c.isprintable() or c in "\r\n\t")
                return clean_banner[:200]
        except Exception:
            pass
        return None
