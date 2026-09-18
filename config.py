"""
ThreatScope V2 - Configuration
Defines application settings, reconnaissance limits, timeouts, and security constants.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

class Config:
    APP_NAME = "ThreatScope"
    APP_VERSION = "2.0.0"
    SECRET_KEY = os.environ.get("THREATSCOPE_SECRET_KEY", "threatscope-v2-dev-secret-key-change-in-prod")
    DEBUG = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")

    # Database
    DATA_DIR = DATA_DIR
    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(DATA_DIR / "threatscope.db"))

    # Concurrency & Timeouts
    MAX_WORKER_THREADS = 10
    SOCKET_TIMEOUT = 1.5  # seconds for TCP connect
    HTTP_TIMEOUT = 5.0    # seconds for HTTP/HTTPS requests
    DNS_TIMEOUT = 2.0     # seconds for DNS lookups
    DNS_NAMESERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]  # High-availability authoritative resolvers
    RDAP_TIMEOUT = 5.0    # seconds for RDAP queries

    # Bounded Safe Reconnaissance Ports
    DEFAULT_SCAN_PORTS = [
        21,    # FTP
        22,    # SSH
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        143,   # IMAP
        443,   # HTTPS
        465,   # SMTPS
        587,   # SMTP Submission
        993,   # IMAPS
        995,   # POP3S
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        8000,  # HTTP Alt / Dev
        8080,  # HTTP Proxy / Web
        8443,  # HTTPS Alt
        8888,  # HTTP Alt
    ]

    # Bounded Well-Known Public Endpoints to Probe Safely
    SAFE_PUBLIC_ENDPOINTS = [
        "/",
        "/login",
        "/admin",
        "/api",
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/health",
        "/status",
        "/docs",
        "/swagger",
        "/api/v1",
        "/.well-known/openid-configuration"
    ]

    # Common Subdomain Prefix Wordlist for Active DNS Verification
    COMMON_SUBDOMAINS = [
        "www", "mail", "api", "dev", "stage", "test", "admin", "app", 
        "portal", "vpn", "cdn", "status", "docs", "blog", "remote", 
        "secure", "auth", "login", "gateway", "support"
    ]

    # User-Agent for ethical reconnaissance
    USER_AGENT = "ThreatScope-Recon/2.0 (Security-Audit-Reconnaissance; +https://threatscope.local)"
