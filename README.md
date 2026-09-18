# ThreatScope V2
### Ethical Hacking &bull; Reconnaissance &bull; VAPT &bull; Attack-Surface Intelligence

ThreatScope V2 is a completely new, professional, full-stack cybersecurity web application built from zero for authorized security testers, penetration testers, and security researchers. It provides comprehensive automated reconnaissance, enumeration, attack surface mapping, evidence-backed findings, timeline auditing, scan-to-scan comparison, and professional 23-section reporting.

---

## 1. Project Purpose & Scope

ThreatScope is designed for:
- **Ethical Hacking & Penetration Testing Pre-Engagement Reconnaissance**
- **External Attack Surface Management (EASM)**
- **Vulnerability Assessment & Penetration Testing (VAPT) Perimeter Auditing**
- **Authoritative Open-Source Intelligence (OSINT) Aggregation**

### What ThreatScope IS NOT:
- **NOT** a SOC (Security Operations Center)
- **NOT** a SIEM (Security Information and Event Management)
- **NOT** an EDR (Endpoint Detection and Response)
- **NOT** a Ransomware or Antivirus agent
- **NOT** an Endpoint file or process monitor
- **NOT** an automated exploitation or payload delivery tool

---

## 2. Product Reconnaissance Workflow

The entire platform operates as a cohesive, connected intelligence system:

```
TARGET
  ↓
RECONNAISSANCE (WHOIS/RDAP, DNS, BGP IP Geolocation)
  ↓
ENUMERATION (Safe Bounded TCP Connect, Subdomains, Endpoints)
  ↓
ATTACK SURFACE (Interactive Topological Asset Graph)
  ↓
EVIDENCE (Raw Socket Handshakes, Headers, Cryptographic Records)
  ↓
FINDINGS (Deterministic Severity Rules: Critical, High, Medium, Low)
  ↓
TIMELINE (Chronological Audit Event Log with Durations)
  ↓
COMPARISON (Added, Removed, Changed, Unchanged Deltas)
  ↓
PROFESSIONAL REPORT (23-Section Printable / PDF-Ready Audit Dossier)
```

---

## 3. Global Design System & Themes

ThreatScope features a custom, technical, and data-focused user interface:
- **Zero Cyberpunk / Zero Gaming Gimmicks / Zero Excessive Glow**: Engineered with crisp borders, clear visual hierarchy, and high data density.
- **Brand Accent**: Deep Purple (`#7C3AED` / `#8B5CF6`).
- **Dual Themes**:
  - **Dark Mode**: Deep navy and charcoal surfaces (`#0B0F19`, `#111827`, `#161F30`), crisp typography, subtle slate borders.
  - **Light Mode**: Pure slate and white surfaces (`#F8FAFC`, `#FFFFFF`), deep navy text, subtle drop shadows.
  - **Persistence**: Global toggle in the top navigation bar, saved instantly via `localStorage` with flicker-free initialization.
- **Typography**: Inter / Segoe UI for interfaces; JetBrains Mono / Consolas for raw logs, hashes, and IP addresses.

---

## 4. Key Features & Telemetry Capabilities

### 1. Target Validation & SSRF Guard Rails
- Supports domain names (FQDN), hostnames, IPv4, IPv6, and URLs.
- Input normalization (automatically strips schemes like `https://` and trailing paths).
- Enforces SSRF protections: blocks loopback (`127.0.0.0/8`, `::1`), RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/cloud metadata (`169.254.169.254`), and multicast addresses.
- Optional toggle for authorized internal penetration testing labs.

### 2. Investigation Workspace & Detail Drawers
- Central investigation console with live status polling (`PENDING` &rarr; `RUNNING` &rarr; `COMPLETED` / `PARTIAL`).
- Target overview card with quick action buttons (`[Attack Surface]`, `[Timeline]`, `[Generate Report]`, `[Compare]`).
- Compact metrics pills for IPs, subdomains, open ports, endpoints, technologies, and findings.
- Organized tab panels with slide-in **[ View Details ]** drawers explaining *What this means*, *What ThreatScope found*, *Technical telemetry*, *Evidence*, *Source*, *Collection timestamp*, and *Limitations*.

### 3. WHOIS & RDAP Intelligence
- Authoritative ICANN Registration Data Access Protocol (RFC 7480) query with fallback to TCP port 43 WHOIS sockets.
- Collects registrar, creation date, expiration date, updated date, nameservers, domain statuses, and DNSSEC.
- Privacy-protected registrant info is explicitly recorded as `REDACTED_FOR_PRIVACY` rather than invented.

### 4. DNS Intelligence & Email Security
- Queries authoritative records: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`, `CAA`.
- **SPF Analysis**: Evaluates qualifier strictness (`-all` hardfail vs `~all` softfail vs `+all` dangerous).
- **DMARC Analysis**: Checks `_dmarc.<domain>` for policy enforcement (`p=reject`, `p=quarantine`, `p=none`).
- **DKIM Indicators**: Probes standard selectors (`default`, `google`, `k1`, `selector1`).
- **CAA Checks**: Discovers authorized Certificate Authorities permitted to issue certificates.

### 5. IP Intelligence & ASN
- Resolves reverse DNS PTR records.
- Queries Autonomous System Number (ASN), BGP network range, ISP/Organization, and country/city coordinates.

### 6. Safe Port & Service Enumeration
- Safe, non-destructive, bounded TCP connect scanning (RFC 793) against standard security audit ports (21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8000, 8080, 8443, 8888).
- Safe banner acquisition on open services without sending hostile payloads.

### 7. SSL / TLS Inspection
- Direct TLS socket handshake retrieving X.509 leaf certificate details.
- Extracts Common Name (CN), Issuer, Serial, Valid From, Valid Until, Days Remaining, and Subject Alternative Names (SANs).
- Evaluates conditions: Expired, Expiring Soon (&le;30 days), Hostname Mismatch, and Deprecated TLS Protocols (TLS 1.0/1.1).

### 8. HTTP & Security Headers
- Full HTTP GET/HEAD response telemetry with redirect history tracing.
- Granular evaluation of 6 defensive headers: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- Factual configuration assessment without arbitrary scores.

### 9. Technology Detection
- Passively detects Web Servers, CDNs, CMSs, Frameworks, JavaScript libraries, and Analytics from headers, cookies, and HTML signatures.

### 10. Subdomain Intelligence
- Aggregates subdomains from public Certificate Transparency (CT) logs (`crt.sh`) and active DNS probing.
- Probes live status (`ACTIVE` vs `UNRESOLVED`) and HTTP/HTTPS responses.

### 11. Web Endpoint Discovery
- Safe, bounded checks of standard administrative and API paths (`/login`, `/admin`, `/api`, `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, `/docs`, `/swagger`).
- Same-origin hyperlink extraction from homepage HTML (bounded depth 1, max 15 links).

### 12. Interactive Attack Surface Map
- Force-directed physics canvas graph visualizer built from scratch with zero external CDN dependencies.
- Typed nodes: `target`, `domain`, `subdomain`, `ip`, `port`, `service`, `endpoint`, `technology`, `certificate`, `dns_record`.
- Typed relationships: `RESOLVES_TO`, `HAS_SUBDOMAIN`, `EXPOSES_PORT`, `RUNS_SERVICE`, `USES_TECH`, `HAS_CERT`, `CONTAINS_ENDPOINT`.
- Includes zoom, pan, fit-to-center, text search, node category filter chips, and floating node inspector.

### 13. Verifiable Findings Engine
- Deterministic rules evaluating collected telemetry into categorized findings: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATION`, `OBSERVATION`.
- Each finding includes Title, Description, Affected Asset, Verifiable Evidence, Source, and Actionable Remediation.

### 14. Reconnaissance Timeline
- Chronological execution log recording timestamp, operation, duration (ms), status (`SUCCESS`, `PARTIAL`, `FAILED`), and message.

### 15. Reconnaissance Comparison
- Multi-dimensional diff engine between any two scans.
- Classifies changes as `ADDED`, `REMOVED`, `CHANGED`, or `UNCHANGED` across subdomains, IPs, ports, services, technologies, DNS, SSL, endpoints, and findings.

### 16. Standalone Tools Suite
- Quick, on-demand modules on `/tools` for instant lookups (WHOIS, DNS, IP, Ports, SSL, Headers, Subdomains, Endpoints) with immediate telemetry rendering.

### 17. Professional 23-Section Report
Full technical dossier featuring all 23 required audit sections:
1. Cover Page
2. Target Specification
3. Investigation Information
4. Scope & Rules of Engagement
5. Executive Summary
6. Target Overview & Inventory
7. WHOIS & RDAP Registration Intelligence
8. DNS Intelligence & Email Authentication
9. IP & Network Routing Intelligence
10. Subdomain Intelligence
11. Web Endpoint Discovery
12. Port & Service Enumeration
13. SSL / TLS Cryptographic Inspection
14. HTTP Response & Server Headers
15. Defensive Security Headers Evaluation
16. Technology Detection Inventory
17. Attack Surface Graph Structure
18. Verifiable Findings
19. Technical Evidence Index
20. Prioritized Strategic Recommendations
21. Reconnaissance Audit Timeline
22. Comparison & Delta Information
23. Reconnaissance Limitations & Intelligence Sources

Includes print-optimized CSS (`@media print`) for clean browser Print-to-PDF export with page breaks.

---

## 5. Project Structure

```
threatscope/
├── app.py                      # Flask application factory
├── config.py                   # Configuration, timeouts, ports, wordlists
├── requirements.txt            # Python dependencies
├── run.py                      # Standalone server launcher
├── README.md                   # Comprehensive project documentation
│
├── database/
│   ├── __init__.py
│   ├── db.py                   # SQLite schema initialization and connection manager
│   └── repository.py           # CRUD repository for investigations, timeline, findings
│
├── services/
│   ├── __init__.py
│   ├── target_validator.py     # Domain/IP normalization and SSRF guard rails
│   ├── whois_service.py        # RFC 7480 RDAP and port 43 WHOIS fallback
│   ├── dns_service.py          # A/AAAA/MX/TXT/CAA queries, SPF and DMARC analyzer
│   ├── ipinfo_service.py       # Reverse DNS PTR, ASN, ISP, Geolocation
│   ├── port_scanner_service.py # Safe bounded TCP connect scan with banner grabbing
│   ├── ssl_service.py          # X.509 certificate parser, SANs, cipher, condition flags
│   ├── http_service.py         # HTTP/HTTPS requests, redirects, raw headers, cookies
│   ├── security_headers_service.py # Evaluates CSP, HSTS, XFO, XCTO, Referrer, Permissions
│   ├── technology_service.py   # Web server, CMS, frameworks, and JS signatures
│   ├── subdomain_service.py    # crt.sh Certificate Transparency logs + active DNS
│   ├── endpoint_service.py     # Safe public well-known paths & same-origin links
│   ├── attack_surface_service.py # Builds typed nodes and relational edges
│   ├── finding_service.py      # Deterministic evidence-backed findings engine
│   ├── timeline_service.py     # Chronological audit event logger
│   ├── comparison_service.py   # Scan comparison and delta classifier
│   ├── investigation_service.py# Orchestrator running background thread execution
│   └── report_service.py       # 23-section report compiler
│
├── routes/
│   ├── __init__.py
│   ├── web_routes.py           # HTML views: Dashboard, Workspace, Map, Compare, Reports
│   └── api_routes.py           # REST API endpoints
│
├── templates/
│   ├── base.html               # Main layout, nav, theme toggle, detail drawer
│   ├── dashboard.html          # Stats cards, pipeline visual, recent investigations
│   ├── investigate.html        # Target submission form with SSRF controls
│   ├── workspace.html          # Central investigation console with all telemetry tabs
│   ├── attack_surface.html     # Interactive canvas graph view with node inspector
│   ├── timeline.html           # Audit timeline view
│   ├── compare.html            # Scan delta selection and diff breakdown
│   ├── history.html            # Past investigations log with delete capability
│   ├── report.html             # Full 23-section report with print-to-PDF button
│   ├── tools.html              # Standalone quick recon tools
│   └── about.html              # Architecture, ethics, and methodology
│
├── static/
│   ├── css/
│   │   ├── design_system.css   # Color tokens, light/dark themes, typography
│   │   ├── components.css      # Buttons, cards, tables, badges, tabs, drawers, modals
│   │   ├── attack_surface.css  # Canvas container, filters, inspector
│   │   └── report.css          # Report layout and print/PDF formatting
│   ├── js/
│   │   ├── app.js              # Theme switcher, drawer logic, tab handlers
│   │   ├── workspace.js        # Status polling and live timeline updater
│   │   ├── attack_surface.js   # Force-directed physics canvas graph
│   │   ├── compare.js          # Comparison runner
│   │   └── tools.js            # Standalone tools AJAX runner
│   └── assets/
│       └── logo.svg            # ThreatScope brand mark
│
└── tests/
    ├── __init__.py
    ├── test_validator.py       # Normalization and SSRF blocking tests
    ├── test_dns.py             # DNS, SPF, and DMARC analysis tests
    ├── test_ssl.py             # SSL certificate parser and expiry tests
    ├── test_security_headers.py# Security headers strength tests
    ├── test_technology.py      # Technology signature tests
    ├── test_findings.py        # Finding generation from evidence tests
    ├── test_comparison.py      # Delta computation tests
    ├── test_database.py        # SQLite persistence and CRUD tests
    └── test_report.py          # 23-section report integrity tests
```

---

## 6. Installation & Execution

### Prerequisites
- Python 3.9+ installed.

### Setup Instructions
1. Navigate to the project directory:
   ```bash
   cd threatscope
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python run.py
   ```
4. Access the web interface in your browser:
   ```
   http://127.0.0.1:5000
   ```

---

## 7. Running the Automated Test Suite

Execute all unit and integration tests using Python's built-in `unittest` runner:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

All 9 test modules verify target validation, SSRF blocking, DNS record parsing, SPF/DMARC analysis, SSL condition checks, security headers, technology signatures, findings heuristics, delta comparisons, database persistence, and 23-section report completeness.

---

## 8. Ethical Use & Legal Rules of Engagement

> [!IMPORTANT]
> ThreatScope is intended solely for authorized security assessments, penetration tests, and defensive attack surface auditing. Testing targets without prior written authorization from the target owner may violate computer fraud and abuse legislation. Always operate within agreed rules of engagement.
