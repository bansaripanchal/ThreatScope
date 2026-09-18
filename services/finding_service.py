"""
ThreatScope V2 - Findings Engine
Generates deterministic, evidence-backed security findings and technical observations
based strictly on verified reconnaissance telemetry.
"""

from datetime import datetime, timezone
from typing import Dict, List, Any

class FindingService:
    @classmethod
    def evaluate(cls, target: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        now = datetime.now(timezone.utc).isoformat()

        def add_finding(title: str, severity: str, description: str, 
                        affected_asset: str, evidence: str, source: str, recommendation: str):
            findings.append({
                "title": title,
                "severity": severity.upper(),
                "description": description,
                "affected_asset": affected_asset,
                "evidence": evidence,
                "source": source,
                "timestamp": now,
                "recommendation": recommendation
            })

        # -------------------------------------------------------------
        # 1. SSL / TLS Findings
        # -------------------------------------------------------------
        ssl_data = data.get("ssl", {})
        if ssl_data and ssl_data.get("status") == "SUCCESS":
            conditions = ssl_data.get("conditions", [])
            days_rem = ssl_data.get("days_remaining")
            tls_ver = ssl_data.get("tls_version")
            
            for cond in conditions:
                if "EXPIRED" in cond:
                    add_finding(
                        title="Expired SSL/TLS Certificate",
                        severity="HIGH",
                        description=f"The presented X.509 certificate for {target} has passed its validity period.",
                        affected_asset=f"{target}:443",
                        evidence=f"Valid until: {ssl_data.get('valid_until')} ({cond})",
                        source="Direct TLS Handshake",
                        recommendation="Renew and deploy an active valid X.509 certificate immediately."
                    )
                elif "CRITICAL_EXPIRING_SOON" in cond:
                    add_finding(
                        title="SSL/TLS Certificate Expiring Imminently",
                        severity="HIGH",
                        description=f"The SSL/TLS certificate will expire in {days_rem} days.",
                        affected_asset=f"{target}:443",
                        evidence=f"Days remaining: {days_rem}; Expiry: {ssl_data.get('valid_until')}",
                        source="Direct TLS Handshake",
                        recommendation="Trigger immediate certificate renewal to prevent outage or browser security warnings."
                    )
                elif "EXPIRING_SOON" in cond:
                    add_finding(
                        title="SSL/TLS Certificate Expiring Soon",
                        severity="MEDIUM",
                        description=f"The SSL/TLS certificate will expire within 30 days ({days_rem} days remaining).",
                        affected_asset=f"{target}:443",
                        evidence=f"Days remaining: {days_rem}; Expiry: {ssl_data.get('valid_until')}",
                        source="Direct TLS Handshake",
                        recommendation="Schedule certificate renewal via automated ACME/Let's Encrypt or your Certificate Authority."
                    )
                elif "HOSTNAME_MISMATCH" in cond:
                    add_finding(
                        title="SSL/TLS Hostname Mismatch",
                        severity="HIGH",
                        description=f"The Common Name and Subject Alternative Names on the certificate do not match the requested target '{target}'.",
                        affected_asset=f"{target}:443",
                        evidence=f"{cond}; Subject CN: {ssl_data.get('subject', {}).get('common_name')}",
                        source="Direct TLS Handshake",
                        recommendation="Reissue the certificate to include the exact FQDN in the Subject Alternative Names (SAN) extension."
                    )
                elif "DEPRECATED_PROTOCOL" in cond:
                    add_finding(
                        title=f"Deprecated TLS Protocol ({tls_ver}) Negotiated",
                        severity="HIGH",
                        description=f"The server negotiated an obsolete cryptographic protocol ({tls_ver}) vulnerable to cipher degradation.",
                        affected_asset=f"{target}:443",
                        evidence=f"Negotiated protocol: {tls_ver}",
                        source="Direct TLS Handshake",
                        recommendation="Disable TLS 1.0 and TLS 1.1 on the web server; mandate TLS 1.2 and TLS 1.3 exclusively."
                    )

            if not conditions and days_rem is not None and days_rem > 30:
                add_finding(
                    title="Valid Modern SSL/TLS Certificate Deployed",
                    severity="OBSERVATION",
                    description=f"The server presents a valid certificate issued by {ssl_data.get('issuer', {}).get('organization', 'CA')} with {days_rem} days remaining.",
                    affected_asset=f"{target}:443",
                    evidence=f"Protocol: {tls_ver}; Cipher: {ssl_data.get('cipher', {}).get('name')}; Expiry: {ssl_data.get('valid_until')}",
                    source="Direct TLS Handshake",
                    recommendation="Maintain automated certificate renewal monitoring."
                )

        # -------------------------------------------------------------
        # 2. Security Headers Findings
        # -------------------------------------------------------------
        sec_headers = data.get("security_headers", {})
        headers_list = sec_headers.get("headers", []) if isinstance(sec_headers, dict) else []
        for h in headers_list:
            if not isinstance(h, dict):
                continue
            h_name = h.get("header")
            status = h.get("status")
            val = h.get("value")

            if status == "MISSING":
                if h_name == "Content-Security-Policy":
                    add_finding(
                        title="Missing Content-Security-Policy Header",
                        severity="MEDIUM",
                        description="No Content-Security-Policy header was detected in the HTTP response. Browsers will execute any inline or third-party scripts loaded by the page.",
                        affected_asset=target,
                        evidence="Header 'Content-Security-Policy' is absent from HTTP response",
                        source="HTTP Response Headers Analysis",
                        recommendation=h.get("recommendation", "Implement a restrictive CSP header.")
                    )
                elif h_name == "Strict-Transport-Security":
                    add_finding(
                        title="Missing Strict-Transport-Security (HSTS) Header",
                        severity="MEDIUM",
                        description="HSTS is missing, leaving visitors susceptible to SSL-stripping and man-in-the-middle protocol downgrade attacks.",
                        affected_asset=target,
                        evidence="Header 'Strict-Transport-Security' is absent from HTTP response",
                        source="HTTP Response Headers Analysis",
                        recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
                    )
                elif h_name == "X-Frame-Options":
                    add_finding(
                        title="Missing X-Frame-Options (Clickjacking Risk)",
                        severity="MEDIUM",
                        description="The absence of X-Frame-Options or CSP frame-ancestors permits external domains to embed this site inside an iframe, creating Clickjacking vulnerabilities.",
                        affected_asset=target,
                        evidence="Header 'X-Frame-Options' is absent from HTTP response",
                        source="HTTP Response Headers Analysis",
                        recommendation="Send 'X-Frame-Options: SAMEORIGIN' or 'DENY' with all responses."
                    )
                elif h_name == "X-Content-Type-Options":
                    add_finding(
                        title="Missing X-Content-Type-Options Header",
                        severity="LOW",
                        description="The MIME-sniffing prevention header is missing. Browsers may interpret non-executable content as executable script.",
                        affected_asset=target,
                        evidence="Header 'X-Content-Type-Options' is absent",
                        source="HTTP Response Headers Analysis",
                        recommendation="Set 'X-Content-Type-Options: nosniff'."
                    )
                elif h_name == "Referrer-Policy":
                    add_finding(
                        title="Missing Referrer-Policy Header",
                        severity="LOW",
                        description="Without an explicit Referrer-Policy, user navigating to external links may leak path parameters or tokens in HTTP Referer headers.",
                        affected_asset=target,
                        evidence="Header 'Referrer-Policy' is absent",
                        source="HTTP Response Headers Analysis",
                        recommendation="Set 'Referrer-Policy: strict-origin-when-cross-origin'."
                    )
                elif h_name == "Permissions-Policy":
                    add_finding(
                        title="Missing Permissions-Policy Header",
                        severity="LOW",
                        description="Browser device hardware features (camera, microphone, geolocation) are not restricted by policy.",
                        affected_asset=target,
                        evidence="Header 'Permissions-Policy' is absent",
                        source="HTTP Response Headers Analysis",
                        recommendation="Configure a restrictive Permissions-Policy."
                    )
            elif status == "SUBOPTIMAL":
                if h_name == "Content-Security-Policy" and ("'unsafe-inline'" in (val or "") or "'unsafe-eval'" in (val or "")):
                    add_finding(
                        title="Permissive Content-Security-Policy Directives",
                        severity="LOW",
                        description="The CSP contains 'unsafe-inline' or 'unsafe-eval' which weakens defense against Cross-Site Scripting.",
                        affected_asset=target,
                        evidence=f"Content-Security-Policy: {val[:80]}...",
                        source="HTTP Response Headers Analysis",
                        recommendation="Refactor inline scripts to use cryptographic nonces or hashes rather than 'unsafe-inline'."
                    )

        # -------------------------------------------------------------
        # 3. DNS & Email Security Findings
        # -------------------------------------------------------------
        dns_data = data.get("dns", {})
        if not isinstance(dns_data, dict):
            dns_data = {}
        spf = dns_data.get("spf")
        dmarc = dns_data.get("dmarc")

        if dns_data.get("status") in ("SUCCESS", "PARTIAL"):
            if not spf:
                add_finding(
                    title="Missing SPF Record (Email Spoofing Risk)",
                    severity="MEDIUM",
                    description=f"Domain {target} lacks a Sender Policy Framework (SPF) record. Malicious actors can forge mail originating from this domain.",
                    affected_asset=target,
                    evidence="No TXT record starting with 'v=spf1' located in DNS",
                    source="Authoritative DNS TXT Analysis",
                    recommendation="Publish an authorized SPF TXT record designating legitimate mail sending servers (e.g. 'v=spf1 mx -all')."
                )
            elif spf and "+all" in spf.get("all_policy", ""):
                add_finding(
                    title="Dangerous Permissive SPF Policy (+all)",
                    severity="HIGH",
                    description="The SPF record specifies '+all', which explicitly authorizes all IP addresses on the internet to send mail for this domain.",
                    affected_asset=target,
                    evidence=f"SPF record: {spf.get('raw')}",
                    source="Authoritative DNS TXT Analysis",
                    recommendation="Change '+all' to strict hardfail '-all' or softfail '~all'."
                )

            if not dmarc:
                add_finding(
                    title="Missing DMARC Policy Record",
                    severity="MEDIUM",
                    description=f"No DMARC policy found at _dmarc.{target}. Inbound receiving mail servers cannot verify SPF/DKIM alignment or report spoofing attempts.",
                    affected_asset=f"_dmarc.{target}",
                    evidence=f"DNS query for TXT at _dmarc.{target} returned no DMARC record",
                    source="Authoritative DNS TXT Analysis",
                    recommendation="Publish a DMARC policy at _dmarc." + target + " with at least 'v=DMARC1; p=quarantine;' or 'p=reject;'."
                )
            elif dmarc and dmarc.get("policy") == "none":
                add_finding(
                    title="DMARC Policy in Monitoring-Only Mode (p=none)",
                    severity="LOW",
                    description="The DMARC policy is set to 'p=none', meaning spoofed or unauthenticated emails are delivered to user inboxes without rejection or quarantine.",
                    affected_asset=f"_dmarc.{target}",
                    evidence=f"DMARC record: {dmarc.get('raw')}",
                    source="Authoritative DNS TXT Analysis",
                    recommendation="Transition DMARC policy from 'p=none' to 'p=quarantine' and ultimately 'p=reject'."
                )

            # CAA Records
            caa_recs = dns_data.get("caa_records", [])
            if not caa_recs:
                add_finding(
                    title="Missing DNS CAA Records",
                    severity="OBSERVATION",
                    description="No Certification Authority Authorization (CAA) record is published. Any public CA may issue certificates for this domain.",
                    affected_asset=target,
                    evidence="No CAA records found in DNS",
                    source="Authoritative DNS Query",
                    recommendation="Add CAA records in DNS specifying which Certificate Authorities are authorized to issue certificates (e.g., Let's Encrypt, DigiCert)."
                )

        # -------------------------------------------------------------
        # 4. Port & Service Findings
        # -------------------------------------------------------------
        ports_data = data.get("ports", {})
        open_ports = ports_data.get("open_ports", []) if isinstance(ports_data, dict) else []
        for op in open_ports:
            if not isinstance(op, dict):
                continue
            p_num = op.get("port")
            p_svc = op.get("service", "")
            banner = op.get("banner")

            if p_num == 21:
                add_finding(
                    title="Exposed Insecure FTP Service (Port 21)",
                    severity="HIGH",
                    description="Unencrypted File Transfer Protocol (FTP) port is open. Plaintext credentials may be transmitted across the network.",
                    affected_asset=f"{target}:21",
                    evidence=f"TCP Port 21 OPEN; Banner: {banner or 'Standard FTP'}",
                    source="TCP Connect Port Scanner",
                    recommendation="Disable plaintext FTP in favor of SFTP (SSH File Transfer Protocol) or FTPS with mandatory TLS."
                )
            elif p_num in (3306, 5432):
                add_finding(
                    title=f"Exposed Database Listener ({p_svc} on Port {p_num})",
                    severity="HIGH",
                    description=f"Database port {p_num} is directly reachable from public networks, exposing it to brute-force or exploitation attempts.",
                    affected_asset=f"{target}:{p_num}",
                    evidence=f"TCP Port {p_num} OPEN ({p_svc})",
                    source="TCP Connect Port Scanner",
                    recommendation="Restrict database ports behind firewall rules, VPCs, or VPN tunnels rather than exposing them publicly."
                )
            elif p_num == 3389:
                add_finding(
                    title="Exposed Remote Desktop (RDP Port 3389)",
                    severity="HIGH",
                    description="Microsoft Remote Desktop Service is publicly reachable, posing a risk of credential stuffing and automated exploit targeting.",
                    affected_asset=f"{target}:3389",
                    evidence="TCP Port 3389 OPEN",
                    source="TCP Connect Port Scanner",
                    recommendation="Place RDP access behind a zero-trust network access (ZTNA) solution, VPN, or IP allowlist."
                )

        # -------------------------------------------------------------
        # 5. Technology / Information Disclosure Findings
        # -------------------------------------------------------------
        http_data = data.get("http", {})
        if not isinstance(http_data, dict):
            http_data = {}
        server_header = http_data.get("server")
        if server_header and any(c.isdigit() for c in server_header):
            add_finding(
                title="Server Version Number Disclosed in HTTP Header",
                severity="LOW",
                description=f"The HTTP Server header discloses exact software version ({server_header}), aiding attackers in identifying known CVEs.",
                affected_asset=target,
                evidence=f"Server: {server_header}",
                source="HTTP Response Analysis",
                recommendation="Configure web server to suppress exact version strings (e.g. 'ServerTokens Prod' in Apache or 'server_tokens off' in Nginx)."
            )

        # Cookie security
        cookie_list = http_data.get("set_cookies", []) if isinstance(http_data, dict) else []
        for cookie in cookie_list:
            if not isinstance(cookie, dict):
                continue
            cname = cookie.get("name")
            if not cookie.get("secure") and http_data.get("scheme") == "https":
                add_finding(
                    title=f"Cookie '{cname}' Missing 'Secure' Flag",
                    severity="LOW",
                    description=f"Cookie '{cname}' was set over HTTPS without the 'Secure' attribute, meaning it could be transmitted over unencrypted HTTP.",
                    affected_asset=f"Cookie: {cname}",
                    evidence=f"Set-Cookie attributes: secure={cookie.get('secure')}, httponly={cookie.get('httponly')}",
                    source="HTTP Response Headers Analysis",
                    recommendation="Append the 'Secure' flag to all session and tracking cookies."
                )
            if not cookie.get("httponly") and any(term in cname.lower() for term in ["sess", "auth", "token", "jwt"]):
                add_finding(
                    title=f"Session Cookie '{cname}' Missing 'HttpOnly' Flag",
                    severity="MEDIUM",
                    description=f"Authentication/session cookie '{cname}' lacks the 'HttpOnly' flag, permitting client-side scripts to access it via JavaScript document.cookie.",
                    affected_asset=f"Cookie: {cname}",
                    evidence=f"Set-Cookie: {cname}; httponly=False",
                    source="HTTP Response Headers Analysis",
                    recommendation="Set 'HttpOnly' on all authentication cookies to mitigate session hijacking via XSS."
                )

        # Sort findings: Critical -> High -> Medium -> Low -> Information -> Observation
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFORMATION": 4,
            "OBSERVATION": 5
        }
        findings.sort(key=lambda x: severity_order.get(x["severity"], 99))

        return findings
