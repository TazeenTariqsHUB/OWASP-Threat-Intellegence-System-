#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║           DarkRecon - OSINT Threat Intelligence Tool      ║
╚═══════════════════════════════════════════════════════════╝
Usage:
    python3 darkRecon.py -d scanme.nmap.org
"""

import argparse
import subprocess
import socket
import ssl
import json
import os
import sys
import datetime
import requests
import whois as whois_lib

RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
RESET   = "\033[0m"
MAGENTA = "\033[95m"

def banner():
    print(f"""{CYAN}{BOLD}
 ██████╗  █████╗ ██████╗ ██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║  ██║███████║██████╔╝█████╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║  ██║██╔══██║██╔══██╗██╔═██╗ ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██████╔╝██║  ██║██║  ██║██║  ██╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{RESET}
{YELLOW}         OSINT & Threat Intelligence Platform   {RESET}
{RED}    ⚠  Only use with explicit written authorization from target owner  ⚠{RESET}
""")

def print_phase(phase, title):
    print(f"\n{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  Phase {phase}: {title}{RESET}")
    print(f"{CYAN}{'═'*60}{RESET}")

def print_finding(label, value, risk="INFO"):
    colors = {"CRITICAL": RED, "HIGH": YELLOW, "MEDIUM": MAGENTA, "LOW": GREEN, "INFO": CYAN}
    color  = colors.get(risk, CYAN)
    print(f"  {color}[{risk}]{RESET} {BOLD}{label}:{RESET} {value}")

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return result.stdout.strip()
    except:
        return ""

def run_cmd_live(cmd, label=""):
    """Run a command and print output live to terminal."""
    print(f"  {YELLOW}[*] Running: {label or cmd}{RESET}")
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        output_lines = []
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                print(f"  {CYAN}  {line}{RESET}")
                output_lines.append(line)
        proc.wait()
        return "\n".join(output_lines)
    except Exception as e:
        print(f"  {RED}[!] Failed: {e}{RESET}")
        return ""

# ── Phase 1: WHOIS ───────────────────────────────────────────────────────────
def whois_recon(domain, save_dir):
    print_phase(1, "WHOIS & Domain Intelligence")
    findings = {}
    try:
        w = whois_lib.whois(domain)
        findings["registrar"]       = str(w.registrar       or "N/A")
        findings["creation_date"]   = str(w.creation_date   or "N/A")
        findings["expiration_date"] = str(w.expiration_date or "N/A")
        findings["name_servers"]    = str(w.name_servers    or "N/A")
        findings["org"]             = str(w.org             or "N/A")
        findings["country"]         = str(w.country         or "N/A")
        findings["emails"]          = str(w.emails          or "N/A")

        print_finding("Registrar",      findings["registrar"])
        print_finding("Organization",   findings["org"])
        print_finding("Country",        findings["country"])
        print_finding("Created",        findings["creation_date"])
        print_finding("Expires",        findings["expiration_date"])
        print_finding("Name Servers",   findings["name_servers"])
        print_finding("Contact Emails", findings["emails"], "HIGH")

        # Save to file
        out = os.path.join(save_dir, "whois.txt")
        with open(out, "w") as f:
            for k, v in findings.items():
                f.write(f"{k.upper()}: {v}\n")
        print(f"  {GREEN}[saved] → {out}{RESET}")

    except Exception as e:
        findings["error"] = str(e)
        print(f"  {RED}[!] WHOIS failed: {e}{RESET}")
    return findings

# ── Phase 2: DNS ─────────────────────────────────────────────────────────────
def dns_recon(domain, save_dir):
    print_phase(2, "DNS Record Enumeration")
    findings = {}

    try:
        ip = socket.gethostbyname(domain)
        findings["a_record"] = ip
        print_finding("A Record (IP)", ip, "HIGH")
    except:
        findings["a_record"] = "Not resolved"
        print_finding("A Record", "Could not resolve", "LOW")

    mx  = run_cmd(f"dig MX {domain} +short 2>/dev/null")
    ns  = run_cmd(f"dig NS {domain} +short 2>/dev/null")
    txt = run_cmd(f"dig TXT {domain} +short 2>/dev/null")

    findings["mx_records"]  = mx  or "None found"
    findings["ns_records"]  = ns  or "None found"
    findings["txt_records"] = txt or "None found"

    print_finding("MX Records",  findings["mx_records"],  "MEDIUM")
    print_finding("NS Records",  findings["ns_records"],  "MEDIUM")
    print_finding("TXT Records", findings["txt_records"], "MEDIUM")

    print(f"\n  {YELLOW}[*] Attempting DNS Zone Transfer...{RESET}")
    zt = run_cmd(f"dig AXFR {domain} 2>/dev/null | head -20")
    if not zt or "Transfer failed" in zt or "connection refused" in zt.lower():
        findings["zone_transfer"] = "Blocked"
        print_finding("Zone Transfer", "Blocked — properly configured", "LOW")
    else:
        findings["zone_transfer"] = zt
        print_finding("Zone Transfer", "VULNERABLE — Zone Transfer Allowed!", "CRITICAL")

    out = os.path.join(save_dir, "dns_records.txt")
    with open(out, "w") as f:
        for k, v in findings.items():
            f.write(f"{k.upper()}:\n{v}\n\n")
    print(f"  {GREEN}[saved] → {out}{RESET}")

    return findings

# ── Phase 3: Subdomains ──────────────────────────────────────────────────────
def subdomain_enum(domain, save_dir):
    print_phase(3, "Subdomain Enumeration")
    findings = {"subdomains": [], "total_found": 0}

    common_subs = [
        "www","mail","remote","blog","webmail","server","ns1","ns2","smtp",
        "secure","vpn","m","shop","ftp","api","dev","staging","portal","admin",
        "test","app","mobile","support","help","login","auth","static","cdn",
        "media","upload","files","db","git","jenkins","hr","finance","backup"
    ]

    print(f"  {YELLOW}[*] Checking {len(common_subs)} common subdomains...{RESET}")
    found = []
    for sub in common_subs:
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            found.append({"subdomain": full, "ip": ip})
            print_finding("FOUND", f"{full}  →  {ip}", "HIGH")
        except:
            pass

    findings["subdomains"]   = found
    findings["total_found"]  = len(found)

    # Sublist3r — live output
    tmp = f"/tmp/subs_{domain}.txt"
    if os.path.exists(tmp):
        os.remove(tmp)
    sublist_out = run_cmd_live(f"sublist3r -d {domain} -o {tmp}", "Sublist3r")
    if os.path.exists(tmp):
        with open(tmp) as f:
            lines = [l.strip() for l in f if l.strip()]
        findings["sublist3r"] = lines
        print(f"  {GREEN}[+] Sublist3r found {len(lines)} subdomains{RESET}")
    else:
        findings["sublist3r"] = []
        print(f"  {YELLOW}[!] Sublist3r returned no results{RESET}")

    # Save
    out = os.path.join(save_dir, "subdomains.txt")
    with open(out, "w") as f:
        f.write(f"Subdomains for {domain}\n{'='*40}\n\n")
        f.write("== Brute Force Results ==\n")
        for s in found:
            f.write(f"{s['subdomain']} -> {s['ip']}\n")
        f.write("\n== Sublist3r Results ==\n")
        for l in findings.get("sublist3r", []):
            f.write(f"{l}\n")
    print(f"  {GREEN}[saved] → {out}{RESET}")

    if len(found) == 0:
        print(f"  {GREEN}[✓] No common subdomains found{RESET}")
    else:
        print(f"\n  {RED}[!] {len(found)} subdomains found — each is an attack vector{RESET}")

    return findings

# ── Phase 4: HTTP Headers ────────────────────────────────────────────────────
def header_audit(domain, save_dir):
    print_phase(4, "HTTP Security Header Audit")
    findings = {"missing": [], "present": [], "server_info": ""}

    security_headers = {
        "Strict-Transport-Security": ("HSTS forces HTTPS",           "HIGH"),
        "Content-Security-Policy":   ("Prevents XSS attacks",        "HIGH"),
        "X-Frame-Options":           ("Clickjacking protection",      "MEDIUM"),
        "X-Content-Type-Options":    ("MIME sniffing protection",     "MEDIUM"),
        "X-XSS-Protection":          ("XSS filter legacy browsers",   "LOW"),
        "Referrer-Policy":           ("Referrer info leakage",        "LOW"),
        "Permissions-Policy":        ("Browser feature access",       "LOW"),
    }

    for protocol in ["https", "http"]:
        try:
            r = requests.get(f"{protocol}://{domain}", timeout=10, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 (Security Audit)"})
            print(f"  {GREEN}[+] Connected via {protocol.upper()} — Status: {r.status_code}{RESET}")

            server = r.headers.get("Server", "Hidden")
            findings["server_info"] = server
            if server != "Hidden":
                print_finding("Server Banner", f"{server} — VERSION DISCLOSED", "HIGH")
            else:
                print_finding("Server Banner", "Hidden — Good", "LOW")

            powered = r.headers.get("X-Powered-By")
            if powered:
                findings["x_powered_by"] = powered
                print_finding("X-Powered-By", f"{powered} — DISCLOSED", "HIGH")

            print(f"\n  {BOLD}Security Headers:{RESET}")
            for header, (desc, risk) in security_headers.items():
                if header in r.headers:
                    findings["present"].append(header)
                    print(f"  {GREEN}  [✓] {header}{RESET}")
                else:
                    findings["missing"].append({"header": header, "desc": desc, "risk": risk})
                    print_finding(f"MISSING {header}", desc, risk)

            findings["status_code"] = r.status_code
            findings["final_url"]   = r.url

            # Save headers raw
            out = os.path.join(save_dir, "http_headers.txt")
            with open(out, "w") as f:
                f.write(f"HTTP Headers for {domain}\n{'='*40}\n\n")
                f.write("== All Response Headers ==\n")
                for k, v in r.headers.items():
                    f.write(f"{k}: {v}\n")
                f.write("\n== Missing Security Headers ==\n")
                for h in findings["missing"]:
                    f.write(f"[{h['risk']}] {h['header']} — {h['desc']}\n")
                f.write("\n== Present Security Headers ==\n")
                for h in findings["present"]:
                    f.write(f"[OK] {h}\n")
            print(f"  {GREEN}[saved] → {out}{RESET}")
            break

        except requests.exceptions.ConnectionError:
            continue
        except Exception as e:
            findings["error"] = str(e)

    score = len(findings["present"])
    total = len(security_headers)
    print(f"\n  {BOLD}Header Score: {score}/{total}{RESET}")
    return findings

# ── Phase 5: SSL ─────────────────────────────────────────────────────────────
def ssl_via_sslscan(domain, save_dir):
    """Option 2 — Run sslscan tool and parse output."""
    print(f"  {YELLOW}[*] Running SSLScan...{RESET}")
    output = run_cmd_live(f"sslscan --no-colour {domain}", "SSLScan")
    if not output or "ERROR" in output or "command not found" in output.lower():
        return None

    findings = {"method": "sslscan", "raw": output}

    # Parse key info from sslscan output
    for line in output.splitlines():
        line = line.strip()
        if "Subject:" in line:
            findings["common_name"] = line.split("Subject:")[-1].strip()
        if "Issuer:" in line:
            findings["issuer"] = line.split("Issuer:")[-1].strip()
        if "Not valid before:" in line:
            findings["valid_from"] = line.split("Not valid before:")[-1].strip()
        if "Not valid after:" in line:
            findings["valid_until"] = line.split("Not valid after:")[-1].strip()
        if "TLSv1.0" in line and "enabled" in line.lower():
            findings["weak_tls"] = "TLS 1.0 enabled — VULNERABLE"
        if "TLSv1.3" in line and "enabled" in line.lower():
            findings["tls13"] = "TLS 1.3 supported — Good"
        if "SSLv" in line and "enabled" in line.lower():
            findings["sslv"] = "SSLv enabled — CRITICAL VULNERABILITY"

    # Print findings
    print_finding("Common Name",  findings.get("common_name",  "N/A"))
    print_finding("Issuer",       findings.get("issuer",       "N/A"))
    print_finding("Valid From",   findings.get("valid_from",   "N/A"))
    print_finding("Valid Until",  findings.get("valid_until",  "N/A"), "MEDIUM")
    if findings.get("weak_tls"):
        print_finding("Weak TLS", findings["weak_tls"], "CRITICAL")
    if findings.get("sslv"):
        print_finding("SSLv", findings["sslv"], "CRITICAL")
    if findings.get("tls13"):
        print_finding("TLS 1.3", findings["tls13"], "LOW")

    # Save full sslscan output
    out = os.path.join(save_dir, "ssl_certificate.txt")
    with open(out, "w") as f:
        f.write(f"SSL Analysis via SSLScan — {domain}\n{'='*40}\n\n")
        f.write(output)
        f.write(f"\n\n== PARSED FINDINGS ==\n")
        for k, v in findings.items():
            if k not in ["method", "raw"]:
                f.write(f"{k.upper()}: {v}\n")
    print(f"  {GREEN}[saved] → {out}{RESET}")
    return findings

def ssl_via_crtsh(domain, save_dir):
    """Option 3 — Fallback: fetch SSL certificate history from crt.sh."""
    print(f"  {YELLOW}[*] SSLScan failed — falling back to crt.sh...{RESET}")
    findings = {"method": "crt.sh"}
    try:
        url  = f"https://crt.sh/?q={domain}&output=json"
        resp = requests.get(url, timeout=15)
        data = resp.json()

        if not data:
            print_finding("crt.sh", "No certificates found for this domain", "MEDIUM")
            findings["error"] = "No certificates found"
            return findings

        # Get most recent cert
        latest = data[0]
        findings["common_name"]    = latest.get("common_name",    "N/A")
        findings["issuer"]         = latest.get("issuer_name",    "N/A")
        findings["valid_from"]     = latest.get("not_before",     "N/A")
        findings["valid_until"]    = latest.get("not_after",      "N/A")
        findings["serial"]         = latest.get("serial_number",  "N/A")
        findings["total_certs"]    = len(data)
        findings["note"]           = "Data sourced from crt.sh certificate transparency logs"

        # Get all unique SANs
        sans = list(set([c.get("common_name","") for c in data if c.get("common_name")]))
        findings["san"] = ", ".join(sans[:10])

        print_finding("Common Name",     findings["common_name"])
        print_finding("Issuer",          findings["issuer"])
        print_finding("Valid From",      findings["valid_from"])
        print_finding("Valid Until",     findings["valid_until"],  "MEDIUM")
        print_finding("Total Certs Found", str(findings["total_certs"]))
        print_finding("All SANs Found",  findings["san"],          "HIGH")
        print(f"  {CYAN}[i] Source: Certificate Transparency Logs via crt.sh{RESET}")

        # Check expiry
        try:
            expiry    = datetime.datetime.strptime(findings["valid_until"][:10], "%Y-%m-%d")
            days_left = (expiry - datetime.datetime.utcnow()).days
            findings["days_until_expiry"] = days_left
            risk = "CRITICAL" if days_left < 30 else "MEDIUM" if days_left < 90 else "LOW"
            print_finding("Days Until Expiry", str(days_left), risk)
        except:
            findings["days_until_expiry"] = "N/A"

        # Save
        out = os.path.join(save_dir, "ssl_certificate.txt")
        with open(out, "w") as f:
            f.write(f"SSL Analysis via crt.sh (Certificate Transparency) — {domain}\n{'='*40}\n\n")
            f.write(f"NOTE: Domain port 443 was closed. Data from public certificate transparency logs.\n\n")
            for k, v in findings.items():
                if k != "method":
                    f.write(f"{k.upper()}: {v}\n")
            f.write(f"\n== ALL CERTIFICATES FOUND ({len(data)}) ==\n")
            for c in data[:20]:
                f.write(f"  [{c.get('not_before','?')} → {c.get('not_after','?')}] {c.get('common_name','?')} | {c.get('issuer_name','?')}\n")
        print(f"  {GREEN}[saved] → {out}{RESET}")

    except Exception as e:
        findings["error"] = str(e)
        print(f"  {RED}[!] crt.sh also failed: {e}{RESET}")

    return findings

def ssl_analysis(domain, save_dir):
    print_phase(5, "SSL/TLS Certificate Analysis")

    # Try native SSL connection first
    print(f"  {YELLOW}[*] Checking port 443...{RESET}")
    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(10)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        findings = {"method": "direct"}
        subject  = dict(x[0] for x in cert.get("subject", []))
        issuer   = dict(x[0] for x in cert.get("issuer",  []))

        findings["common_name"] = subject.get("commonName",      "N/A")
        findings["issuer"]      = issuer.get("organizationName", "N/A")
        findings["valid_from"]  = cert.get("notBefore",          "N/A")
        findings["valid_until"] = cert.get("notAfter",           "N/A")
        findings["san"]         = str(cert.get("subjectAltName", "None"))

        print_finding("Common Name", findings["common_name"])
        print_finding("Issuer",      findings["issuer"])
        print_finding("Valid From",  findings["valid_from"])
        print_finding("Valid Until", findings["valid_until"], "MEDIUM")
        print_finding("Alt Names",   findings["san"],         "HIGH")

        try:
            expiry    = datetime.datetime.strptime(findings["valid_until"], "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days
            findings["days_until_expiry"] = days_left
            risk = "CRITICAL" if days_left < 30 else "MEDIUM" if days_left < 90 else "LOW"
            print_finding("Days Until Expiry", str(days_left), risk)
        except:
            findings["days_until_expiry"] = "N/A"

        out = os.path.join(save_dir, "ssl_certificate.txt")
        with open(out, "w") as f:
            f.write(f"SSL Certificate Analysis — {domain}\n{'='*40}\n\n")
            for k, v in findings.items():
                f.write(f"{k.upper()}: {v}\n")
        print(f"  {GREEN}[saved] → {out}{RESET}")
        return findings

    except Exception:
        # Port 443 closed — try SSLScan
        print(f"  {YELLOW}[!] Port 443 closed — trying SSLScan...{RESET}")
        findings = ssl_via_sslscan(domain, save_dir)
        if findings:
            return findings
        # SSLScan failed — fall back to crt.sh
        findings = ssl_via_crtsh(domain, save_dir)
        return findings

# ── Phase 6: Tech Fingerprint ─────────────────────────────────────────────────
def tech_fingerprint(domain, save_dir):
    print_phase(6, "Technology Fingerprinting")
    findings = {}

    whatweb = run_cmd_live(f"whatweb --color=never {domain}", "WhatWeb Fingerprinting")
    findings["whatweb"] = whatweb or "Not available"

    wafw00f = run_cmd_live(f"wafw00f {domain}", "WafW00f WAF Detection")
    findings["waf"] = wafw00f or "Not available"
    if wafw00f:
        if "No WAF" in wafw00f or "not detected" in wafw00f.lower():
            print_finding("WAF", "No WAF detected — easier to attack", "HIGH")
        else:
            print_finding("WAF", "WAF detected — harder to attack", "LOW")

    try:
        r = requests.get(f"https://{domain}/robots.txt", timeout=8)
        findings["robots_txt"] = r.text[:1000] if r.status_code == 200 else "Not found"
        if r.status_code == 200:
            print_finding("robots.txt", "EXISTS — may reveal hidden paths", "MEDIUM")
    except:
        findings["robots_txt"] = "Could not fetch"

    out = os.path.join(save_dir, "tech_fingerprint.txt")
    with open(out, "w") as f:
        f.write(f"Technology Fingerprint — {domain}\n{'='*40}\n\n")
        f.write(f"WHATWEB:\n{findings['whatweb']}\n\n")
        f.write(f"WAF DETECTION:\n{findings['waf']}\n\n")
        f.write(f"ROBOTS.TXT:\n{findings['robots_txt']}\n")
    print(f"  {GREEN}[saved] → {out}{RESET}")

    return findings

# ── Risk Assessment ───────────────────────────────────────────────────────────
def risk_assessment(all_findings, save_dir):
    print_phase(7, "Risk Assessment & Compliance Mapping")
    risks = []

    headers = all_findings.get("headers",    {})
    ssl_d   = all_findings.get("ssl",        {})
    dns_d   = all_findings.get("dns",        {})
    subs    = all_findings.get("subdomains", {})
    whois_d = all_findings.get("whois",      {})

    for h in headers.get("missing", []):
        risks.append({
            "finding":        f"Missing Header: {h['header']}",
            "description":    h["desc"],
            "risk":           h["risk"],
            "nist":           "PR.IP-1",
            "iso27001":       "A.14.1",
            "recommendation": f"Implement {h['header']} on web server"
        })

    if headers.get("server_info") not in ["Hidden", "", None]:
        risks.append({
            "finding":        "Server Version Disclosed",
            "description":    f"Header reveals: {headers['server_info']}",
            "risk":           "HIGH",
            "nist":           "PR.IP-1",
            "iso27001":       "A.12.6",
            "recommendation": "Hide server version in config"
        })

    if dns_d.get("zone_transfer") and "Blocked" not in str(dns_d.get("zone_transfer", "")):
        risks.append({
            "finding":        "DNS Zone Transfer Allowed",
            "description":    "Full DNS zone exposed to anyone",
            "risk":           "CRITICAL",
            "nist":           "PR.AC-5",
            "iso27001":       "A.13.1",
            "recommendation": "Restrict zone transfers to authorized IPs only"
        })

    sub_count = subs.get("total_found", 0)
    if sub_count > 0:
        risks.append({
            "finding":        f"{sub_count} Subdomains Discovered",
            "description":    "Each subdomain is a potential attack entry point",
            "risk":           "HIGH",
            "nist":           "ID.AM-1",
            "iso27001":       "A.8.1",
            "recommendation": "Audit and remove unused subdomains"
        })

    if whois_d.get("emails") not in ["N/A", "None", None, ""]:
        risks.append({
            "finding":        "Contact Emails in WHOIS",
            "description":    f"Emails exposed: {whois_d['emails']}",
            "risk":           "MEDIUM",
            "nist":           "PR.AC-1",
            "iso27001":       "A.7.2",
            "recommendation": "Use WHOIS privacy protection"
        })

    days = ssl_d.get("days_until_expiry", 999)
    if isinstance(days, int) and days < 30:
        risks.append({
            "finding":        "SSL Certificate Expiring Soon",
            "description":    f"Expires in {days} days",
            "risk":           "CRITICAL",
            "nist":           "PR.DS-2",
            "iso27001":       "A.10.1",
            "recommendation": "Renew SSL certificate immediately"
        })

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    risks.sort(key=lambda x: risk_order.get(x["risk"], 4))

    colors = {"CRITICAL": RED, "HIGH": YELLOW, "MEDIUM": MAGENTA, "LOW": GREEN}
    print(f"\n  {'RISK':<10} {'FINDING':<40} {'NIST':<12} ISO 27001")
    print(f"  {'─'*10} {'─'*40} {'─'*12} {'─'*10}")
    for r in risks:
        c = colors.get(r["risk"], CYAN)
        print(f"  {c}{r['risk']:<10}{RESET} {r['finding']:<40} {r['nist']:<12} {r['iso27001']}")

    # Save risk matrix
    out = os.path.join(save_dir, "risk_matrix.txt")
    with open(out, "w") as f:
        f.write(f"RISK MATRIX — NIST CSF + ISO 27001 Mapping\n{'='*60}\n\n")
        for r in risks:
            f.write(f"[{r['risk']}] {r['finding']}\n")
            f.write(f"  Description    : {r['description']}\n")
            f.write(f"  NIST CSF       : {r['nist']}\n")
            f.write(f"  ISO 27001      : {r['iso27001']}\n")
            f.write(f"  Recommendation : {r['recommendation']}\n\n")
    print(f"  {GREEN}[saved] → {out}{RESET}")

    return risks

# ── HTML Report ───────────────────────────────────────────────────────────────
def generate_html_report(domain, all_findings, risks):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    risk_rows = ""
    risk_colors = {"CRITICAL": "#ff4757", "HIGH": "#ffa502", "MEDIUM": "#eccc68", "LOW": "#2ed573"}
    for r in risks:
        color = risk_colors.get(r["risk"], "#888")
        risk_rows += f"""
        <tr>
            <td><span class="badge" style="background:{color}">{r['risk']}</span></td>
            <td>{r['finding']}</td>
            <td>{r['description']}</td>
            <td>{r['nist']}</td>
            <td>{r['iso27001']}</td>
            <td>{r['recommendation']}</td>
        </tr>"""

    subdomain_rows = ""
    for s in all_findings.get("subdomains", {}).get("subdomains", []):
        subdomain_rows += f"<tr><td>{s['subdomain']}</td><td>{s['ip']}</td><td><span class='badge' style='background:#ffa502'>HIGH</span></td></tr>"

    missing_headers = ""
    for h in all_findings.get("headers", {}).get("missing", []):
        c = risk_colors.get(h["risk"], "#888")
        missing_headers += f"<li><span class='badge' style='background:{c}'>{h['risk']}</span> <strong>{h['header']}</strong> — {h['desc']}</li>"

    present_headers = ""
    for h in all_findings.get("headers", {}).get("present", []):
        present_headers += f"<li><span style='color:#2ed573'>✓</span> {h}</li>"

    whois_d = all_findings.get("whois", {})
    dns_d   = all_findings.get("dns",   {})
    ssl_d   = all_findings.get("ssl",   {})

    tc = sum(1 for r in risks if r["risk"] == "CRITICAL")
    th = sum(1 for r in risks if r["risk"] == "HIGH")
    tm = sum(1 for r in risks if r["risk"] == "MEDIUM")
    tl = sum(1 for r in risks if r["risk"] == "LOW")

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DarkRecon — {domain}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
:root{{--bg:#0a0e1a;--surface:#0f1629;--border:#1e2d4a;--accent:#00d4ff;--red:#ff4757;--yellow:#ffa502;--green:#2ed573;--text:#c8d8f0;--muted:#5a7a9a;}}
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;font-size:15px;line-height:1.6;}}
body::before{{content:'';position:fixed;top:0;left:0;right:0;bottom:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,212,255,.015) 2px,rgba(0,212,255,.015) 4px);pointer-events:none;z-index:0;}}
.wrap{{max-width:1200px;margin:0 auto;padding:0 24px;position:relative;z-index:1;}}
header{{border-bottom:1px solid var(--border);padding:32px 0 24px;margin-bottom:40px;position:relative;}}
header::after{{content:'';position:absolute;bottom:-1px;left:0;width:200px;height:2px;background:var(--accent);}}
.logo{{font-family:'Share Tech Mono',monospace;font-size:28px;color:var(--accent);letter-spacing:4px;text-shadow:0 0 20px rgba(0,212,255,.5);}}
.logo span{{color:var(--red);}}
.subtitle{{color:var(--muted);font-size:13px;letter-spacing:2px;margin-top:4px;font-family:'Share Tech Mono',monospace;}}
.meta-bar{{display:flex;gap:32px;margin-top:20px;flex-wrap:wrap;}}
.meta-item{{display:flex;flex-direction:column;}}
.meta-label{{font-size:11px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;}}
.meta-value{{font-family:'Share Tech Mono',monospace;color:var(--accent);font-size:14px;margin-top:2px;}}
.risk-summary{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:40px;}}
.risk-card{{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:20px;text-align:center;position:relative;overflow:hidden;}}
.risk-card::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px;}}
.risk-card.critical::before{{background:var(--red);}}
.risk-card.high::before{{background:var(--yellow);}}
.risk-card.medium::before{{background:#eccc68;}}
.risk-card.low::before{{background:var(--green);}}
.risk-card .count{{font-family:'Share Tech Mono',monospace;font-size:48px;font-weight:700;line-height:1;}}
.risk-card.critical .count{{color:var(--red);}}
.risk-card.high .count{{color:var(--yellow);}}
.risk-card.medium .count{{color:#eccc68;}}
.risk-card.low .count{{color:var(--green);}}
.risk-card .label{{font-size:12px;letter-spacing:2px;color:var(--muted);margin-top:8px;text-transform:uppercase;}}
.section{{background:var(--surface);border:1px solid var(--border);border-radius:4px;margin-bottom:24px;overflow:hidden;}}
.section-header{{padding:16px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;background:rgba(0,212,255,.03);}}
.phase-badge{{font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--accent);background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.3);padding:2px 8px;border-radius:2px;letter-spacing:1px;}}
.section-title{{font-size:16px;font-weight:700;color:#e0eeff;letter-spacing:1px;text-transform:uppercase;}}
.section-body{{padding:24px;}}
table{{width:100%;border-collapse:collapse;font-size:14px;}}
th{{text-align:left;padding:10px 14px;background:rgba(0,212,255,.06);color:var(--accent);font-size:11px;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid var(--border);font-family:'Share Tech Mono',monospace;}}
td{{padding:10px 14px;border-bottom:1px solid rgba(30,45,74,.5);vertical-align:top;}}
tr:last-child td{{border-bottom:none;}}
tr:hover td{{background:rgba(0,212,255,.03);}}
.badge{{display:inline-block;padding:2px 8px;border-radius:2px;font-size:11px;font-weight:700;font-family:'Share Tech Mono',monospace;letter-spacing:1px;color:#000;}}
.kv-grid{{display:grid;grid-template-columns:200px 1fr;}}
.kv-key{{padding:8px 14px;color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:12px;border-bottom:1px solid rgba(30,45,74,.4);background:rgba(0,0,0,.2);}}
.kv-val{{padding:8px 14px;color:var(--text);border-bottom:1px solid rgba(30,45,74,.4);font-family:'Share Tech Mono',monospace;font-size:12px;word-break:break-all;}}
ul{{list-style:none;padding:0;}}
ul li{{padding:6px 0;border-bottom:1px solid rgba(30,45,74,.3);display:flex;align-items:center;gap:10px;}}
ul li:last-child{{border-bottom:none;}}
footer{{border-top:1px solid var(--border);padding:24px 0;margin-top:40px;text-align:center;color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:12px;letter-spacing:1px;}}
.legal{{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.3);border-radius:4px;padding:16px 20px;margin-bottom:32px;font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--red);letter-spacing:1px;}}
</style></head><body><div class="wrap">
<header>
  <div class="logo">DARK<span>RECON</span></div>
  <div class="subtitle">// OSINT THREAT INTELLIGENCE PLATFORM — CY103 CCP PROJECT</div>
  <div class="meta-bar">
    <div class="meta-item"><span class="meta-label">Target</span><span class="meta-value">{domain}</span></div>
    <div class="meta-item"><span class="meta-label">Generated</span><span class="meta-value">{timestamp}</span></div>
    <div class="meta-item"><span class="meta-label">Total Findings</span><span class="meta-value">{len(risks)}</span></div>
    <div class="meta-item"><span class="meta-label">Classification</span><span class="meta-value" style="color:var(--red)">CONFIDENTIAL</span></div>
  </div>
</header>
<div class="legal">⚠ This report was generated with explicit written authorization. Unauthorized use violates PECA 2016.</div>
<div class="risk-summary">
  <div class="risk-card critical"><div class="count">{tc}</div><div class="label">Critical</div></div>
  <div class="risk-card high"><div class="count">{th}</div><div class="label">High</div></div>
  <div class="risk-card medium"><div class="count">{tm}</div><div class="label">Medium</div></div>
  <div class="risk-card low"><div class="count">{tl}</div><div class="label">Low</div></div>
</div>
<div class="section"><div class="section-header"><span class="phase-badge">PHASE 01</span><span class="section-title">WHOIS Intelligence</span></div>
<div class="section-body"><div class="kv-grid">
  <div class="kv-key">REGISTRAR</div><div class="kv-val">{whois_d.get('registrar','N/A')}</div>
  <div class="kv-key">ORGANIZATION</div><div class="kv-val">{whois_d.get('org','N/A')}</div>
  <div class="kv-key">COUNTRY</div><div class="kv-val">{whois_d.get('country','N/A')}</div>
  <div class="kv-key">CREATED</div><div class="kv-val">{whois_d.get('creation_date','N/A')}</div>
  <div class="kv-key">EXPIRES</div><div class="kv-val">{whois_d.get('expiration_date','N/A')}</div>
  <div class="kv-key">NAME SERVERS</div><div class="kv-val">{whois_d.get('name_servers','N/A')}</div>
  <div class="kv-key">CONTACT EMAILS</div><div class="kv-val" style="color:var(--yellow)">{whois_d.get('emails','N/A')}</div>
</div></div></div>
<div class="section"><div class="section-header"><span class="phase-badge">PHASE 02</span><span class="section-title">DNS Records</span></div>
<div class="section-body"><div class="kv-grid">
  <div class="kv-key">A RECORD</div><div class="kv-val" style="color:var(--accent)">{dns_d.get('a_record','N/A')}</div>
  <div class="kv-key">MX RECORDS</div><div class="kv-val">{dns_d.get('mx_records','N/A')}</div>
  <div class="kv-key">NS RECORDS</div><div class="kv-val">{dns_d.get('ns_records','N/A')}</div>
  <div class="kv-key">TXT RECORDS</div><div class="kv-val">{dns_d.get('txt_records','N/A')}</div>
  <div class="kv-key">ZONE TRANSFER</div><div class="kv-val" style="color:{'var(--green)' if 'Blocked' in str(dns_d.get('zone_transfer','')) else 'var(--red)'}">{dns_d.get('zone_transfer','Not tested')}</div>
</div></div></div>
<div class="section"><div class="section-header"><span class="phase-badge">PHASE 03</span><span class="section-title">Subdomain Enumeration</span></div>
<div class="section-body">{'<p style="color:var(--muted)">No subdomains discovered.</p>' if not subdomain_rows else f'<table><thead><tr><th>Subdomain</th><th>IP</th><th>Risk</th></tr></thead><tbody>{subdomain_rows}</tbody></table>'}</div></div>
<div class="section"><div class="section-header"><span class="phase-badge">PHASE 04</span><span class="section-title">HTTP Security Headers</span></div>
<div class="section-body"><div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;">
  <div><p style="color:var(--red);font-weight:700;margin-bottom:12px">✗ MISSING</p><ul>{missing_headers or '<li style="color:var(--green)">All headers present</li>'}</ul></div>
  <div><p style="color:var(--green);font-weight:700;margin-bottom:12px">✓ PRESENT</p><ul>{present_headers or '<li style="color:var(--muted)">None</li>'}</ul></div>
</div>
<div style="margin-top:16px;padding:12px;background:rgba(0,0,0,.2);border-left:3px solid var(--yellow)">
  <span style="font-family:Share Tech Mono,monospace;font-size:12px;color:var(--muted)">SERVER: </span>
  <span style="font-family:Share Tech Mono,monospace;font-size:12px;color:var(--yellow)">{all_findings.get('headers',{}).get('server_info','Hidden')}</span>
</div></div></div>
<div class="section"><div class="section-header"><span class="phase-badge">PHASE 05</span><span class="section-title">SSL/TLS Certificate</span></div>
<div class="section-body"><div class="kv-grid">
  <div class="kv-key">COMMON NAME</div><div class="kv-val">{ssl_d.get('common_name','N/A')}</div>
  <div class="kv-key">ISSUER</div><div class="kv-val">{ssl_d.get('issuer','N/A')}</div>
  <div class="kv-key">VALID FROM</div><div class="kv-val">{ssl_d.get('valid_from','N/A')}</div>
  <div class="kv-key">VALID UNTIL</div><div class="kv-val">{ssl_d.get('valid_until','N/A')}</div>
  <div class="kv-key">DAYS REMAINING</div><div class="kv-val">{ssl_d.get('days_until_expiry','N/A')}</div>
  <div class="kv-key">ALT NAMES</div><div class="kv-val" style="color:var(--accent)">{ssl_d.get('san','N/A')}</div>
</div></div></div>
<div class="section"><div class="section-header"><span class="phase-badge">RISK MATRIX</span><span class="section-title">Findings + NIST CSF + ISO 27001</span></div>
<div class="section-body"><table><thead><tr><th>Risk</th><th>Finding</th><th>Description</th><th>NIST</th><th>ISO 27001</th><th>Fix</th></tr></thead>
<tbody>{risk_rows or '<tr><td colspan="6" style="color:var(--green);text-align:center">No significant risks found</td></tr>'}</tbody></table></div></div>
<footer>DARKRECON v2.0 | CY103 INFORMATION ASSURANCE | NASTP IIT | {timestamp}<br><br>CONFIDENTIAL — AUTHORIZED USE ONLY — PECA 2016 COMPLIANT</footer>
</div></body></html>"""

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(description="DarkRecon — OSINT Tool")
    parser.add_argument("-d", "--domain",   required=True, help="Target domain")
    parser.add_argument("--skip-ssl",       action="store_true")
    parser.add_argument("--skip-subs",      action="store_true")
    args = parser.parse_args()

    domain = args.domain.replace("https://","").replace("http://","").strip("/")

    # Create scan folder: scans/domain_timestamp/
    ts          = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe        = domain.replace(".", "_").replace(":", "_")
    scan_dir    = os.path.join("scans", f"{safe}_{ts}")
    os.makedirs(scan_dir, exist_ok=True)

    print(f"\n{BOLD}{CYAN}[*] Target     : {domain}{RESET}")
    print(f"{BOLD}{CYAN}[*] Scan Folder: {scan_dir}/{RESET}")
    print(f"{YELLOW}[!] Ensure you have written authorization{RESET}")
    print(f"\n{CYAN}Press ENTER to start or Ctrl+C to cancel...{RESET}", end="")
    input()

    findings = {}
    findings["whois"]      = whois_recon(domain, scan_dir)
    findings["dns"]        = dns_recon(domain, scan_dir)
    if not args.skip_subs:
        findings["subdomains"] = subdomain_enum(domain, scan_dir)
    findings["headers"]    = header_audit(domain, scan_dir)
    if not args.skip_ssl:
        findings["ssl"]    = ssl_analysis(domain, scan_dir)
    findings["tech"]       = tech_fingerprint(domain, scan_dir)

    risks = risk_assessment(findings, scan_dir)

    print_phase("✓", "Generating HTML Report")
    html     = generate_html_report(domain, findings, risks)
    html_out = os.path.join(scan_dir, "report.html")
    json_out = os.path.join(scan_dir, "findings.json")

    with open(html_out, "w", encoding="utf-8") as f:
        f.write(html)
    with open(json_out, "w") as f:
        json.dump({"domain": domain, "timestamp": str(datetime.datetime.now()),
                   "findings": findings, "risks": risks}, f, indent=2, default=str)

    print(f"\n{GREEN}{BOLD}{'═'*60}{RESET}")
    print(f"{GREEN}{BOLD}  [✓] DarkRecon Complete!{RESET}")
    print(f"{GREEN}  Folder  : {scan_dir}/{RESET}")
    print(f"{GREEN}  Files saved in scan folder:{RESET}")
    for f in os.listdir(scan_dir):
        print(f"{GREEN}    ├── {f}{RESET}")
    print(f"{GREEN}  Risks   : {len(risks)}{RESET}")
    print(f"{GREEN}{BOLD}{'═'*60}{RESET}")
    print(f"\n{CYAN}  firefox {html_out}{RESET}\n")

if __name__ == "__main__":
    main()


