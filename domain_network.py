"""
domain_network.py — Domain & network reconnaissance.

Aggregates:
  · DNS records (A/AAAA/MX/NS/TXT/SOA/CNAME via Google DoH)
  · RDAP registration data (registrar, dates, nameservers)
  · SSL certificate details (subject, issuer, SANs, expiry)
  · HTTP headers + security header audit
  · technology fingerprint (server, x-powered-by, cookies, meta)
  · subdomain enumeration via crt.sh
  · robots.txt / sitemap.xml discovery
  · TCP port scan (top 20 common ports)
"""

import json
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme
from tqdm import tqdm

console = Console(theme=Theme({
    "g": "grey70", "dg": "grey50", "bg": "grey93", "bd": "grey37",
}))

BAR_FMT = "\033[38;5;245m  {desc} |{bar}| {percentage:3.0f}%\033[0m"
OUT_DIR = Path.home() / ".doxtoolkit" / "exports"
OUT_DIR.mkdir(parents=True, exist_ok=True)

UA = "Mozilla/5.0 (compatible; doxtoolkit/2.0)"
DNS_URL = "https://dns.google/resolve"

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]

TOP_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
    (443, "HTTPS"), (445, "SMB"), (465, "SMTPS"), (587, "SMTP-sub"),
    (993, "IMAPS"), (995, "POP3S"), (1433, "MSSQL"), (3306, "MySQL"),
    (3389, "RDP"), (5432, "Postgres"), (6379, "Redis"), (8080, "HTTP-alt"),
]


def _dns(domain, rtype):
    try:
        r = requests.get(
            DNS_URL,
            params={"name": domain, "type": rtype},
            headers={"User-Agent": UA, "Accept": "application/dns-json"},
            timeout=8,
        )
        d = r.json()
        out = []
        for a in d.get("Answer") or []:
            out.append(a.get("data"))
        return rtype, out
    except Exception:
        return rtype, []


def _rdap(domain):
    try:
        # try the generic RDAP first
        r = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={"User-Agent": UA, "Accept": "application/rdap+json"},
            timeout=12,
        )
        if r.status_code != 200:
            return None
        d = r.json()
    except Exception:
        return None

    out = {
        "handle": d.get("handle"),
        "ldhName": d.get("ldhName"),
        "status": d.get("status") or [],
        "nameservers": [],
        "events": {},
        "entities": [],
    }
    for ns in d.get("nameservers") or []:
        out["nameservers"].append(ns.get("ldhName"))
    for ev in d.get("events") or []:
        out["events"][ev.get("eventAction")] = ev.get("eventDate")
    for ent in d.get("entities") or []:
        roles = ent.get("roles") or []
        if "registrar" in roles:
            vc = ent.get("vcardArray")
            name = None
            if vc and len(vc) > 1:
                for f in vc[1]:
                    if f[0] == "fn":
                        name = f[3]
            out["entities"].append({"role": "registrar", "name": name})
    return out


def _ssl_cert(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        sans = []
        for t, v in cert.get("subjectAltName", []):
            if t == "DNS":
                sans.append(v)
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        return {
            "subject_cn": subject.get("commonName"),
            "subject_org": subject.get("organizationName"),
            "issuer_cn": issuer.get("commonName"),
            "issuer_org": issuer.get("organizationName"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "sans": sans[:30],
            "san_count": len(sans),
        }
    except Exception as e:
        return {"error": str(e)}


def _http_headers(domain):
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{domain}",
                headers={"User-Agent": UA},
                timeout=10,
                allow_redirects=True,
            )
            return {
                "url": r.url,
                "status": r.status_code,
                "server": r.headers.get("Server"),
                "powered_by": r.headers.get("X-Powered-By"),
                "via": r.headers.get("Via"),
                "cdn": r.headers.get("CF-Ray") or r.headers.get("X-Cache"),
                "headers": dict(r.headers),
                "body_snippet": r.text[:2000],
            }
        except Exception:
            continue
    return None


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _audit_security(headers):
    if not headers:
        return []
    present = {h.lower() for h in headers.keys()}
    return [(h, "yes" if h.lower() in present else "no") for h in SECURITY_HEADERS]


TECH_SIGNATURES = [
    ("wordpress", ("wp-content", "wp-includes", "wordpress")),
    ("drupal", ("drupal", "sites/default/files")),
    ("joomla", ("joomla", "/components/com_")),
    ("react", ("__next", "react", "_next/static")),
    ("vue", ("__vue__", "vue.js")),
    ("angular", ("ng-version", "angular")),
    ("bootstrap", ("bootstrap.min.css", "bootstrap.min.js")),
    ("jquery", ("jquery.min.js", "jquery-")),
    ("cloudflare", ("cf-ray", "cloudflare")),
    ("nginx", ("nginx",)),
    ("apache", ("apache",)),
    ("shopify", ("shopify", "cdn.shopify")),
    ("magento", ("magento", "mage/cookies")),
    ("wix", ("wix.com", "wixstatic")),
]


def _fingerprint(resp):
    hits = set()
    if not resp:
        return []
    server = (resp.get("server") or "").lower()
    pb = (resp.get("powered_by") or "").lower()
    body = (resp.get("body_snippet") or "").lower()
    hdrs = " ".join(f"{k}:{v}" for k, v in resp.get("headers", {}).items()).lower()
    blob = f"{server} {pb} {body} {hdrs}"
    for name, sigs in TECH_SIGNATURES:
        if any(s in blob for s in sigs):
            hits.add(name)
    return sorted(hits)


def _crtsh(domain):
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": UA}, timeout=20,
        )
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:
        return []
    subs = set()
    for entry in data:
        for name in (entry.get("name_value") or "").split("\n"):
            name = name.strip().lower()
            if name.endswith(domain) and "*" not in name:
                subs.add(name)
    return sorted(subs)[:200]


def _robots(domain):
    out = {"robots": None, "sitemap": None, "disallow": []}
    try:
        r = requests.get(f"https://{domain}/robots.txt",
                         headers={"User-Agent": UA}, timeout=8)
        if r.status_code == 200:
            out["robots"] = f"https://{domain}/robots.txt"
            for line in r.text.splitlines():
                if line.lower().startswith("disallow:"):
                    out["disallow"].append(line.split(":", 1)[1].strip())
                if line.lower().startswith("sitemap:"):
                    out["sitemap"] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    if not out["sitemap"]:
        for path in ("sitemap.xml", "sitemap_index.xml", "sitemap-index.xml"):
            try:
                r = requests.head(f"https://{domain}/{path}",
                                  headers={"User-Agent": UA}, timeout=6)
                if r.status_code == 200:
                    out["sitemap"] = f"https://{domain}/{path}"
                    break
            except Exception:
                continue
    return out


def _scan_port(host, port):
    try:
        with socket.create_connection((host, port), timeout=2):
            try:
                banner_sock = socket.socket()
                banner_sock.settimeout(1.5)
                banner_sock.connect((host, port))
                banner = banner_sock.recv(128).decode(errors="ignore").strip()
                banner_sock.close()
                return port, "open", banner
            except Exception:
                return port, "open", ""
    except Exception:
        return port, "closed", ""


def _render(domain, dns, rdap, ssl_d, http, tech, sec, subs, rb, ports):
    console.print(Panel.fit(
        f"[bg]DOMAIN RECON[/bg]  [dg]{domain}[/dg]",
        border_style="bd", padding=(0, 2),
    ))

    # DNS
    if dns:
        dt = Table(border_style="bd", title="[bg]dns[/bg]",
                   show_header=True, padding=(0, 2))
        dt.add_column("type", style="bg", no_wrap=True)
        dt.add_column("value", style="g", overflow="fold")
        for rtype, vals in dns.items():
            for v in vals:
                dt.add_row(rtype, v)
        console.print(dt)

    # RDAP
    if rdap:
        rt = Table(border_style="bd", title="[bg]registration[/bg]",
                   show_header=False, padding=(0, 2))
        rt.add_column("k", style="dg", no_wrap=True)
        rt.add_column("v", style="g")
        rt.add_row("handle", rdap.get("handle") or "—")
        for k, v in (rdap.get("events") or {}).items():
            rt.add_row(k, v)
        if rdap.get("nameservers"):
            rt.add_row("nameservers", ", ".join(rdap["nameservers"]))
        for e in rdap.get("entities", []):
            if e.get("role") == "registrar":
                rt.add_row("registrar", e.get("name") or "—")
        if rdap.get("status"):
            rt.add_row("status", ", ".join(rdap["status"]))
        console.print(rt)

    # SSL
    if ssl_d and "error" not in ssl_d:
        st = Table(border_style="bd", title="[bg]ssl cert[/bg]",
                   show_header=False, padding=(0, 2))
        st.add_column("k", style="dg", no_wrap=True)
        st.add_column("v", style="g", overflow="fold")
        st.add_row("subject", ssl_d.get("subject_cn") or "—")
        st.add_row("org", ssl_d.get("subject_org") or "—")
        st.add_row("issuer", ssl_d.get("issuer_cn") or "—")
        st.add_row("not before", ssl_d.get("not_before") or "—")
        st.add_row("not after", ssl_d.get("not_after") or "—")
        st.add_row("san count", str(ssl_d.get("san_count") or 0))
        if ssl_d.get("sans"):
            st.add_row("sans", ", ".join(ssl_d["sans"][:12]))
        console.print(st)

    # HTTP
    if http:
        ht = Table(border_style="bd", title="[bg]http[/bg]",
                   show_header=False, padding=(0, 2))
        ht.add_column("k", style="dg", no_wrap=True)
        ht.add_column("v", style="g", overflow="fold")
        ht.add_row("final url", http.get("url"))
        ht.add_row("status", str(http.get("status")))
        ht.add_row("server", http.get("server") or "—")
        ht.add_row("x-powered-by", http.get("powered_by") or "—")
        ht.add_row("cdn", http.get("cdn") or "—")
        console.print(ht)

    # tech
    if tech:
        console.print(f"[dg]  tech fingerprint: "
                      f"{', '.join(tech)}[/dg]")

    # security
    if sec:
        sect = Table(border_style="bd",
                     title="[bg]security headers[/bg]",
                     show_header=True, padding=(0, 2))
        sect.add_column("header", style="dg", overflow="fold")
        sect.add_column("present", style="g")
        for h, v in sec:
            sect.add_row(h, v)
        console.print(sect)

    # subdomains
    if subs:
        console.print(Panel.fit(
            f"[bg]subdomains (crt.sh)[/bg]  "
            f"[g]{len(subs)} unique[/g]",
            border_style="bd", padding=(0, 2),
        ))
        for s in subs[:60]:
            console.print(f"[g]  · {s}[/g]")
        if len(subs) > 60:
            console.print(f"[dg]  ... +{len(subs) - 60} more[/dg]")
        console.print()

    # robots
    if rb and (rb.get("robots") or rb.get("disallow") or rb.get("sitemap")):
        bt = Table(border_style="bd", title="[bg]robots / sitemap[/bg]",
                   show_header=False, padding=(0, 2))
        bt.add_column("k", style="dg", no_wrap=True)
        bt.add_column("v", style="g", overflow="fold")
        bt.add_row("robots", rb.get("robots") or "—")
        bt.add_row("sitemap", rb.get("sitemap") or "—")
        if rb.get("disallow"):
            bt.add_row("disallow", ", ".join(rb["disallow"][:15]))
        console.print(bt)

    # ports
    if ports:
        pt = Table(border_style="bd", title="[bg]top ports[/bg]",
                   show_header=True, padding=(0, 2))
        pt.add_column("port", style="bg", justify="right")
        pt.add_column("service", style="dg")
        pt.add_column("state", style="g")
        pt.add_column("banner", style="g", overflow="fold")
        open_ports = [p for p in ports if p[1] == "open"]
        for port, state, banner in sorted(ports):
            svc = next((s for p, s in TOP_PORTS if p == port), "?")
            pt.add_row(str(port), svc, state, banner[:60] or "")
        console.print(pt)
        console.print(f"[dg]  {len(open_ports)} open / {len(ports)} scanned"
                      f"[/dg]\n")


def _export(domain, payload):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", domain)[:40]
    p = OUT_DIR / f"domain_{safe}_{ts}.json"
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False,
                            default=str), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]\n")


def run():
    domain = input("  domain >> ").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    if not domain or "." not in domain:
        print("  [!] invalid domain")
        return

    with tqdm(total=len(RECORD_TYPES) + 3, desc="dns + rdap",
              ncols=60, bar_format=BAR_FMT) as bar:
        dns = {}
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(_dns, domain, rt): rt for rt in RECORD_TYPES}
            for f in as_completed(futs):
                rt, vals = f.result()
                if vals:
                    dns[rt] = vals
                bar.update(1)
        rdap = _rdap(domain); bar.update(1)
        ssl_d = _ssl_cert(domain); bar.update(1)
        http = _http_headers(domain); bar.update(1)

    tech = _fingerprint(http)
    sec = _audit_security(http.get("headers") if http else None)

    with tqdm(total=3, desc="crt.sh + robots + ports",
              ncols=60, bar_format=BAR_FMT) as bar:
        subs = _crtsh(domain); bar.update(1)
        rb = _robots(domain); bar.update(1)

        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = None
        ports = []
        if ip:
            with ThreadPoolExecutor(max_workers=30) as ex:
                futs = [ex.submit(_scan_port, ip, p) for p, _ in TOP_PORTS]
                for f in as_completed(futs):
                    ports.append(f.result())
        bar.update(1)

    _render(domain, dns, rdap, ssl_d, http, tech, sec, subs, rb, ports)

    if input("  export? [y/N] >> ").strip().lower() == "y":
        _export(domain, {
            "domain": domain, "dns": dns, "rdap": rdap, "ssl": ssl_d,
            "http": {k: v for k, v in (http or {}).items()
                     if k != "body_snippet"},
            "tech": tech, "security_headers": sec,
            "subdomains": subs, "robots": rb,
            "ports": [{"port": p, "state": s, "banner": b}
                      for p, s, b in ports],
            "generated": datetime.now().isoformat(timespec="seconds"),
        })