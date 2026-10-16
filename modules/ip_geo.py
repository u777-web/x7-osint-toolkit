"""
ip_geo.py — Multi-source IP intelligence (deep edition).

Aggregates geolocation, ASN, network registration (RDAP), reverse DNS,
abuse contacts, passive DNS history, threat reputation, open ports,
CVEs, TLS certificate data, and BGP routing info from public providers.
Disk-cached with per-source fallbacks so a single dead endpoint
doesn't kill the lookup.

New in this version:
  · Shodan InternetDB (free, no key) — open ports, tags, CPEs, CVEs
  · Robtex Free API — IP reputation vs 100+ blocklists, passive DNS
    forward/reverse, historic reverse DNS, AS prefixes, MAC lookup
  · RIPE Stat — announced prefixes for ASN with BGPView fallback
  · RDAP IP — netblock, abuse contact
  · TLS certificate probe on port 443 (CN, SAN, issuer, expiry)
  · threat reputation scoring with plain-English reasons
  · multi-source geolocation divergence report
  · bulk IP mode
  · history tracking per IP with diff
  · export to JSON, CSV, and standalone HTML report
"""

import csv
import hashlib
import html
import ipaddress
import json
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme
from tqdm import tqdm

console = Console(theme=Theme({
    "g": "grey70", "dg": "grey50", "bg": "grey93", "bd": "grey37",
    "red": "red", "green": "green", "yellow": "yellow",
}))

BAR_FMT = "\033[38;5;245m  {desc} |{bar}| {percentage:3.0f}%\033[0m"

CACHE_DIR = Path.home() / ".ostinttol" / "ipcache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
HIST_DIR = Path.home() / ".ostinttol" / "ip_history"
HIST_DIR.mkdir(parents=True, exist_ok=True)
EXPORT_DIR = Path.home() / ".ostinttol" / "exports"
EXPORT_DIR.mkdir(parents=True, exist_ok=True)
CACHE_TTL = 6 * 3600

UA = "Mozilla/5.0 (compatible; ostinttol/2.0)"


# ============================================================
# Input validation
# ============================================================
def _validate(target: str):
    """Return (ip, hostname_or_None). Resolve hostnames if given."""
    target = target.strip()
    try:
        ip = ipaddress.ip_address(target)
        return str(ip), None
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(target)
        return ip, target
    except socket.gaierror:
        return None, None


# ============================================================
# Cache
# ============================================================
def _cache_path(ip):
    return CACHE_DIR / f"{ip}.json"


def _cache_read(ip):
    p = _cache_path(ip)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if time.time() - data.get("_ts", 0) > CACHE_TTL:
            return None
        return data
    except Exception:
        return None


def _cache_write(ip, data):
    try:
        data["_ts"] = time.time()
        _cache_path(ip).write_text(
            json.dumps(data, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
    except Exception:
        pass


# ============================================================
# Generic HTTP
# ============================================================
def _get_json(url, timeout=8, headers=None, params=None):
    h = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        h.update(headers)
    r = requests.get(url, headers=h, params=params, timeout=timeout)
    r.raise_for_status()
    return r.json()


# ============================================================
# Geolocation providers (multi-source)
# ============================================================
def _ip_api(ip):
    d = _get_json(f"http://ip-api.com/json/{ip}?fields=66846719")
    if d.get("status") != "success":
        raise RuntimeError(d.get("message", "failed"))
    return {
        "country": d.get("country"),
        "country_code": d.get("countryCode"),
        "region": d.get("regionName"),
        "city": d.get("city"),
        "zip": d.get("zip"),
        "lat": d.get("lat"),
        "lon": d.get("lon"),
        "timezone": d.get("timezone"),
        "isp": d.get("isp"),
        "org": d.get("org"),
        "asn": d.get("as"),
        "reverse": d.get("reverse"),
        "mobile": d.get("mobile"),
        "proxy": d.get("proxy"),
        "hosting": d.get("hosting"),
    }


def _ipwho_is(ip):
    d = _get_json(f"https://ipwho.is/{ip}")
    if not d.get("success"):
        raise RuntimeError(d.get("message", "failed"))
    conn = d.get("connection") or {}
    tz = d.get("timezone") or {}
    return {
        "country": d.get("country"),
        "country_code": d.get("country_code"),
        "region": d.get("region"),
        "city": d.get("city"),
        "zip": d.get("postal") or "",
        "lat": d.get("latitude"),
        "lon": d.get("longitude"),
        "timezone": tz.get("id"),
        "timezone_utc": tz.get("utc"),
        "timezone_current": tz.get("current_time"),
        "isp": conn.get("isp"),
        "org": conn.get("org"),
        "asn": f"AS{conn.get('asn')} {conn.get('org', '')}".strip(),
        "continent": d.get("continent"),
        "continent_code": d.get("continent_code"),
        "capital": (d.get("country") or "") and None,
        "calling_code": d.get("calling_code"),
        "currency_code": (d.get("currency") or {}).get("code"),
        "currency_name": (d.get("currency") or {}).get("name"),
    }


def _freeipapi(ip):
    d = _get_json(f"https://freeipapi.com/api/json/{ip}")
    return {
        "country": d.get("countryName"),
        "country_code": d.get("countryCode"),
        "region": d.get("regionName"),
        "city": d.get("cityName"),
        "zip": d.get("zipCode"),
        "lat": d.get("latitude"),
        "lon": d.get("longitude"),
        "timezone": ", ".join(d.get("timeZones") or []),
    }


def _ipapi_co(ip):
    d = _get_json(f"https://ipapi.co/{ip}/json/")
    if d.get("error"):
        raise RuntimeError(d.get("reason", "failed"))
    return {
        "country": d.get("country_name"),
        "country_code": d.get("country_code"),
        "region": d.get("region"),
        "city": d.get("city"),
        "zip": d.get("postal"),
        "lat": d.get("latitude"),
        "lon": d.get("longitude"),
        "timezone": d.get("timezone"),
        "isp": d.get("org"),
        "asn": d.get("asn"),
        "currency_code": d.get("currency"),
        "calling_code": d.get("country_calling_code"),
        "language": d.get("languages"),
        "eu": d.get("in_eu"),
    }


def _ipapi_is(ip):
    """ipapi.is — free tier, 1,000/day, no key."""
    d = _get_json(f"https://api.ipapi.is/?q={ip}")
    loc = d.get("location") or {}
    asn = d.get("asn") or {}
    return {
        "country": loc.get("country"),
        "country_code": loc.get("country_code"),
        "region": loc.get("state"),
        "city": loc.get("city"),
        "zip": loc.get("zip"),
        "lat": loc.get("latitude"),
        "lon": loc.get("longitude"),
        "timezone": loc.get("timezone"),
        "isp": asn.get("org"),
        "org": asn.get("descr"),
        "asn": f"AS{asn.get('asn')}",
        "is_datacenter": d.get("is_datacenter"),
        "is_vpn": d.get("is_vpn"),
        "is_proxy": d.get("is_proxy"),
        "is_tor": d.get("is_tor"),
        "is_abuser": d.get("is_abuser"),
        "is_crawler": d.get("is_crawler"),
        "is_bot": d.get("is_bot"),
        "elapsed_ms": d.get("elapsed_ms"),
    }


def _ipdata_co(ip):
    """ipdata.co — free tier 1,500/day (key required)."""
    try:
        d = _get_json(f"https://api.ipdata.co/{ip}?api-key=test")
    except Exception:
        raise
    return {
        "country": d.get("country_name"),
        "country_code": d.get("country_code"),
        "region": d.get("region"),
        "city": d.get("city"),
        "zip": d.get("postal"),
        "lat": d.get("latitude"),
        "lon": d.get("longitude"),
        "timezone": (d.get("time_zone") or {}).get("name"),
        "isp": (d.get("asn") or {}).get("name"),
        "org": (d.get("organisation") or ""),
        "asn": (d.get("asn") or {}).get("asn"),
        "currency_code": (d.get("currency") or {}).get("code"),
        "calling_code": d.get("calling_code"),
        "threat": d.get("threat"),
    }


GEOLOCATION_PROVIDERS = [
    ("ip-api",    _ip_api),
    ("ipwho.is",  _ipwho_is),
    ("freeipapi", _freeipapi),
    ("ipapi.co",  _ipapi_co),
    ("ipapi.is",  _ipapi_is),
]


# ============================================================
# Shodan InternetDB — free, no key
# ============================================================
def _shodan_internetdb(ip):
    """Shodan's free InternetDB API — open ports, tags, CPEs, CVEs."""
    try:
        d = _get_json(f"https://internetdb.shodan.io/{ip}", timeout=10)
        return {
            "ports": d.get("ports") or [],
            "hostnames": d.get("hostnames") or [],
            "cpes": d.get("cpes") or [],
            "tags": d.get("tags") or [],
            "vulns": d.get("vulns") or [],
        }
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return {"ports": [], "hostnames": [], "cpes": [],
                    "tags": [], "vulns": [], "note": "no data"}
        return None
    except Exception:
        return None


# ============================================================
# Robtex Free API — reputation, passive DNS, historic
# ============================================================
ROBTEX_BASE = "https://freeapi.robtex.com"


def _robtex_ip_query(ip):
    try:
        return _get_json(f"{ROBTEX_BASE}/ipquery?ip={ip}", timeout=10)
    except Exception:
        return None


def _robtex_reputation(ip):
    try:
        d = _get_json(f"{ROBTEX_BASE}/ip_reputation?ip={ip}", timeout=12)
        return d
    except Exception:
        return None


def _robtex_threat_intel(ip):
    try:
        return _get_json(f"{ROBTEX_BASE}/ip_threat_intel?ip={ip}", timeout=12)
    except Exception:
        return None


def _robtex_blocklist(ip):
    try:
        return _get_json(f"{ROBTEX_BASE}/ip_blocklist_check?ip={ip}",
                         timeout=12)
    except Exception:
        return None


def _robtex_reverse_ip(ip):
    """Domains currently pointing at this IP (passive reverse DNS)."""
    try:
        return _get_json(f"{ROBTEX_BASE}/pdns_reverse?value={ip}&type=a",
                         timeout=15)
    except Exception:
        return None


def _robtex_historic_reverse(ip):
    """Domains that previously pointed at this IP."""
    try:
        return _get_json(
            f"{ROBTEX_BASE}/pdns_reverse_historic?value={ip}&type=a",
            timeout=15)
    except Exception:
        return None


def _robtex_as_prefixes(asn):
    """Prefixes announced by an AS number (IPv4 + IPv6)."""
    asn_clean = str(asn).lstrip("AS").lstrip("as")
    try:
        return _get_json(f"{ROBTEX_BASE}/as_prefixes?asn={asn_clean}",
                         timeout=12)
    except Exception:
        return None


def _robtex_as_info(asn):
    asn_clean = str(asn).lstrip("AS").lstrip("as")
    try:
        return _get_json(f"{ROBTEX_BASE}/as_info?asn={asn_clean}",
                         timeout=10)
    except Exception:
        return None


# ============================================================
# RIPE Stat — announced prefixes for ASN (fallback for Robtex)
# ============================================================
def _ripe_announced_prefixes(asn):
    asn_clean = str(asn).lstrip("AS").lstrip("as")
    try:
        d = _get_json(
            "https://stat.ripe.net/data/announced-prefixes/data.json",
            params={"resource": f"AS{asn_clean}"},
            timeout=12,
        )
        prefixes = []
        for p in (d.get("data") or {}).get("prefixes") or []:
            prefixes.append(p.get("prefix"))
        return {"prefixes": prefixes}
    except Exception:
        return None


# ============================================================
# RDAP IP — netblock + abuse contact
# ============================================================
def _rdap_ip(ip):
    try:
        d = _get_json(f"https://rdap.org/ip/{ip}", timeout=12)
    except Exception:
        return None
    out = {
        "handle": d.get("handle"),
        "name": d.get("name"),
        "start": d.get("startAddress"),
        "end": d.get("endAddress"),
        "country": d.get("country"),
        "type": d.get("type"),
        "parent": d.get("parentHandle"),
    }
    for ent in d.get("entities", []) or []:
        roles = ent.get("roles") or []
        if "abuse" in roles:
            vc = ent.get("vcardArray")
            if vc and len(vc) > 1:
                for f in vc[1]:
                    if f[0] == "email":
                        out["abuse_email"] = f[3]
                    elif f[0] == "fn":
                        out["abuse_name"] = f[3]
        if "registrant" in roles or "administrative" in roles:
            vc = ent.get("vcardArray")
            if vc and len(vc) > 1:
                for f in vc[1]:
                    if f[0] == "fn" and "registrant_name" not in out:
                        out["registrant_name"] = f[3]
    # CIDR summarization
    try:
        start = ipaddress.ip_address(out.get("start"))
        end = ipaddress.ip_address(out.get("end"))
        nets = list(ipaddress.summarize_address_range(start, end))
        if nets:
            out["cidr"] = str(nets[0])
    except Exception:
        pass
    return out


# ============================================================
# Reverse DNS + forward DNS confirmation
# ============================================================
def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _forward_dns(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


# ============================================================
# TLS certificate probe (port 443)
# ============================================================
def _tls_probe(ip):
    """Fetch cert metadata from port 443. Silent failure if closed."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=None) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                proto = ssock.version()
    except Exception:
        return None

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    sans = []
    for t, v in cert.get("subjectAltName", []):
        if t == "DNS":
            sans.append(v)
    return {
        "subject_cn": subject.get("commonName"),
        "subject_org": subject.get("organizationName"),
        "issuer_cn": issuer.get("commonName"),
        "issuer_org": issuer.get("organizationName"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "protocol": proto,
        "cipher": cipher[0] if cipher else None,
        "cipher_bits": cipher[2] if cipher else None,
        "san_count": len(sans),
        "sans": sans[:25],
    }


# ============================================================
# Port scan (light — top ports via socket connect)
# ============================================================
TOP_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
    (443, "HTTPS"), (445, "SMB"), (465, "SMTPS"), (587, "SMTP-sub"),
    (993, "IMAPS"), (995, "POP3S"), (1433, "MSSQL"), (3306, "MySQL"),
    (3389, "RDP"), (5432, "Postgres"), (6379, "Redis"),
    (8080, "HTTP-alt"), (8443, "HTTPS-alt"), (9200, "Elasticsearch"),
    (27017, "MongoDB"),
]


def _scan_port(ip, port, timeout=2):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            try:
                s = socket.socket()
                s.settimeout(1.5)
                s.connect((ip, port))
                banner = s.recv(256).decode(errors="ignore").strip()
                s.close()
                return port, True, banner
            except Exception:
                return port, True, ""
    except Exception:
        return port, False, ""


def _port_scan(ip, threads=25):
    hits = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_scan_port, ip, p) for p, _ in TOP_PORTS]
        for f in as_completed(futs):
            try:
                hits.append(f.result())
            except Exception:
                pass
    return sorted(hits)


# ============================================================
# Merge
# ============================================================
def _merge(results):
    """First non-empty value wins per key."""
    merged = {}
    for _, data in results.items():
        if not data:
            continue
        for k, v in data.items():
            if k not in merged and v not in (None, "", [], 0, False):
                merged[k] = v
    return merged


def _flag(cc):
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    return chr(0x1F1E6 + ord(cc[0].upper()) - 65) + \
           chr(0x1F1E6 + ord(cc[1].upper()) - 65)


# ============================================================
# Divergence report
# ============================================================
def _divergence(results):
    """Show where providers disagree on country / city / ASN."""
    countries = {}
    cities = {}
    asns = {}
    for src, data in results.items():
        if not data:
            continue
        cc = data.get("country_code") or data.get("country")
        if cc:
            countries.setdefault(cc, []).append(src)
        city = data.get("city")
        if city:
            cities.setdefault(city, []).append(src)
        asn = data.get("asn")
        if asn:
            asns.setdefault(str(asn), []).append(src)

    out = {"country": countries, "city": cities, "asn": asns,
           "country_diverged": len(countries) > 1,
           "city_diverged": len(cities) > 1,
           "asn_diverged": len(asns) > 1}
    return out


# ============================================================
# Reputation scoring
# ============================================================
def _reputation_score(shodan, robtex_rep, robtex_ti, robtex_bl,
                      merged_geo):
    score = 0
    reasons = []

    # proxy / VPN / hosting / tor
    if merged_geo.get("is_tor") or merged_geo.get("proxy") is True:
        score += 25
        reasons.append("Tor exit / proxy flagged by geolocation provider")
    if merged_geo.get("is_vpn"):
        score += 15
        reasons.append("VPN endpoint flagged")
    if merged_geo.get("is_datacenter") or merged_geo.get("hosting"):
        score += 10
        reasons.append("hosting / datacenter IP")
    if merged_geo.get("is_abuser"):
        score += 20
        reasons.append("flagged as abuser in abuse-intel database")

    # Shodan
    if shodan:
        vulns = shodan.get("vulns") or []
        if vulns:
            score += min(30, len(vulns) * 6)
            reasons.append(f"{len(vulns)} known CVE(s) on open services")
        tags = shodan.get("tags") or []
        for risky in ("tor", "proxy", "vpn", "honeypot", "malware",
                      "compromised", "c2", "scanner", "exploit"):
            if risky in [t.lower() for t in tags]:
                score += 15
                reasons.append(f"Shodan tag: {risky}")
                break
        ports = shodan.get("ports") or []
        risky_ports = [p for p in ports if p in
                       (23, 445, 1433, 3306, 3389, 5432, 6379, 27017,
                        9200, 11211, 2375, 2376)]
        if risky_ports:
            score += min(20, len(risky_ports) * 5)
            reasons.append(f"exposed risky ports: {risky_ports}")

    # Robtex reputation
    if robtex_rep:
        # Robtex returns list of listings from blocklists
        listings = robtex_rep if isinstance(robtex_rep, list) else \
            (robtex_rep.get("listings") or robtex_rep.get("hits") or [])
        if listings:
            n = len(listings) if isinstance(listings, list) else 1
            score += min(25, n * 5)
            reasons.append(f"{n} blocklist listing(s) via Robtex")

    if robtex_ti:
        ips = robtex_ti.get("ip_sum_score")
        if ips is not None and ips > 0:
            score += min(20, ips // 5)
            reasons.append(f"IPsum suspicious score: {ips}")
        if robtex_ti.get("is_tor"):
            score += 10
            reasons.append("Tor exit node (Robtex)")
        if robtex_ti.get("bad_asn"):
            score += 10
            reasons.append("flagged bad ASN")
        firehol = robtex_ti.get("firehol") or []
        if firehol:
            score += min(15, len(firehol) * 3)
            reasons.append(f"FireHOL tier listing(s): {len(firehol)}")

    if robtex_bl:
        lists = robtex_bl.get("listed_on") or robtex_bl.get("hits") or []
        if lists:
            score += min(20, len(lists) * 4)
            reasons.append(f"{len(lists)} public blocklist(s)")

    return min(score, 100), reasons


def _reputation_label(score):
    if score == 0:
        return "clean", "green"
    if score < 20:
        return "low risk", "green"
    if score < 45:
        return "moderate risk", "yellow"
    if score < 70:
        return "high risk", "yellow"
    return "critical", "red"


# ============================================================
# History
# ============================================================
def _history_path(ip):
    return HIST_DIR / f"{ip}.json"


def _load_history(ip):
    p = _history_path(ip)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _save_history(ip, snapshot):
    p = _history_path(ip)
    try:
        p.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False,
                                default=str), encoding="utf-8")
    except Exception:
        pass


def _diff_history(prev, curr):
    if not prev:
        return []
    diffs = []
    if prev.get("reputation_score") != curr.get("reputation_score"):
        diffs.append(
            f"reputation: {prev.get('reputation_score')} → "
            f"{curr.get('reputation_score')}"
        )
    prev_ports = set(prev.get("ports") or [])
    cur_ports = set(curr.get("ports") or [])
    added = cur_ports - prev_ports
    closed = prev_ports - cur_ports
    if added:
        diffs.append(f"new open ports: {sorted(added)}")
    if closed:
        diffs.append(f"closed ports: {sorted(closed)}")
    prev_asn = (prev.get("asn") or "").strip()
    cur_asn = (curr.get("asn") or "").strip()
    if prev_asn and cur_asn and prev_asn != cur_asn:
        diffs.append(f"ASN changed: {prev_asn} → {cur_asn}")
    prev_cc = prev.get("country_code")
    cur_cc = curr.get("country_code")
    if prev_cc and cur_cc and prev_cc != cur_cc:
        diffs.append(f"country changed: {prev_cc} → {cur_cc}")
    return diffs


# ============================================================
# Render
# ============================================================
def _render(ip, hostname, merged, rdap, ptr, shodan, tls_probe,
            robtex_ip, robtex_rep, robtex_ti, robtex_bl,
            robtex_rev, robtex_hist, as_info, prefixes,
            ports, div, rep_score, rep_reasons, history_diffs,
            sources_ok, elapsed):
    label, label_color = _reputation_label(rep_score)

    console.print(Panel.fit(
        f"[bg]IP INTELLIGENCE[/bg]  [dg]{ip}[/dg]",
        border_style="bd", padding=(0, 2),
    ))

    # reputation banner
    console.print(Panel.fit(
        f"[bg]reputation[/bg]  [{label_color}]{label} — "
        f"{rep_score}/100[/{label_color}]",
        border_style="bd", padding=(0, 2),
    ))
    for r in rep_reasons:
        console.print(f"[dg]  · {r}[/dg]")
    if not rep_reasons:
        console.print("[green]  · no adverse signals[/green]")
    console.print()

    # identity
    t = Table(border_style="bd", show_header=False, padding=(0, 2),
              title="[bg]identity[/bg]")
    t.add_column("k", style="dg", no_wrap=True)
    t.add_column("v", style="g", overflow="fold")

    def add(k, v):
        if v not in (None, "", [], 0, False):
            t.add_row(k, str(v))

    if hostname:
        add("input hostname", hostname)
    if ptr:
        add("reverse dns", ptr)
    add("continent", merged.get("continent"))
    cc = merged.get("country_code")
    country = merged.get("country") or ""
    if cc:
        country = f"{country} {_flag(cc)}".strip()
    add("country", country)
    add("region", merged.get("region"))
    add("city", merged.get("city"))
    add("zip", merged.get("zip"))
    add("capital", merged.get("capital"))
    lat, lon = merged.get("lat"), merged.get("lon")
    if lat is not None and lon is not None:
        add("coords", f"{lat}, {lon}")
        add("map", f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}"
                  f"#map=12/{lat}/{lon}")
    add("timezone", merged.get("timezone"))
    add("current time", merged.get("timezone_current"))
    add("currency", merged.get("currency_code")
        and f"{merged.get('currency_name') or ''} ({merged['currency_code']})")
    add("calling code", merged.get("calling_code"))
    add("language", merged.get("language"))
    add("ISP", merged.get("isp"))
    add("org", merged.get("org"))
    add("ASN", merged.get("asn"))
    if merged.get("mobile") is not None:
        add("mobile", merged["mobile"])
    if merged.get("proxy") is not None:
        add("proxy", merged["proxy"])
    if merged.get("hosting") is not None:
        add("hosting", merged["hosting"])
    if merged.get("is_vpn") is not None:
        add("vpn", merged["is_vpn"])
    if merged.get("is_tor") is not None:
        add("tor", merged["is_tor"])
    if merged.get("is_datacenter") is not None:
        add("datacenter", merged["is_datacenter"])
    if merged.get("is_crawler") is not None:
        add("crawler", merged["is_crawler"])
    if merged.get("is_abuser") is not None:
        add("abuser", merged["is_abuser"])
    if merged.get("is_bot") is not None:
        add("bot", merged["is_bot"])
    console.print(t)

    # RDAP
    if rdap:
        rt = Table(border_style="bd", show_header=False, padding=(0, 2),
                   title="[bg]rdap (netblock)[/bg]")
        rt.add_column("k", style="dg", no_wrap=True)
        rt.add_column("v", style="g", overflow="fold")
        for k in ("handle", "name", "type", "country", "start", "end",
                  "cidr", "parent", "abuse_email", "abuse_name",
                  "registrant_name"):
            v = rdap.get(k)
            if v:
                rt.add_row(k, str(v))
        console.print(rt)

    # AS info
    if as_info or prefixes:
        at = Table(border_style="bd", show_header=False, padding=(0, 2),
                   title="[bg]autonomous system[/bg]")
        at.add_column("k", style="dg", no_wrap=True)
        at.add_column("v", style="g", overflow="fold")
        if as_info:
            for k in ("asn", "name", "org", "country", "descr",
                      "description"):
                v = as_info.get(k)
                if v:
                    at.add_row(k, str(v)[:120])
        if prefixes and prefixes.get("prefixes"):
            plist = prefixes["prefixes"]
            at.add_row("prefix count", str(len(plist)))
            for p in plist[:8]:
                at.add_row("  prefix", str(p))
            if len(plist) > 8:
                at.add_row("  ", f"... +{len(plist) - 8} more")
        console.print(at)

    # Shodan InternetDB
    if shodan:
        st = Table(border_style="bd", show_header=True, padding=(0, 2),
                   title="[bg]shodan internetdb[/bg]")
        st.add_column("field", style="dg")
        st.add_column("value", style="g", overflow="fold")
        ports_s = ", ".join(str(p) for p in (shodan.get("ports") or []))
        st.add_row("open ports", ports_s or "—")
        if shodan.get("hostnames"):
            st.add_row("hostnames", ", ".join(shodan["hostnames"][:10]))
        if shodan.get("tags"):
            st.add_row("tags", ", ".join(shodan["tags"]))
        if shodan.get("cpes"):
            st.add_row("CPEs", "; ".join(shodan["cpes"][:5]))
        vulns = shodan.get("vulns") or []
        if vulns:
            st.add_row("CVEs", f"[red]{', '.join(vulns[:10])}[/red]")
            if len(vulns) > 10:
                st.add_row("", f"... +{len(vulns) - 10} more")
        console.print(st)

    # Port scan
    open_ports = [p for p, ok, _ in ports if ok]
    if open_ports:
        pt = Table(border_style="bd",
                   title=f"[bg]port scan[/bg]  [g]{len(open_ports)} open[/g]",
                   show_header=True, padding=(0, 2))
        pt.add_column("port", style="bg", justify="right")
        pt.add_column("service", style="dg")
        pt.add_column("banner", style="g", overflow="fold")
        for port, ok, banner in ports:
            if not ok:
                continue
            svc = next((s for p, s in TOP_PORTS if p == port), "?")
            pt.add_row(str(port), svc, banner[:60] or "")
        console.print(pt)

    # TLS
    if tls_probe:
        tt = Table(border_style="bd", show_header=False, padding=(0, 2),
                   title="[bg]tls certificate (443)[/bg]")
        tt.add_column("k", style="dg", no_wrap=True)
        tt.add_column("v", style="g", overflow="fold")
        for k in ("subject_cn", "subject_org", "issuer_cn", "issuer_org",
                  "protocol", "cipher", "cipher_bits",
                  "not_before", "not_after", "san_count"):
            v = tls_probe.get(k)
            if v:
                tt.add_row(k, str(v))
        if tls_probe.get("sans"):
            tt.add_row("SANs", ", ".join(tls_probe["sans"][:12]))
        console.print(tt)

    # Robtex IP query
    if robtex_ip:
        rbt = Table(border_style="bd", show_header=False, padding=(0, 2),
                    title="[bg]robtex ipquery[/bg]")
        rbt.add_column("k", style="dg", no_wrap=True)
        rbt.add_column("v", style="g", overflow="fold")
        for k in ("city", "country", "bgproute", "as", "asname"):
            v = robtex_ip.get(k)
            if v:
                rbt.add_row(k, str(v))
        acts = robtex_ip.get("act") or []
        if acts:
            rbt.add_row("active DNS", ", ".join(
                a.get("o", "?") for a in acts[:5]))
        pas = robtex_ip.get("pas") or []
        if pas:
            rbt.add_row("passive DNS", ", ".join(
                p.get("o", "?") for p in pas[:5]))
        console.print(rbt)

    # Passive reverse DNS
    if robtex_rev or robtex_hist:
        rev_rows = []
        if robtex_rev:
            items = robtex_rev if isinstance(robtex_rev, list) else \
                (robtex_rev.get("results") or robtex_rev.get("data") or [])
            for r in items[:20]:
                if isinstance(r, dict):
                    rev_rows.append(("current", r.get("rrname") or
                                     r.get("o") or "?"))
                else:
                    rev_rows.append(("current", str(r)))
        if robtex_hist:
            items = robtex_hist if isinstance(robtex_hist, list) else \
                (robtex_hist.get("results") or robtex_hist.get("data") or [])
            for r in items[:20]:
                if isinstance(r, dict):
                    rev_rows.append(("historic", r.get("rrname") or
                                     r.get("o") or "?"))
                else:
                    rev_rows.append(("historic", str(r)))
        if rev_rows:
            rt = Table(border_style="bd",
                       title=f"[bg]passive reverse DNS[/bg]  "
                             f"[g]{len(rev_rows)}[/g]",
                       show_header=True, padding=(0, 2))
            rt.add_column("scope", style="dg")
            rt.add_column("domain", style="g", overflow="fold")
            for scope, dom in rev_rows:
                rt.add_row(scope, dom)
            console.print(rt)

    # Divergence
    if div:
        c_div = div.get("country_diverged")
        city_div = div.get("city_diverged")
        asn_div = div.get("asn_diverged")
        if c_div or city_div or asn_div:
            dt = Table(border_style="bd",
                       title="[bg]provider divergence[/bg]",
                       show_header=True, padding=(0, 2))
            dt.add_column("field", style="dg")
            dt.add_column("values", style="g", overflow="fold")
            if c_div:
                dt.add_row("country", ", ".join(
                    f"{k} ({','.join(v)})" for k, v in
                    div["country"].items()))
            if city_div:
                dt.add_row("city", ", ".join(
                    f"{k} ({','.join(v)})" for k, v in
                    div["city"].items()))
            if asn_div:
                dt.add_row("asn", ", ".join(
                    f"{k} ({','.join(v)})" for k, v in
                    div["asn"].items()))
            console.print(dt)

    # History diff
    if history_diffs:
        console.print(Panel.fit(
            "[bg]changes since last scan[/bg]",
            border_style="bd", padding=(0, 2),
        ))
        for d in history_diffs:
            console.print(f"[yellow]  · {d}[/yellow]")
        console.print()

    console.print(f"[dg]  sources ok: {sources_ok}  ·  {elapsed:.2f}s[/dg]\n")


# ============================================================
# Export
# ============================================================
def _export_json(ip, payload):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    p = EXPORT_DIR / f"ip_{ip.replace(':', '_')}_{ts}.json"
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False,
                            default=str), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]")
    return p


def _export_csv(ip, merged, rdap, shodan, ports, rep_score, rep_reasons):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    p = EXPORT_DIR / f"ip_{ip.replace(':', '_')}_{ts}.csv"
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["section", "key", "value"])
        w.writerow(["meta", "ip", ip])
        w.writerow(["meta", "reputation_score", rep_score])
        for i, r in enumerate(rep_reasons):
            w.writerow(["reputation", f"reason_{i}", r])
        for k, v in merged.items():
            w.writerow(["geo", k, str(v)])
        if rdap:
            for k, v in rdap.items():
                w.writerow(["rdap", k, str(v)])
        if shodan:
            for k, v in shodan.items():
                w.writerow(["shodan", k, str(v)])
        for port, ok, banner in ports:
            if ok:
                w.writerow(["port", str(port), banner[:100]])
    console.print(f"[dg]  exported → {p}[/dg]")


def _export_html(ip, merged, rdap, shodan, tls_probe, ports,
                 robtex_rev, prefixes, rep_score, rep_reasons):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    p = EXPORT_DIR / f"ip_{ip.replace(':', '_')}_{ts}.html"

    def esc(x):
        return html.escape(str(x))

    def rows_table(rows, headers):
        th = "".join(f"<th>{esc(h)}</th>" for h in headers)
        trs = "".join(
            "<tr>" + "".join(f"<td>{esc(c)}</td>" for c in r) + "</tr>"
            for r in rows)
        return f"<table><tr>{th}</tr>{trs}</table>"

    label, label_color = _reputation_label(rep_score)
    color_map = {"green": "#8fe388", "yellow": "#f2c14e", "red": "#ff6b6b"}
    score_color = color_map.get(label_color, "#dddddd")

    geo_rows = [(k, str(v)) for k, v in merged.items()]
    rdap_rows = [(k, str(v)) for k, v in (rdap or {}).items() if v]
    shodan_rows = []
    if shodan:
        for k in ("ports", "hostnames", "tags", "cpes", "vulns"):
            v = shodan.get(k)
            if v:
                shodan_rows.append((k, ", ".join(str(x) for x in v)))
    tls_rows = []
    if tls_probe:
        for k, v in tls_probe.items():
            if k == "sans":
                v = ", ".join(v[:20])
            tls_rows.append((k, str(v)))
    port_rows = [(str(p), next((s for pp, s in TOP_PORTS if pp == p), "?"),
                  banner[:80]) for p, ok, banner in ports if ok]
    rev_rows = []
    if robtex_rev:
        items = robtex_rev if isinstance(robtex_rev, list) else \
            (robtex_rev.get("results") or [])
        for r in items[:50]:
            if isinstance(r, dict):
                rev_rows.append((r.get("rrname") or r.get("o") or "?",))
            else:
                rev_rows.append((str(r),))
    reasons_html = "".join(f"<li>{esc(r)}</li>" for r in rep_reasons)

    doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>IP Report — {esc(ip)}</title>
<style>
body {{ background: #111; color: #ddd; font-family: monospace; padding: 2em; }}
h1, h2 {{ color: #9fd4ff; }}
table {{ border-collapse: collapse; margin: 1em 0; }}
td, th {{ border: 1px solid #333; padding: 4px 10px; }}
a {{ color: #8fe388; }}
.score {{ font-size: 2em; color: {score_color}; }}
</style></head><body>
<h1>IP Report — {esc(ip)}</h1>
<p>Generated {esc(datetime.now().isoformat(timespec="seconds"))}</p>
<h2>Reputation — {esc(label)} {esc(rep_score)}/100</h2>
<p class="score">{esc(rep_score)}/100</p>
<ul>{reasons_html or "<li>no adverse signals</li>"}</ul>
<h2>Geolocation</h2>
{rows_table(geo_rows, ["field", "value"])}
<h2>RDAP (Netblock)</h2>
{rows_table(rdap_rows, ["field", "value"]) if rdap_rows else "<p>—</p>"}
<h2>Shodan InternetDB</h2>
{rows_table(shodan_rows, ["field", "value"]) if shodan_rows else "<p>—</p>"}
<h2>Port Scan</h2>
{rows_table(port_rows, ["port", "service", "banner"]) if port_rows else "<p>—</p>"}
<h2>TLS Certificate</h2>
{rows_table(tls_rows, ["field", "value"]) if tls_rows else "<p>—</p>"}
<h2>Reverse DNS (passive)</h2>
{rows_table(rev_rows, ["domain"]) if rev_rows else "<p>—</p>"}
</body></html>
"""
    p.write_text(doc, encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]")


# ============================================================
# Core processing
# ============================================================
def _process_one(ip, hostname, use_cache=True):
    """Run all enrichment and return the payload dict."""

    if use_cache:
        cached = _cache_read(ip)
        if cached:
            console.print(f"[dg]  cache hit for {ip}[/dg]")
            return cached

    start = time.time()
    geo_results = {}
    extra = {}

    # ---- parallel geolocation + RDAP + reverse DNS + Robtex + Shodan ----
    tasks = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        for name, fn in GEOLOCATION_PROVIDERS:
            tasks.append((name, ex.submit(fn, ip)))
        tasks.append(("rdap", ex.submit(_rdap_ip, ip)))
        tasks.append(("ptr", ex.submit(_reverse_dns, ip)))
        tasks.append(("shodan", ex.submit(_shodan_internetdb, ip)))
        tasks.append(("robtex_ip", ex.submit(_robtex_ip_query, ip)))
        tasks.append(("robtex_rep", ex.submit(_robtex_reputation, ip)))
        tasks.append(("robtex_ti", ex.submit(_robtex_threat_intel, ip)))
        tasks.append(("robtex_bl", ex.submit(_robtex_blocklist, ip)))
        tasks.append(("robtex_rev", ex.submit(_robtex_reverse_ip, ip)))
        tasks.append(("robtex_hist",
                      ex.submit(_robtex_historic_reverse, ip)))
        tasks.append(("tls", ex.submit(_tls_probe, ip)))

        with tqdm(total=len(tasks), desc=f"enriching {ip}",
                  ncols=60, bar_format=BAR_FMT) as bar:
            for name, fut in tasks:
                try:
                    result = fut.result()
                except Exception:
                    result = None
                if name in ("rdap", "ptr", "shodan", "robtex_ip",
                            "robtex_rep", "robtex_ti", "robtex_bl",
                            "robtex_rev", "robtex_hist", "tls"):
                    extra[name] = result
                else:
                    geo_results[name] = result
                bar.update(1)

    # ---- port scan (runs after the parallel phase to avoid saturating
    #      the network stack while the other requests finish) ----
    ports = _port_scan(ip)
    open_ports = [p for p, ok, _ in ports if ok]
    extra["ports"] = ports
    extra["open_ports"] = open_ports

    # ---- AS lookup (using ASN from merged geolocation) ----
    merged = _merge(geo_results)
    asn = merged.get("asn")
    as_info = None
    prefixes = None
    if asn:
        asn_clean = str(asn)
        m = re.search(r"(\d+)", asn_clean)
        if m:
            num = m.group(1)
            with ThreadPoolExecutor(max_workers=2) as ex:
                f_info = ex.submit(_robtex_as_info, num)
                f_prefix = ex.submit(_robtex_as_prefixes, num)
                try:
                    as_info = f_info.result()
                except Exception:
                    as_info = None
                try:
                    prefixes = f_prefix.result()
                except Exception:
                    prefixes = None
            # fallback to RIPE if Robtex returned nothing
            if not prefixes or not (prefixes.get("prefixes")
                                    or prefixes.get("ipv4")
                                    or prefixes.get("ipv6")):
                with ThreadPoolExecutor(max_workers=1) as ex:
                    f2 = ex.submit(_ripe_announced_prefixes, num)
                    try:
                        ripe = f2.result()
                        if ripe:
                            prefixes = ripe
                    except Exception:
                        pass
    extra["as_info"] = as_info
    extra["prefixes"] = prefixes

    # ---- pointer RDAP ASN/prefix correlation ----
    merged["reverse"] = merged.get("reverse") or extra.get("ptr")

    # ---- divergence ----
    div = _divergence(geo_results)

    # ---- reputation ----
    rep_score, rep_reasons = _reputation_score(
        extra.get("shodan"), extra.get("robtex_rep"),
        extra.get("robtex_ti"), extra.get("robtex_bl"), merged,
    )

    # ---- history diff ----
    snapshot = {
        "ip": ip,
        "reputation_score": rep_score,
        "reasons": rep_reasons,
        "ports": open_ports,
        "asn": merged.get("asn"),
        "country_code": merged.get("country_code"),
        "generated": datetime.now().isoformat(timespec="seconds"),
    }
    prev = _load_history(ip)
    history_diffs = _diff_history(prev, snapshot)

    elapsed = time.time() - start
    sources_ok = sum(1 for v in geo_results.values() if v) + \
                 sum(1 for k in ("rdap", "shodan", "robtex_ip", "tls")
                     if extra.get(k))

    payload = {
        "ip": ip,
        "hostname": hostname,
        "merged_geo": merged,
        "geo_raw": geo_results,
        "rdap": extra.get("rdap"),
        "ptr": extra.get("ptr"),
        "shodan": extra.get("shodan"),
        "tls": extra.get("tls"),
        "robtex_ip": extra.get("robtex_ip"),
        "robtex_reputation": extra.get("robtex_rep"),
        "robtex_threat_intel": extra.get("robtex_ti"),
        "robtex_blocklist": extra.get("robtex_bl"),
        "robtex_reverse_dns": extra.get("robtex_rev"),
        "robtex_historic_dns": extra.get("robtex_hist"),
        "as_info": extra.get("as_info"),
        "prefixes": extra.get("prefixes"),
        "ports": [{"port": p, "open": ok, "banner": b}
                  for p, ok, b in extra.get("ports", [])],
        "open_ports": open_ports,
        "divergence": div,
        "reputation_score": rep_score,
        "reputation_reasons": rep_reasons,
        "history_diffs": history_diffs,
        "sources_ok": sources_ok,
        "elapsed": elapsed,
        "generated": datetime.now().isoformat(timespec="seconds"),
    }

    _cache_write(ip, payload)
    _save_history(ip, snapshot)
    return payload


# ============================================================
# Runner
# ============================================================
def run():
    raw = input("  ip / hostname (or comma-separated list) >> ").strip()
    if not raw:
        print("  [!] empty target")
        return

    targets = [t.strip() for t in raw.split(",") if t.strip()]
    if not targets:
        print("  [!] no targets")
        return

    payloads = []
    for target in targets:
        ip, hostname = _validate(target)
        if not ip:
            console.print(f"[yellow]  [!] invalid or unresolvable: {target}[/yellow]")
            continue

        console.print()
        console.print(f"[bg]  ▶ {ip}[/bg]")

        payload = _process_one(ip, hostname, use_cache=True)
        payloads.append(payload)

        _render(
            ip, hostname,
            payload.get("merged_geo") or {},
            payload.get("rdap"),
            payload.get("ptr"),
            payload.get("shodan"),
            payload.get("tls"),
            payload.get("robtex_ip"),
            payload.get("robtex_reputation"),
            payload.get("robtex_threat_intel"),
            payload.get("robtex_blocklist"),
            payload.get("robtex_reverse_dns"),
            payload.get("robtex_historic_dns"),
            payload.get("as_info"),
            payload.get("prefixes"),
            payload.get("ports") and [
                (p["port"], p["open"], p["banner"])
                for p in payload["ports"]
            ] or [],
            payload.get("divergence"),
            payload.get("reputation_score", 0),
            payload.get("reputation_reasons") or [],
            payload.get("history_diffs") or [],
            payload.get("sources_ok", 0),
            payload.get("elapsed", 0.0),
        )

    if not payloads:
        return

    # ---- exports ----
    choice = input("  export json? [y/N] >> ").strip().lower()
    if choice == "y":
        for p in payloads:
            _export_json(p["ip"], p)

    choice = input("  export csv? [y/N] >> ").strip().lower()
    if choice == "y":
        for p in payloads:
            _export_csv(
                p["ip"], p.get("merged_geo") or {}, p.get("rdap"),
                p.get("shodan"),
                p.get("ports") and [
                    (pp["port"], pp["open"], pp["banner"])
                    for pp in p["ports"]
                ] or [],
                p.get("reputation_score", 0),
                p.get("reputation_reasons") or [],
            )

    choice = input("  export html? [y/N] >> ").strip().lower()
    if choice == "y":
        for p in payloads:
            _export_html(
                p["ip"], p.get("merged_geo") or {}, p.get("rdap"),
                p.get("shodan"), p.get("tls"),
                p.get("ports") and [
                    (pp["port"], pp["open"], pp["banner"])
                    for pp in p["ports"]
                ] or [],
                p.get("robtex_reverse_dns"),
                p.get("prefixes"),
                p.get("reputation_score", 0),
                p.get("reputation_reasons") or [],
            )
