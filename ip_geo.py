"""
ip_geo.py — Multi-source IP intelligence.

Aggregates geolocation, ASN, network registration (RDAP), reverse DNS,
and abuse contact data from several public providers. Disk-cached with
per-source fallbacks so a single dead endpoint doesn't kill the lookup.
"""

import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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

CACHE_DIR = Path.home() / ".doxtoolkit" / "ipcache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
CACHE_TTL = 6 * 3600

UA = "Mozilla/5.0 (compatible; doxtoolkit/2.0; +https://localhost)"


# ───────────────────────── input ─────────────────────────

def _validate(target: str):
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


# ───────────────────────── cache ─────────────────────────

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
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


# ───────────────────────── providers ─────────────────────────

def _get(url, timeout=8):
    r = requests.get(
        url,
        headers={"User-Agent": UA, "Accept": "application/json"},
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()


def _ip_api(ip):
    d = _get(f"http://ip-api.com/json/{ip}?fields=66846719")
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
    d = _get(f"https://ipwho.is/{ip}")
    if not d.get("success"):
        raise RuntimeError(d.get("message", "failed"))
    conn = d.get("connection") or {}
    return {
        "country": d.get("country"),
        "country_code": d.get("country_code"),
        "region": d.get("region"),
        "city": d.get("city"),
        "zip": d.get("postal") or "",
        "lat": d.get("latitude"),
        "lon": d.get("longitude"),
        "timezone": (d.get("timezone") or {}).get("id"),
        "isp": conn.get("isp"),
        "org": conn.get("org"),
        "asn": f"AS{conn.get('asn')} {conn.get('org', '')}".strip(),
    }


def _freeipapi(ip):
    d = _get(f"https://freeipapi.com/api/json/{ip}")
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
    d = _get(f"https://ipapi.co/{ip}/json/")
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
    }


PROVIDERS = [
    ("ip-api",    _ip_api),
    ("ipwho.is",  _ipwho_is),
    ("freeipapi", _freeipapi),
    ("ipapi.co",  _ipapi_co),
]


# ───────────────────────── RDAP / PTR ─────────────────────────

def _rdap(ip):
    try:
        d = _get(f"https://rdap.org/ip/{ip}", timeout=10)
    except Exception:
        return None
    out = {
        "handle": d.get("handle"),
        "name": d.get("name"),
        "start": d.get("startAddress"),
        "end": d.get("endAddress"),
        "country": d.get("country"),
        "type": d.get("type"),
    }
    for ent in d.get("entities", []) or []:
        if "abuse" in (ent.get("roles") or []):
            vc = ent.get("vcardArray")
            if vc and len(vc) > 1:
                for f in vc[1]:
                    if f[0] == "email":
                        out["abuse_email"] = f[3]
                    elif f[0] == "fn":
                        out["abuse_name"] = f[3]
    return out


def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ───────────────────────── merge / output ─────────────────────────

def _merge(results):
    merged = {}
    for _, data in results.items():
        if not data:
            continue
        for k, v in data.items():
            if k not in merged and v not in (None, "", []):
                merged[k] = v
    return merged


def _flag(cc):
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    return chr(0x1F1E6 + ord(cc[0].upper()) - 65) + \
           chr(0x1F1E6 + ord(cc[1].upper()) - 65)


def _render(ip, hostname, merged, rdap, ptr, sources_ok, elapsed):
    console.print(Panel.fit(
        f"[bg]IP INTELLIGENCE[/bg]  [dg]{ip}[/dg]",
        border_style="bd", padding=(0, 2),
    ))

    t = Table(border_style="bd", show_header=False, padding=(0, 2))
    t.add_column("k", style="dg", no_wrap=True)
    t.add_column("v", style="g")

    def add(k, v):
        if v not in (None, "", []):
            t.add_row(k, str(v))

    if hostname:
        add("hostname", hostname)
    if ptr:
        add("reverse dns", ptr)

    cc = merged.get("country_code")
    country = merged.get("country") or ""
    if cc:
        country = f"{country} {_flag(cc)}".strip()
    add("country", country)
    add("region", merged.get("region"))
    add("city", merged.get("city"))
    add("zip", merged.get("zip"))
    lat, lon = merged.get("lat"), merged.get("lon")
    if lat is not None and lon is not None:
        add("coords", f"{lat}, {lon}")
        add("map", f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}"
                  f"#map=12/{lat}/{lon}")
    add("timezone", merged.get("timezone"))
    add("isp", merged.get("isp"))
    add("org", merged.get("org"))
    add("asn", merged.get("asn"))
    if merged.get("proxy") is not None:
        add("proxy/vpn", merged.get("proxy"))
    if merged.get("hosting") is not None:
        add("hosting", merged.get("hosting"))
    if merged.get("mobile") is not None:
        add("mobile", merged.get("mobile"))
    console.print(t)

    if rdap:
        rt = Table(border_style="bd", show_header=False, padding=(0, 2),
                   title="[bg]rdap[/bg]")
        rt.add_column("k", style="dg", no_wrap=True)
        rt.add_column("v", style="g")
        for k, v in rdap.items():
            if v:
                rt.add_row(k, str(v))
        console.print(rt)

    console.print(f"[dg]  sources ok: {sources_ok}  ·  {elapsed:.2f}s[/dg]\n")


# ───────────────────────── entry ─────────────────────────

def run():
    target = input("  ip / hostname >> ").strip()
    if not target:
        print("  [!] empty target")
        return

    ip, hostname = _validate(target)
    if not ip:
        print("  [!] invalid ip or unresolvable host")
        return

    cached = _cache_read(ip)
    if cached:
        console.print(f"[dg]  cache hit for {ip}[/dg]")
        _render(ip, hostname, cached.get("merged", {}),
                cached.get("rdap"), cached.get("ptr"),
                cached.get("_sources", 0), 0.0)
        return

    start = time.time()
    results = {}
    with tqdm(total=len(PROVIDERS) + 2,
              desc=f"enriching {ip}",
              ncols=60, bar_format=BAR_FMT) as bar:
        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(fn, ip): name for name, fn in PROVIDERS}
            futs[ex.submit(_rdap, ip)] = "rdap"
            futs[ex.submit(_reverse_dns, ip)] = "ptr"
            for fut in as_completed(futs):
                name = futs[fut]
                try:
                    results[name] = fut.result()
                except Exception:
                    results[name] = None
                bar.update(1)

    rdap = results.pop("rdap", None)
    ptr = results.pop("ptr", None)
    merged = _merge(results)
    if ptr and not merged.get("reverse"):
        merged["reverse"] = ptr

    sources_ok = sum(1 for v in results.values() if v)
    elapsed = time.time() - start

    _cache_write(ip, {"merged": merged, "rdap": rdap, "ptr": ptr,
                      "_sources": sources_ok})
    _render(ip, hostname, merged, rdap, ptr, sources_ok, elapsed)