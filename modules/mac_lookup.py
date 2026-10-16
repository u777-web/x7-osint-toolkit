"""
mac_lookup.py — MAC address vendor & hardware intelligence (deep edition).

Validates and normalizes MAC addresses, resolves OUI across multiple
providers with fallback, and provides deep analysis of address type,
block type, country, and randomization signals.

New in this version:
  · Multi-provider OUI lookup (macadress.com keyless, macvendors.com,
    http2mac, macaddress.io with key, local embedded fallback)
  · IEEE block-type identification (MA-L, MA-M, MA-S, IAB, CID)
  · Country code from OUI assignment
  · Address type analysis: unicast/multicast, UAA/LAA
  · Randomization detection (privacy MAC heuristics)
  · Virtual machine / container / emulator detection
  · EUI-64 and IPv6 link-local derivation
  · Full MAC address bit-level breakdown
  · Local OUI database download + cache (IEEE CSV)
  · Batch input mode (paste multiple MACs)
  · Scan history per OUI with diff
  · Export to JSON, CSV, HTML
"""

import csv
import hashlib
import html
import io
import json
import re
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
    "red": "red", "green": "green", "yellow": "yellow",
}))

BAR_FMT = "\033[38;5;245m  {desc} |{bar}| {percentage:3.0f}%\033[0m"
OUT_DIR = Path.home() / ".ostinttol" / "exports"
OUT_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR = Path.home() / ".ostinttol" / "mac_lookup"
DATA_DIR.mkdir(parents=True, exist_ok=True)
HIST_DIR = DATA_DIR / "history"
HIST_DIR.mkdir(parents=True, exist_ok=True)
OUI_CACHE = DATA_DIR / "oui_cache.json"
CONFIG_FILE = Path("config") / "config.json"

UA = "Mozilla/5.0 (compatible; ostinttol)"


# ============================================================
# Config
# ============================================================
def _load_config():
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


# ============================================================
# Local OUI fallback (extended)
# ============================================================
LOCAL_OUI = {
    # virtualisation
    "000C29": ("VMware", "US"), "005056": ("VMware", "US"),
    "000569": ("VMware", "US"), "001C14": ("VMware", "US"),
    "080027": ("Oracle VirtualBox", "US"),
    "0A0027": ("Oracle VirtualBox", "US"),
    "525400": ("QEMU/KVM", "US"), "52540A": ("QEMU", "US"),
    "00155D": ("Microsoft (Hyper-V)", "US"),
    "001C42": ("Parallels", "US"),
    "000F4B": ("Virtual Iron", "US"),
    "020054": ("Xen", "US"),
    "00163E": ("XenSource", "US"),
    "0003FF": ("Microsoft Virtual PC", "US"),
    "001DD8": ("Microsoft", "US"),
    # Raspberry Pi
    "B827EB": ("Raspberry Pi Foundation", "GB"),
    "DCA632": ("Raspberry Pi Trading", "GB"),
    "E45F01": ("Raspberry Pi Trading", "GB"),
    "2CCF67": ("Raspberry Pi Trading", "GB"),
    # Apple
    "288023": ("Apple", "US"), "3C0754": ("Apple", "US"),
    "F0766F": ("Apple", "US"), "A45E60": ("Apple", "US"),
    "9C207B": ("Apple", "US"), "3C22FB": ("Apple", "US"),
    "F0DBE2": ("Apple", "US"), "6C4008": ("Apple", "US"),
    # Samsung
    "F4F5D8": ("Samsung", "KR"), "8425DB": ("Samsung", "KR"),
    "E8E5D6": ("Samsung", "KR"), "3C5A37": ("Samsung", "KR"),
    "5C0A5B": ("Samsung", "KR"),
    # TP-Link
    "3C46D8": ("TP-Link", "CN"), "50C7BF": ("TP-Link", "CN"),
    "A42BB0": ("TP-Link", "CN"), "0C8063": ("TP-Link", "CN"),
    "5C63BF": ("TP-Link", "CN"), "F8D111": ("TP-Link", "CN"),
    "E8DE27": ("TP-Link", "CN"), "18A6F7": ("TP-Link", "CN"),
    "A0F3C1": ("TP-Link", "CN"), "C46E1F": ("TP-Link", "CN"),
    "B0BE76": ("TP-Link", "CN"), "5C0214": ("TP-Link", "CN"),
    # D-Link
    "001B11": ("D-Link", "TW"), "1CBDB9": ("D-Link", "TW"),
    "F07D68": ("D-Link", "TW"), "001E58": ("D-Link", "TW"),
    # ZyXEL
    "001349": ("ZyXEL", "TW"), "5CE28C": ("ZyXEL", "TW"),
    # NETGEAR
    "20E52A": ("NETGEAR", "US"), "9CD36D": ("NETGEAR", "US"),
    "A040A0": ("NETGEAR", "US"), "E091F5": ("NETGEAR", "US"),
    # ASUSTek
    "0C9D92": ("ASUSTek", "TW"), "2C56DC": ("ASUSTek", "TW"),
    "AC9E17": ("ASUSTek", "TW"), "708BCD": ("ASUSTek", "TW"),
    "001BFC": ("ASUSTek", "TW"), "3C7C3F": ("ASUSTek", "TW"),
    "1C872C": ("ASUSTek", "TW"), "E0CB4E": ("ASUSTek", "TW"),
    "F832E4": ("ASUSTek", "TW"), "BCEE7B": ("ASUSTek", "TW"),
    # HP
    "D8D385": ("Hewlett Packard", "US"),
    "001708": ("Hewlett Packard", "US"),
    # Dell
    "D4BED9": ("Dell", "US"), "00188B": ("Dell", "US"),
    "F8BC12": ("Dell", "US"), "B083FE": ("Dell", "US"),
    "F48E38": ("Dell", "US"), "5CF9DD": ("Dell", "US"),
    "001E4F": ("Dell", "US"), "1866DA": ("Dell", "US"),
    "D067E5": ("Dell", "US"),
    # Intel
    "0024D7": ("Intel", "US"), "0021CC": ("Intel", "US"),
    "3C9509": ("Intel", "US"), "4C3488": ("Intel", "US"),
    "A0A8CD": ("Intel", "US"), "001B21": ("Intel", "US"),
    "0026C7": ("Intel", "US"), "3CA9F4": ("Intel", "US"),
    "E4A471": ("Intel", "US"), "7CB27D": ("Intel", "US"),
    "38BAF8": ("Intel", "US"), "9CB6D0": ("Intel", "US"),
    "B4AE2B": ("Intel", "US"),
    # Cisco
    "00000C": ("Cisco", "US"), "000142": ("Cisco", "US"),
    "001BD4": ("Cisco", "US"), "FCFBFB": ("Cisco", "US"),
    "087402": ("Cisco", "US"),
    # Microsoft
    "000D3A": ("Microsoft", "US"), "7C1E52": ("Microsoft", "US"),
    "C83F26": ("Microsoft", "US"), "281878": ("Microsoft", "US"),
    "F01DBC": ("Microsoft", "US"), "0017FA": ("Microsoft", "US"),
    # Amazon
    "DCB4C4": ("Amazon", "US"), "44650D": ("Amazon", "US"),
    "F0272D": ("Amazon", "US"), "6854FD": ("Amazon", "US"),
    "A002DC": ("Amazon", "US"), "747548": ("Amazon", "US"),
    "84D6D0": ("Amazon", "US"), "FC65DE": ("Amazon", "US"),
    "38F73D": ("Amazon", "US"), "0C47C9": ("Amazon", "US"),
    "6C5697": ("Amazon", "US"), "B47C9C": ("Amazon", "US"),
    # Google
    "44D9E7": ("Google", "US"), "F4F5E8": ("Google", "US"),
    "3C5AB4": ("Google", "US"), "9C4E36": ("Google", "US"),
    "A47733": ("Google", "US"), "1CDF0F": ("Google", "US"),
    "DA1664": ("Google", "US"), "E4F042": ("Google", "US"),
    "F88FCA": ("Google", "US"), "C4AD34": ("Google", "US"),
    # Xiaomi
    "D850E6": ("Xiaomi", "CN"), "64B473": ("Xiaomi", "CN"),
    "F8A45F": ("Xiaomi", "CN"), "F0B429": ("Xiaomi", "CN"),
    "50EC50": ("Xiaomi", "CN"),
    # OnePlus
    "7CB59B": ("OnePlus", "CN"), "C0EEFB": ("OnePlus", "CN"),
    "94652D": ("OnePlus", "CN"), "AC64DD": ("OnePlus", "CN"),
    "E41C4B": ("OnePlus", "CN"),
    # Huawei
    "1C1B0D": ("Huawei", "CN"), "E0247F": ("Huawei", "CN"),
    "D07AB5": ("Huawei", "CN"), "C8D15E": ("Huawei", "CN"),
    "00E0FC": ("Huawei", "CN"), "F8E61A": ("Huawei", "CN"),
    # Realtek
    "00E04C": ("Realtek", "TW"),
    # Sony
    "9C5CF9": ("Sony", "JP"),
}


# ============================================================
# Virtualisation fingerprints
# ============================================================
VIRTUAL_PREFIXES = {
    "000C29": "VMware", "005056": "VMware", "000569": "VMware",
    "001C14": "VMware",
    "080027": "Oracle VirtualBox", "0A0027": "Oracle VirtualBox",
    "525400": "QEMU/KVM", "52540A": "QEMU",
    "00155D": "Microsoft Hyper-V",
    "001C42": "Parallels",
    "000F4B": "Virtual Iron",
    "020054": "Xen", "00163E": "XenSource",
    "0003FF": "Microsoft Virtual PC",
    "001DD8": "Microsoft",
    "0A0027": "VirtualBox (host-only adapter)",
}

CONTAINER_PREFIXES = {
    "0242AC": "Docker (default bridge)",
    "0242AC11": "Docker",
}

EMULATOR_PREFIXES = {
    "080027": "VirtualBox / Genymotion",
    "525400": "QEMU / Android emulator",
}


# ============================================================
# Normalization
# ============================================================
def normalize(raw):
    """Strip non-hex chars, validate length, return 12 uppercase hex."""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", raw).upper()
    if len(cleaned) != 12:
        return None
    return cleaned


def format_variants(clean):
    pairs = [clean[i:i+2] for i in range(0, 12, 2)]
    return {
        "colon":  ":".join(pairs),
        "hyphen": "-".join(pairs),
        "dot":    ".".join([clean[i:i+4] for i in range(0, 12, 4)]),
        "plain":  clean,
        "cisco":  ".".join([clean[i:i+4] for i in range(0, 12, 4)]),
        "lower":  ":".join(p.lower() for p in pairs),
        "bare":   clean,
    }


def oui_of(clean):
    return clean[:6]


def nic_of(clean):
    return clean[6:]


# ============================================================
# Address type analysis
# ============================================================
def first_octet_bits(clean):
    """Return bit breakdown of the first octet."""
    first = int(clean[0:2], 16)
    return {
        "value": first,
        "bits": format(first, "08b"),
        "ig_bit": first & 0b00000001,      # individual/group
        "ul_bit": (first >> 1) & 0b00000001,  # universal/local
    }


def is_multicast(clean):
    first = int(clean[0:2], 16)
    return bool(first & 0b00000001)


def is_broadcast(clean):
    return clean == "FFFFFFFFFFFF"


def is_locally_administered(clean):
    first = int(clean[0:2], 16)
    return bool((first >> 1) & 0b00000001)


def is_universally_administered(clean):
    return not is_locally_administered(clean)


def is_null(clean):
    return clean == "000000000000"


# ============================================================
# Randomization detection
# ============================================================
def detect_randomization(clean):
    """Heuristic for privacy MAC addresses (LAA + weak vendor match)."""
    result = {
        "is_laa": is_locally_administered(clean),
        "is_multicast": is_multicast(clean),
        "is_broadcast": is_broadcast(clean),
        "is_null": is_null(clean),
        "likely_randomized": False,
        "confidence": "none",
        "reasons": [],
    }

    if result["is_null"]:
        result["confidence"] = "certain"
        result["reasons"].append("all-zero MAC")
        return result

    if result["is_broadcast"]:
        result["confidence"] = "certain"
        result["reasons"].append("broadcast MAC")
        return result

    if result["is_multicast"]:
        result["confidence"] = "certain"
        result["reasons"].append("multicast bit set — not a hardware address")
        return result

    if not result["is_laa"]:
        result["confidence"] = "none"
        return result

    # it's LAA — likely a privacy MAC
    result["likely_randomized"] = True
    result["reasons"].append("locally administered bit set (LAA)")

    # check for weak vendor match in local table
    oui = clean[:6]
    if oui in LOCAL_OUI:
        result["reasons"].append(f"OUI {oui} coincidentally matches {LOCAL_OUI[oui][0]}")
        result["confidence"] = "possible"
    else:
        # if the NIC part looks fully random (high entropy), lean likely
        nic = clean[6:]
        unique_nibbles = len(set(nic))
        if unique_nibbles >= 4:
            result["confidence"] = "likely"
            result["reasons"].append(f"high-entropy NIC part ({unique_nibbles} distinct nibbles)")
        else:
            result["confidence"] = "possible"

    return result


# ============================================================
# Virtualisation detection
# ============================================================
def detect_virtualization(clean):
    """Flag known hypervisor, container, and emulator prefixes."""
    oui = clean[:6]
    result = {
        "is_virtual": False,
        "is_container": False,
        "is_emulator": False,
        "platform": None,
        "reasons": [],
    }

    if oui in VIRTUAL_PREFIXES:
        result["is_virtual"] = True
        result["platform"] = VIRTUAL_PREFIXES[oui]
        result["reasons"].append(f"known hypervisor prefix: {result['platform']}")

    if oui in CONTAINER_PREFIXES:
        result["is_container"] = True
        result["platform"] = result["platform"] or CONTAINER_PREFIXES[oui]
        result["reasons"].append(f"container default prefix: {CONTAINER_PREFIXES[oui]}")

    if oui in EMULATOR_PREFIXES:
        result["is_emulator"] = True
        result["reasons"].append(f"emulator prefix: {EMULATOR_PREFIXES[oui]}")

    return result


# ============================================================
# EUI-64 / IPv6 link-local derivation
# ============================================================
def eui64(clean):
    """Derive the EUI-64 form (flip U/L bit, insert FFFE)."""
    first_byte = int(clean[0:2], 16)
    flipped = first_byte ^ 0b00000010
    first = f"{flipped:02X}"
    rest = clean[2:]
    return f"{first}{rest[:4]}FFFE{rest[4:]}"


def ipv6_link_local(clean):
    """Derive the IPv6 link-local address (fe80::/64) from the MAC."""
    e64 = eui64(clean)
    pairs = [e64[i:i+4] for i in range(0, 16, 4)]
    return "fe80::" + ":".join(pairs)


# ============================================================
# OUI lookup — providers
# ============================================================
def _lookup_local(oui):
    """Embedded OUI table lookup."""
    entry = LOCAL_OUI.get(oui)
    if entry:
        return {"vendor": entry[0], "country": entry[1], "source": "local"}
    return None


def _lookup_macadress(oui):
    """macadress.com — keyless vendor lookup."""
    try:
        r = requests.get(
            "https://api.macadress.com/vendor",
            params={"mac": oui},
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict) and data.get("vendor"):
                return {
                    "vendor": data["vendor"],
                    "country": data.get("country"),
                    "source": "macadress.com",
                }
            if isinstance(data, str) and data.strip():
                return {"vendor": data.strip(), "source": "macadress.com"}
    except Exception:
        pass
    return None


def _lookup_macadress_full(oui, api_key):
    """macadress.com — full analysis with API key."""
    if not api_key:
        return None
    try:
        r = requests.get(
            "https://api.macadress.com/lookup",
            params={"mac": oui},
            headers={
                "User-Agent": UA,
                "Accept": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            timeout=10,
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "vendor": d.get("organization"),
                "country": d.get("country"),
                "block_type": d.get("blockType"),
                "matched_prefix": d.get("matchedPrefix"),
                "address": d.get("address"),
                "source": "macadress.com (full)",
                "eui64": d.get("eui64"),
                "ipv6_link_local": d.get("ipv6LinkLocal"),
                "randomization": d.get("randomizationConfidence"),
                "device_guess": d.get("deviceGuess"),
            }
    except Exception:
        pass
    return None


def _lookup_macvendors(oui):
    """macvendors.com — keyless, rate-limited ~1/s."""
    try:
        r = requests.get(
            f"https://api.macvendors.com/{oui}",
            headers={"User-Agent": UA}, timeout=10,
        )
        if r.status_code == 200 and r.text.strip():
            return {
                "vendor": r.text.strip(),
                "source": "macvendors.com",
            }
        if r.status_code == 429:
            return {"vendor": None, "source": "macvendors.com (rate-limited)"}
        if r.status_code == 404:
            return {"vendor": None, "source": "macvendors.com (not found)"}
    except Exception:
        pass
    return None


def _lookup_http2mac(oui):
    """http2mac — local Docker gateway. Silent failure if not running."""
    try:
        r = requests.post(
            "http://localhost:8080/api/v1/mac",
            json={"mac": oui},
            headers={"User-Agent": UA, "Content-Type": "application/json"},
            timeout=5,
        )
        if r.status_code == 200:
            d = r.json()
            answers = d.get("answers") or [{}]
            a = answers[0]
            return {
                "vendor": a.get("organisation_name"),
                "country": a.get("country_code"),
                "block_type": a.get("assignment"),
                "address_range": f"{a.get('address_min', '')} - {a.get('address_max', '')}",
                "block_size": a.get("block_size"),
                "virtual": a.get("virtual"),
                "source": "http2mac",
            }
    except Exception:
        pass
    return None


def _lookup_macaddress_io(oui, api_key):
    """macaddress.io — requires API key."""
    if not api_key:
        return None
    try:
        r = requests.get(
            "https://api.macaddress.io/v1",
            params={"output": "json", "search": oui, "apiKey": api_key},
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code == 200:
            d = r.json()
            vendor = d.get("vendorDetails") or {}
            block = d.get("blockDetails") or {}
            return {
                "vendor": vendor.get("companyName"),
                "address": vendor.get("companyAddress"),
                "country": vendor.get("countryCode"),
                "block_found": block.get("blockFound"),
                "border_left": block.get("borderLeft"),
                "border_right": block.get("borderRight"),
                "block_size": block.get("blockSize"),
                "assignment": block.get("assignmentBlockSize"),
                "date_created": block.get("dateCreated"),
                "date_updated": block.get("dateUpdated"),
                "source": "macaddress.io",
            }
    except Exception:
        pass
    return None


def vendor_lookup(oui, cfg=None):
    """Try all providers in order. First hit wins. Fall back to local."""
    cfg = cfg or {}
    macadress_key = cfg.get("macadress_api_key")
    macaddress_io_key = cfg.get("macaddress_io_api_key")

    # 1. macadress.com full (best data)
    if macadress_key:
        r = _lookup_macadress_full(oui, macadress_key)
        if r and r.get("vendor"):
            return r

    # 2. macadress.com keyless
    r = _lookup_macadress(oui)
    if r and r.get("vendor"):
        return r

    # 3. macvendors.com keyless
    r = _lookup_macvendors(oui)
    if r and r.get("vendor"):
        return r

    # 4. http2mac (local)
    r = _lookup_http2mac(oui)
    if r and r.get("vendor"):
        return r

    # 5. macaddress.io (key)
    if macaddress_io_key:
        r = _lookup_macaddress_io(oui, macaddress_io_key)
        if r and r.get("vendor"):
            return r

    # 6. local embedded table
    r = _lookup_local(oui)
    if r:
        return r

    return {"vendor": None, "source": "none"}


def vendor_lookup_multi(oui, cfg=None):
    """Query ALL providers in parallel and merge results."""
    cfg = cfg or {}
    macadress_key = cfg.get("macadress_api_key")
    macaddress_io_key = cfg.get("macaddress_io_api_key")

    tasks = [
        ("macadress.com", lambda: _lookup_macadress(oui)),
        ("macvendors.com", lambda: _lookup_macvendors(oui)),
        ("http2mac", lambda: _lookup_http2mac(oui)),
        ("local", lambda: _lookup_local(oui)),
    ]
    if macadress_key:
        tasks.append(
            ("macadress.com/full",
             lambda: _lookup_macadress_full(oui, macadress_key))
        )
    if macaddress_io_key:
        tasks.append(
            ("macaddress.io",
             lambda: _lookup_macaddress_io(oui, macaddress_io_key))
        )

    results = {}
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(fn): name for name, fn in tasks}
        for f in as_completed(futs):
            name = futs[f]
            try:
                r = f.result()
                if r:
                    results[name] = r
            except Exception:
                pass
    return results


# ============================================================
# OUI database download (IEEE CSV)
# ============================================================
IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def download_oui_db(timeout=60):
    """Download and cache the IEEE OUI CSV."""
    try:
        r = requests.get(IEEE_OUI_URL, headers={"User-Agent": UA},
                         timeout=timeout)
        if r.status_code != 200:
            return None
        entries = {}
        reader = csv.reader(io.StringIO(r.text))
        next(reader, None)  # skip header
        for row in reader:
            if len(row) < 3:
                continue
            prefix = re.sub(r"[^0-9A-Fa-f]", "", row[1]).upper()
            if len(prefix) >= 6:
                entries[prefix[:6]] = {
                    "vendor": row[2],
                    "registry": row[0] if len(row) > 0 else "",
                    "address": row[3] if len(row) > 3 else "",
                }
        OUI_CACHE.write_text(
            json.dumps(entries, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return len(entries)
    except Exception:
        return None


def load_oui_cache():
    """Load cached IEEE OUI data if present."""
    if not OUI_CACHE.exists():
        return None
    try:
        return json.loads(OUI_CACHE.read_text(encoding="utf-8"))
    except Exception:
        return None


def lookup_oui_cache(oui, cache):
    """Look up OUI in the cached IEEE data."""
    if not cache:
        return None
    entry = cache.get(oui)
    if entry:
        return {
            "vendor": entry.get("vendor"),
            "registry": entry.get("registry"),
            "address": entry.get("address"),
            "source": "IEEE CSV (cached)",
        }
    return None


# ============================================================
# History
# ============================================================
def _history_path(oui):
    return HIST_DIR / f"{oui}.json"


def _load_history(oui):
    p = _history_path(oui)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _save_history(oui, snapshot):
    p = _history_path(oui)
    try:
        p.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False,
                                default=str), encoding="utf-8")
    except Exception:
        pass


def _diff_history(prev, curr):
    if not prev:
        return []
    diffs = []
    if prev.get("vendor") != curr.get("vendor"):
        diffs.append(f"vendor: {prev.get('vendor')} → {curr.get('vendor')}")
    if prev.get("country") != curr.get("country"):
        diffs.append(f"country: {prev.get('country')} → {curr.get('country')}")
    if prev.get("block_type") != curr.get("block_type"):
        diffs.append(f"block type: {prev.get('block_type')} → {curr.get('block_type')}")
    return diffs


# ============================================================
# Render
# ============================================================
def _render(raw, clean, variants, vendor_info, addr_type, randomization,
            virtualization, bits, eui64_str, ipv6_str, multi_results,
            history_diffs):
    console.print(Panel.fit(
        f"[bg]MAC LOOKUP[/bg]  [dg]{variants['colon']}[/dg]",
        border_style="bd", padding=(0, 2),
    ))

    # formats
    ft = Table(border_style="bd", title="[bg]formats[/bg]",
               show_header=False, padding=(0, 2))
    ft.add_column("k", style="dg", no_wrap=True)
    ft.add_column("v", style="g")
    for k in ("colon", "hyphen", "dot", "cisco", "plain", "lower"):
        v = variants.get(k)
        if v:
            ft.add_row(k, v)
    console.print(ft)

    # vendor
    vt = Table(border_style="bd", title="[bg]vendor[/bg]",
               show_header=False, padding=(0, 2))
    vt.add_column("k", style="dg", no_wrap=True)
    vt.add_column("v", style="g", overflow="fold")
    vt.add_row("oui", oui_of(clean))
    vt.add_row("nic", nic_of(clean))
    vt.add_row("vendor", vendor_info.get("vendor") or "—")
    if vendor_info.get("country"):
        vt.add_row("country", vendor_info["country"])
    if vendor_info.get("block_type"):
        vt.add_row("block type", vendor_info["block_type"])
    if vendor_info.get("matched_prefix"):
        vt.add_row("matched prefix", vendor_info["matched_prefix"])
    if vendor_info.get("address"):
        vt.add_row("address", str(vendor_info["address"])[:120])
    if vendor_info.get("address_range"):
        vt.add_row("address range", vendor_info["address_range"])
    if vendor_info.get("block_size"):
        vt.add_row("block size", str(vendor_info["block_size"]))
    if vendor_info.get("date_created"):
        vt.add_row("date created", str(vendor_info["date_created"])[:10])
    if vendor_info.get("date_updated"):
        vt.add_row("date updated", str(vendor_info["date_updated"])[:10])
    vt.add_row("source", vendor_info.get("source") or "—")
    console.print(vt)

    # address type
    at = Table(border_style="bd", title="[bg]address type[/bg]",
               show_header=False, padding=(0, 2))
    at.add_column("k", style="dg", no_wrap=True)
    at.add_column("v", style="g")
    at.add_row("first octet", f"{bits['value']:02X}  ({bits['bits']})")
    at.add_row("I/G bit", f"{bits['ig_bit']}  "
               f"({'multicast' if bits['ig_bit'] else 'unicast'})")
    at.add_row("U/L bit", f"{bits['ul_bit']}  "
               f"({'locally administered' if bits['ul_bit'] else 'universally administered'})")
    at.add_row("multicast", "yes" if addr_type["is_multicast"] else "no")
    at.add_row("broadcast", "yes" if addr_type["is_broadcast"] else "no")
    at.add_row("null", "yes" if addr_type["is_null"] else "no")
    console.print(at)

    # randomization
    rt = Table(border_style="bd",
               title=f"[bg]randomization[/bg]  "
                     f"[{'red' if randomization['likely_randomized'] else 'green'}]"
                     f"{randomization['confidence']}[/]",
               show_header=False, padding=(0, 2))
    rt.add_column("k", style="dg", no_wrap=True)
    rt.add_column("v", style="g")
    rt.add_row("likely randomized",
               "yes" if randomization["likely_randomized"] else "no")
    rt.add_row("confidence", randomization["confidence"])
    for r in randomization["reasons"]:
        rt.add_row("", r)
    console.print(rt)

    # virtualization
    if virtualization["is_virtual"] or virtualization["is_container"] \
            or virtualization["is_emulator"]:
        vt2 = Table(border_style="bd",
                    title="[bg]virtualization[/bg]",
                    show_header=False, padding=(0, 2))
        vt2.add_column("k", style="dg", no_wrap=True)
        vt2.add_column("v", style="g")
        vt2.add_row("virtual machine",
                    "yes" if virtualization["is_virtual"] else "no")
        vt2.add_row("container",
                    "yes" if virtualization["is_container"] else "no")
        vt2.add_row("emulator",
                    "yes" if virtualization["is_emulator"] else "no")
        if virtualization["platform"]:
            vt2.add_row("platform", virtualization["platform"])
        for r in virtualization["reasons"]:
            vt2.add_row("", r)
        console.print(vt2)

    # derived
    dt = Table(border_style="bd", title="[bg]derived[/bg]",
               show_header=False, padding=(0, 2))
    dt.add_column("k", style="dg", no_wrap=True)
    dt.add_column("v", style="g")
    dt.add_row("eui-64", eui64_str)
    dt.add_row("ipv6 link-local", ipv6_str)
    console.print(dt)

    # multi-provider results
    if multi_results and len(multi_results) > 1:
        mt = Table(border_style="bd",
                   title=f"[bg]all providers ({len(multi_results)})[/bg]",
                   show_header=True, padding=(0, 2))
        mt.add_column("provider", style="bg")
        mt.add_column("vendor", style="g", overflow="fold")
        mt.add_column("country", style="dg")
        mt.add_column("block", style="dg")
        for name, data in sorted(multi_results.items()):
            mt.add_row(
                name,
                (data.get("vendor") or "—")[:40],
                data.get("country") or "—",
                data.get("block_type") or "—",
            )
        console.print(mt)

    # history diff
    if history_diffs:
        console.print(Panel.fit(
            "[bg]changes since last lookup[/bg]",
            border_style="bd", padding=(0, 2),
        ))
        for d in history_diffs:
            console.print(f"[yellow]  · {d}[/yellow]")
        console.print()

    console.print()


# ============================================================
# Export
# ============================================================
def _export_json(raw, clean, variants, vendor_info, addr_type,
                 randomization, virtualization, bits, eui64_str,
                 ipv6_str, multi_results):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    p = OUT_DIR / f"mac_{clean}_{ts}.json"
    p.write_text(json.dumps({
        "input": raw,
        "normalized": clean,
        "formats": variants,
        "oui": oui_of(clean),
        "nic": nic_of(clean),
        "vendor": vendor_info,
        "address_type": addr_type,
        "bits": bits,
        "randomization": randomization,
        "virtualization": virtualization,
        "eui64": eui64_str,
        "ipv6_link_local": ipv6_str,
        "all_providers": multi_results,
        "generated": datetime.now().isoformat(timespec="seconds"),
    }, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]")
    return p


def _export_csv(raw, clean, variants, vendor_info, addr_type,
                randomization, virtualization):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    p = OUT_DIR / f"mac_{clean}_{ts}.csv"
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["section", "key", "value"])
        w.writerow(["meta", "input", raw])
        w.writerow(["meta", "normalized", clean])
        for k, v in variants.items():
            w.writerow(["format", k, v])
        w.writerow(["vendor", "oui", oui_of(clean)])
        w.writerow(["vendor", "nic", nic_of(clean)])
        for k, v in vendor_info.items():
            w.writerow(["vendor", k, str(v)])
        for k, v in addr_type.items():
            w.writerow(["addr_type", k, str(v)])
        for k, v in randomization.items():
            if not isinstance(v, list):
                w.writerow(["randomization", k, str(v)])
        for k, v in virtualization.items():
            if not isinstance(v, list):
                w.writerow(["virtualization", k, str(v)])
    console.print(f"[dg]  exported → {p}[/dg]")


def _export_html(raw, clean, variants, vendor_info, addr_type,
                 randomization, virtualization, bits, eui64_str,
                 ipv6_str, multi_results):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    p = OUT_DIR / f"mac_{clean}_{ts}.html"

    def esc(x):
        return html.escape(str(x))

    def rows(seq):
        return "".join(
            f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in seq
        )

    variant_rows = rows(variants.items())
    vendor_rows = rows(
        (k, str(v)) for k, v in vendor_info.items() if v
    )
    addr_rows = rows(
        (k, str(v)) for k, v in addr_type.items()
    )
    rand_rows = rows(
        (k, str(v)) for k, v in randomization.items()
        if not isinstance(v, list)
    )
    virt_rows = rows(
        (k, str(v)) for k, v in virtualization.items()
        if not isinstance(v, list)
    )

    doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>MAC Report — {esc(clean)}</title>
<style>
body {{ background:#111; color:#ddd; font-family:monospace; padding:2em; }}
h1,h2 {{ color:#9fd4ff; }}
table {{ border-collapse:collapse; margin:1em 0; }}
td,th {{ border:1px solid #333; padding:4px 10px; }}
</style></head><body>
<h1>MAC Address Report — {esc(variants.get('colon', clean))}</h1>
<p>Generated {esc(datetime.now().isoformat(timespec="seconds"))}</p>
<h2>Formats</h2><table>{variant_rows}</table>
<h2>Vendor</h2><table>{vendor_rows}</table>
<h2>Address Type</h2><table>{addr_rows}</table>
<h2>Randomization</h2><table>{rand_rows}</table>
<h2>Virtualization</h2><table>{virt_rows}</table>
<h2>Derived</h2>
<table>
<tr><td>EUI-64</td><td>{esc(eui64_str)}</td></tr>
<tr><td>IPv6 link-local</td><td>{esc(ipv6_str)}</td></tr>
</table>
</body></html>
"""
    p.write_text(doc, encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]")


# ============================================================
# Core processing
# ============================================================
def _process_one(raw, cfg=None, deep=False):
    """Run full analysis on a single MAC address."""
    cfg = cfg or {}
    clean = normalize(raw)
    if not clean:
        return None

    oui = oui_of(clean)
    variants = format_variants(clean)
    bits = first_octet_bits(clean)

    addr_type = {
        "is_multicast": is_multicast(clean),
        "is_broadcast": is_broadcast(clean),
        "is_null": is_null(clean),
        "is_locally_administered": is_locally_administered(clean),
        "is_universally_administered": is_universally_administered(clean),
    }

    randomization = detect_randomization(clean)
    virtualization = detect_virtualization(clean)
    eui64_str = eui64(clean)
    ipv6_str = ipv6_link_local(clean)

    # vendor lookup
    if deep:
        multi_results = vendor_lookup_multi(oui, cfg)
        # pick the best
        vendor_info = {}
        for priority in ("macadress.com/full", "macadress.com",
                         "macvendors.com", "macaddress.io",
                         "http2mac", "local"):
            if priority in multi_results:
                vendor_info = multi_results[priority]
                break
    else:
        vendor_info = vendor_lookup(oui, cfg)
        multi_results = {}

    # history
    snapshot = {
        "oui": oui,
        "vendor": vendor_info.get("vendor"),
        "country": vendor_info.get("country"),
        "block_type": vendor_info.get("block_type"),
        "source": vendor_info.get("source"),
        "generated": datetime.now().isoformat(timespec="seconds"),
    }
    prev = _load_history(oui)
    history_diffs = _diff_history(prev, snapshot)
    _save_history(oui, snapshot)

    return {
        "raw": raw,
        "clean": clean,
        "oui": oui,
        "nic": nic_of(clean),
        "variants": variants,
        "bits": bits,
        "addr_type": addr_type,
        "randomization": randomization,
        "virtualization": virtualization,
        "eui64": eui64_str,
        "ipv6": ipv6_str,
        "vendor": vendor_info,
        "multi_results": multi_results,
        "history_diffs": history_diffs,
    }


# ============================================================
# Runner
# ============================================================
def run():
    cfg = _load_config()

    while True:
        console.print(Panel.fit(
            "[bg]MAC LOOKUP[/bg]\n"
            "[dg]vendor & hardware intelligence[/dg]",
            border_style="bd", padding=(0, 2),
        ))
        print("  1) single MAC lookup")
        print("  2) batch MAC lookup (comma-separated)")
        print("  3) deep mode (query all providers)")
        print("  4) download IEEE OUI database")
        print("  5) lookup from cached IEEE database")
        print("  0) exit")
        print()

        choice = input("  mac >> ").strip().lower()

        if choice in ("0", "q", "exit", "quit"):
            return

        elif choice == "1":
            raw = input("  mac address >> ").strip()
            if not raw:
                console.print("[dg]  empty input[/dg]")
                continue

            with tqdm(total=2, desc="resolving", ncols=60,
                      bar_format=BAR_FMT) as bar:
                payload = _process_one(raw, cfg, deep=False)
                bar.update(2)

            if not payload:
                console.print("[red]  [!] invalid mac (need 12 hex digits)[/red]")
                continue

            _render(
                payload["raw"], payload["clean"], payload["variants"],
                payload["vendor"], payload["addr_type"],
                payload["randomization"], payload["virtualization"],
                payload["bits"], payload["eui64"], payload["ipv6"],
                payload["multi_results"], payload["history_diffs"],
            )

            if input("  export json? [y/N] >> ").strip().lower() == "y":
                _export_json(
                    payload["raw"], payload["clean"], payload["variants"],
                    payload["vendor"], payload["addr_type"],
                    payload["randomization"], payload["virtualization"],
                    payload["bits"], payload["eui64"], payload["ipv6"],
                    payload["multi_results"],
                )
            if input("  export csv? [y/N] >> ").strip().lower() == "y":
                _export_csv(
                    payload["raw"], payload["clean"], payload["variants"],
                    payload["vendor"], payload["addr_type"],
                    payload["randomization"], payload["virtualization"],
                )
            if input("  export html? [y/N] >> ").strip().lower() == "y":
                _export_html(
                    payload["raw"], payload["clean"], payload["variants"],
                    payload["vendor"], payload["addr_type"],
                    payload["randomization"], payload["virtualization"],
                    payload["bits"], payload["eui64"], payload["ipv6"],
                    payload["multi_results"],
                )

        elif choice == "2":
            raw = input("  mac addresses (comma-separated) >> ").strip()
            if not raw:
                continue
            macs = [m.strip() for m in raw.split(",") if m.strip()]
            for m in macs:
                payload = _process_one(m, cfg, deep=False)
                if not payload:
                    console.print(f"[red]  [!] invalid: {m}[/red]")
                    continue
                console.print(f"\n[bg]  ▶ {payload['variants']['colon']}[/bg]")
                _render(
                    payload["raw"], payload["clean"], payload["variants"],
                    payload["vendor"], payload["addr_type"],
                    payload["randomization"], payload["virtualization"],
                    payload["bits"], payload["eui64"], payload["ipv6"],
                    payload["multi_results"], payload["history_diffs"],
                )

        elif choice == "3":
            raw = input("  mac address (deep scan) >> ").strip()
            if not raw:
                continue
            with tqdm(total=3, desc="deep scan", ncols=60,
                      bar_format=BAR_FMT) as bar:
                payload = _process_one(raw, cfg, deep=True)
                bar.update(3)
            if not payload:
                console.print("[red]  [!] invalid mac[/red]")
                continue
            _render(
                payload["raw"], payload["clean"], payload["variants"],
                payload["vendor"], payload["addr_type"],
                payload["randomization"], payload["virtualization"],
                payload["bits"], payload["eui64"], payload["ipv6"],
                payload["multi_results"], payload["history_diffs"],
            )

        elif choice == "4":
            with console.status("[dg]downloading IEEE OUI database...[/dg]",
                                spinner="dots"):
                n = download_oui_db()
            if n:
                console.print(f"[green]  ✓ cached {n:,} OUI entries[/green]\n")
            else:
                console.print("[red]  [!] download failed[/red]\n")

        elif choice == "5":
            cache = load_oui_cache()
            if not cache:
                console.print("[yellow]  no cached database — "
                              "run option 4 first[/yellow]\n")
                continue
            raw = input("  mac address >> ").strip()
            clean = normalize(raw)
            if not clean:
                console.print("[red]  [!] invalid mac[/red]")
                continue
            r = lookup_oui_cache(oui_of(clean), cache)
            if r:
                console.print(Panel.fit(
                    f"[bg]IEEE CSV LOOKUP[/bg]  [dg]{format_variants(clean)['colon']}[/dg]\n"
                    f"[g]vendor:[/g] {r.get('vendor')}\n"
                    f"[g]registry:[/g] {r.get('registry')}\n"
                    f"[g]address:[/g] {r.get('address')}",
                    border_style="bd", padding=(0, 2),
                ))
            else:
                console.print("[dg]  OUI not found in cached database[/dg]\n")
