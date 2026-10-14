"""
mac_lookup.py — MAC address vendor & hardware intelligence.

Validates and normalizes MAC addresses, resolves OUI via macvendors.com,
falls back to an embedded vendor table for the most common OUIs, and
flags locally-administered / multicast addresses.
"""

import json
import re
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

# tiny embedded fallback — most common OUIs seen in the wild
LOCAL_OUI = {
    "000C29": "VMware", "005056": "VMware", "000569": "VMware",
    "080027": "Oracle VirtualBox", "0A0027": "Oracle VirtualBox",
    "525400": "QEMU/KVM", "52540": "QEMU/KVM",
    "00155D": "Microsoft (Hyper-V)",
    "001C42": "Parallels",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Trading",
    "E45F01": "Raspberry Pi Trading",
    "288023": "Apple", "3C0754": "Apple", "F0766F": "Apple",
    "A45E60": "Apple", "9C207B": "Apple",
    "F4F5D8": "Samsung", "8425DB": "Samsung", "E8E5D6": "Samsung",
    "3C5A37": "Samsung",
    "3C46D8": "TP-Link", "50C7BF": "TP-Link", "A42BB0": "TP-Link",
    "0C8063": "TP-Link",
    "001A2B": "Ayecom", "001B11": "D-Link", "1CBDB9": "D-Link",
    "F07D68": "D-Link",
    "001349": "ZyXEL", "5CE28C": "ZyXEL",
    "001E58": "D-Link", "5C63BF": "TP-Link",
    "F8D111": "TP-Link", "8CFDF0": "Qualcomm",
    "E8DE27": "TP-Link", "18A6F7": "TP-Link",
    "A0F3C1": "TP-Link", "C46E1F": "TP-Link",
    "20E52A": "NETGEAR", "9CD36D": "NETGEAR", "A040A0": "NETGEAR",
    "E091F5": "NETGEAR",
    "0C9D92": "ASUSTek", "2C56DC": "ASUSTek", "AC9E17": "ASUSTek",
    "708BCD": "ASUSTek",
    "B0BE76": "TP-Link", "001BFC": "ASUSTek",
    "3C7C3F": "ASUSTek", "1C872C": "ASUSTek",
    "E0CB4E": "ASUSTek", "F832E4": "ASUSTek",
    "B0958E": "TP-Link", "5C0214": "TP-Link",
    "D8D385": "Hewlett Packard",
    "001708": "Hewlett Packard",
    "F0DEF1": "Wistron",
    "D4BED9": "Dell", "00188B": "Dell", "F8BC12": "Dell",
    "B083FE": "Dell", "F48E38": "Dell", "5CF9DD": "Dell",
    "001E4F": "Dell",
    "00E04C": "Realtek", "52540A": "QEMU",
    "1866DA": "Dell", "D067E5": "Dell",
    "9C5CF9": "Sony", "FCFBFB": "Cisco", "00000C": "Cisco",
    "000142": "Cisco", "001BD4": "Cisco",
    "0024D7": "Intel", "0021CC": "Intel",
    "3C9509": "Intel", "4C3488": "Intel", "A0A8CD": "Intel",
    "001B21": "Intel", "0026C7": "Intel", "3CA9F4": "Intel",
    "E4A471": "Intel", "7CB27D": "Intel",
    "38BAF8": "Intel", "9CB6D0": "Intel",
    "A0A8CD": "Intel", "B4AE2B": "Intel",
    "000D3A": "Microsoft", "7C1E52": "Microsoft",
    "C83F26": "Microsoft", "281878": "Microsoft",
    "F01DBC": "Microsoft", "0017FA": "Microsoft",
    "DCB4C4": "Amazon", "44650D": "Amazon", "F0272D": "Amazon",
    "6854FD": "Amazon", "A002DC": "Amazon", "747548": "Amazon",
    "84D6D0": "Amazon", "FC65DE": "Amazon", "38F73D": "Amazon",
    "0C47C9": "Amazon", "6C5697": "Amazon", "B47C9C": "Amazon",
    "44D9E7": "Google", "F4F5E8": "Google", "3C5AB4": "Google",
    "9C4E36": "Google", "A47733": "Google", "1CDF0F": "Google",
    "DA1664": "Google", "E4F042": "Google", "F88FCA": "Google",
    "C4AD34": "Google",
    "D850E6": "Xiaomi", "64B473": "Xiaomi", "F8A45F": "Xiaomi",
    "78 11 DC".replace(" ", "").lower().upper(): "Xiaomi",
    "AC C1 EE".replace(" ", "").lower().upper(): "Xiaomi",
    "F0B429": "Xiaomi", "50EC50": "Xiaomi",
    "7CB59B": "OnePlus", "C0EEFB": "OnePlus",
    "94652D": "OnePlus", "AC64DD": "OnePlus",
    "E41C4B": "OnePlus",
    "1C1B0D": "Huawei", "E0247F": "Huawei", "D07AB5": "Huawei",
    "C8D15E": "Huawei", "00E0FC": "Huawei",
    "28 6C 07".replace(" ", "").lower().upper(): "Xiaomi",
    "F8E61A": "Huawei",
}


def normalize(raw):
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
    }


def oui_of(clean):
    return clean[:6]


def is_locally_administered(clean):
    first = int(clean[0:2], 16)
    return bool(first & 0b00000010)


def is_multicast(clean):
    first = int(clean[0:2], 16)
    return bool(first & 0b00000001)


def vendor_lookup(oui):
    local = LOCAL_OUI.get(oui)
    try:
        r = requests.get(
            f"https://api.macvendors.com/{oui}",
            headers={"User-Agent": UA}, timeout=10,
        )
        if r.status_code == 200 and r.text.strip():
            return r.text.strip(), "macvendors.com"
        if r.status_code == 429:
            return local, "local (api rate-limited)"
        if r.status_code == 404:
            return local, "local (api 404)"
    except Exception:
        pass
    return local, "local"


def _render(raw, clean, variants, vendor, source):
    console.print(Panel.fit(
        f"[bg]MAC LOOKUP[/bg]  [dg]{variants['colon']}[/dg]",
        border_style="bd", padding=(0, 2),
    ))

    ft = Table(border_style="bd", title="[bg]formats[/bg]",
               show_header=False, padding=(0, 2))
    ft.add_column("k", style="dg", no_wrap=True)
    ft.add_column("v", style="g")
    for k, v in variants.items():
        ft.add_row(k, v)
    console.print(ft)

    vt = Table(border_style="bd", title="[bg]vendor[/bg]",
               show_header=False, padding=(0, 2))
    vt.add_column("k", style="dg", no_wrap=True)
    vt.add_column("v", style="g", overflow="fold")
    vt.add_row("oui", oui_of(clean))
    vt.add_row("vendor", vendor or "—")
    vt.add_row("source", source)
    vt.add_row("locally administered",
               "yes" if is_locally_administered(clean) else "no")
    vt.add_row("multicast",
               "yes" if is_multicast(clean) else "no")
    console.print(vt)

    console.print()


def _export(raw, clean, variants, vendor, source):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    p = OUT_DIR / f"mac_{clean}_{ts}.json"
    p.write_text(json.dumps({
        "input": raw, "normalized": clean, "formats": variants,
        "oui": oui_of(clean), "vendor": vendor, "source": source,
        "locally_administered": is_locally_administered(clean),
        "multicast": is_multicast(clean),
        "generated": datetime.now().isoformat(timespec="seconds"),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]\n")


def run():
    raw = input("  mac address >> ").strip()
    if not raw:
        print("  [!] empty input")
        return

    clean = normalize(raw)
    if not clean:
        print("  [!] invalid mac (need 12 hex digits)")
        return

    variants = format_variants(clean)
    oui = oui_of(clean)

    with tqdm(total=2, desc="resolving", ncols=60, bar_format=BAR_FMT) as bar:
        vendor, source = vendor_lookup(oui); bar.update(2)

    _render(raw, clean, variants, vendor, source)

    if input("  export? [y/N] >> ").strip().lower() == "y":
        _export(raw, clean, variants, vendor, source)