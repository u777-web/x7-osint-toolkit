"""
phone_lookup.py — Phone number intelligence.

Given a phone number (any format), this module:
  · normalizes to E.164 and multiple display formats
  · resolves country, region, carrier, line type
  · pulls timezone(s) for the number's region
  · builds pivot links (WhatsApp, Truecaller, TruePeople, NumLookup)
  · generates reverse-search dorks
  · exports json
"""

import json
import re
import time
from datetime import datetime
from pathlib import Path

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme
from tqdm import tqdm

try:
    import phonenumbers
    from phonenumbers import (
        geocoder, carrier, timezone as pn_timezone, number_type,
        PhoneNumberType, NumberParseException,
    )
    HAS_PN = True
except ImportError:
    HAS_PN = False

console = Console(theme=Theme({
    "g": "grey70", "dg": "grey50", "bg": "grey93", "bd": "grey37",
}))

BAR_FMT = "\033[38;5;245m  {desc} |{bar}| {percentage:3.0f}%\033[0m"
OUT_DIR = Path.home() / ".osinttoolkit" / "exports"
OUT_DIR.mkdir(parents=True, exist_ok=True)

UA = "Mozilla/5.0 (compatible; doxtoolkit/2.0)"

TYPE_MAP = {}
if HAS_PN:
    TYPE_MAP = {
        PhoneNumberType.MOBILE: "mobile",
        PhoneNumberType.FIXED_LINE: "fixed line",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed or mobile",
        PhoneNumberType.TOLL_FREE: "toll free",
        PhoneNumberType.PREMIUM_RATE: "premium rate",
        PhoneNumberType.SHARED_COST: "shared cost",
        PhoneNumberType.VOIP: "voip",
        PhoneNumberType.PERSONAL_NUMBER: "personal",
        PhoneNumberType.PAGER: "pager",
        PhoneNumberType.UAN: "uan",
        PhoneNumberType.VOICEMAIL: "voicemail",
        PhoneNumberType.UNKNOWN: "unknown",
    }


def _digits(raw):
    return "".join(ch for ch in raw if ch.isdigit())


def _parse(raw, default_region="PL"):
    if not HAS_PN:
        return None, "phonenumbers library not installed"
    try:
        n = phonenumbers.parse(raw, None if raw.startswith("+") else default_region)
        if not phonenumbers.is_valid_number(n):
            return None, "not a valid number"
        return n, None
    except NumberParseException as e:
        return None, str(e)


def _formats(n):
    return {
        "e164": phonenumbers.format_number(
            n, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(
            n, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(
            n, phonenumbers.PhoneNumberFormat.NATIONAL),
        "rfc3966": phonenumbers.format_number(
            n, phonenumbers.PhoneNumberFormat.RFC3966),
    }


def _meta(n):
    region = phonenumbers.region_code_for_number(n)
    geo = geocoder.description_for_number(n, "en") or "—"
    car = carrier.name_for_number(n, "en") or "—"
    tzs = list(pn_timezone.time_zones_for_number(n))
    ntype = TYPE_MAP.get(number_type(n), "unknown")
    return {
        "region": region,
        "geocoded": geo,
        "carrier": car,
        "timezones": tzs,
        "line_type": ntype,
        "country_code": n.country_code,
        "national": n.national_number,
    }


# ───────────────────────── pivots ─────────────────────────

def _pivots(e164_digits):
    return [
        ("WhatsApp",   f"https://wa.me/{e164_digits}"),
        ("Truecaller", f"https://www.truecaller.com/search/global/{e164_digits}"),
        ("TruePeople", f"https://www.truepeoplesearch.com/results?phoneno={e164_digits}"),
        ("NumLookup",  f"https://www.numlookup.com/?number={e164_digits}"),
        ("Sync.me",    f"https://sync.me/search/?number={e164_digits}"),
        ("SpyDialer",  f"https://www.spydialer.com/default.aspx?phone={e164_digits}"),
        ("FastPeople", f"https://www.fastpeoplesearch.com/{e164_digits}"),
        ("ThatsThem",  f"https://thatsthem.com/phone/{e164_digits}"),
    ]


def _dorks(raw_digits, e164):
    return [
        f'"{raw_digits}"',
        f'"{raw_digits}" site:facebook.com',
        f'"{raw_digits}" site:linkedin.com',
        f'"{raw_digits}" site:twitter.com OR site:x.com',
        f'"{raw_digits}" filetype:pdf',
        f'"{raw_digits}" "@gmail.com"',
        f'"{e164}"',
        f'"{e164}" intext:contact',
    ]


# ───────────────────────── online ─────────────────────────

def _numverify(e164_digits):
    """free-tier public mirror — no key required for basic"""
    try:
        r = requests.get(
            f"https://api.apilayer.com/number_verification/validate"
            f"?number={e164_digits}",
            headers={"User-Agent": UA}, timeout=8,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


# ───────────────────────── render ─────────────────────────

def _render(raw, fmt, meta, pivots):
    console.print(Panel.fit(
        f"[bg]PHONE LOOKUP[/bg]  [dg]{fmt.get('e164', raw)}[/dg]",
        border_style="bd", padding=(0, 2),
    ))

    ft = Table(border_style="bd", title="[bg]formats[/bg]",
               show_header=False, padding=(0, 2))
    ft.add_column("k", style="dg", no_wrap=True)
    ft.add_column("v", style="g")
    for k in ("e164", "international", "national", "rfc3966"):
        if fmt.get(k):
            ft.add_row(k, fmt[k])
    console.print(ft)

    mt = Table(border_style="bd", title="[bg]metadata[/bg]",
               show_header=False, padding=(0, 2))
    mt.add_column("k", style="dg", no_wrap=True)
    mt.add_column("v", style="g")
    mt.add_row("region", meta.get("region") or "—")
    mt.add_row("geocoded", meta.get("geocoded") or "—")
    mt.add_row("carrier", meta.get("carrier") or "—")
    mt.add_row("line type", meta.get("line_type") or "—")
    mt.add_row("timezones", ", ".join(meta.get("timezones") or []) or "—")
    mt.add_row("country code", str(meta.get("country_code") or "—"))
    mt.add_row("national", str(meta.get("national") or "—"))
    console.print(mt)

    pt = Table(border_style="bd", title="[bg]pivot links[/bg]",
               show_header=True, padding=(0, 2))
    pt.add_column("service", style="bg")
    pt.add_column("url", style="g", overflow="fold")
    for svc, url in pivots:
        pt.add_row(svc, url)
    console.print(pt)

    dt = Table(border_style="bd", title="[bg]dorks[/bg]",
               show_header=False, padding=(0, 2))
    dt.add_column("q", style="g", overflow="fold")
    for d in _dorks(_digits(raw), fmt.get("e164", "")):
        dt.add_row(d)
    console.print(dt)

    console.print()


def _export(raw, fmt, meta, pivots):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = _digits(raw)[:20]
    p = OUT_DIR / f"phone_{safe}_{ts}.json"
    p.write_text(json.dumps({
        "raw": raw,
        "formats": fmt,
        "meta": meta,
        "pivots": [{"service": s, "url": u} for s, u in pivots],
        "dorks": _dorks(_digits(raw), fmt.get("e164", "")),
        "generated": datetime.now().isoformat(timespec="seconds"),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]\n")


# ───────────────────────── entry ─────────────────────────

def run():
    raw = input("  phone (any format, e.g. +48...) >> ").strip()
    if not raw:
        print("  [!] empty input")
        return

    if not HAS_PN:
        print("  [!] install phonenumbers: pip install phonenumbers")
        return

    with tqdm(total=4, desc="parsing", ncols=60, bar_format=BAR_FMT) as bar:
        n, err = _parse(raw); bar.update(1)
        if err:
            print(f"  [!] {err}")
            return
        fmt = _formats(n); bar.update(1)
        meta = _meta(n); bar.update(1)
        pivots = _pivots(fmt["e164"].lstrip("+"))
        bar.update(1)

    _render(raw, fmt, meta, pivots)

    if input("  export? [y/N] >> ").strip().lower() == "y":
        _export(raw, fmt, meta, pivots)
