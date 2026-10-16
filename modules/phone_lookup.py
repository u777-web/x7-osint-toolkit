"""
phone_lookup.py — Phone number intelligence (deep edition).

Given a phone number (any format), this module:
  · normalizes to E.164 and multiple display formats
  · resolves country, region, carrier, line type, timezone
  · checks for OVH Telecom VoIP ownership (free API, no key)
  · pulls FTC Do Not Call / robocall complaint data (free, no key)
  · queries free-tier carrier lookup APIs (Veriphone, OmkarCloud)
  · checks account existence on Instagram, Snapchat, Amazon (silent)
  · checks breach exposure via HIBP (key optional)
  · builds SMS/email gateway addresses for ~40 carriers
  · generates categorized Google dorks (social, docs, fraud, business)
  · builds multi-engine search links (Google/Bing/DDG/Yandex/Brave)
  · builds deep links for WhatsApp, Telegram, Viber, Signal
  · generates business directory dorks (GMaps, Yelp, JustDial)
  · computes a 0–100 exposure score
  · tracks scan history, shows diff from previous run
  · exports to JSON, CSV, and HTML
"""

import csv
import html
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
    "yellow": "yellow", "red": "red", "green": "green",
}))

BAR_FMT = "\033[38;5;245m  {desc} |{bar}| {percentage:3.0f}%\033[0m"
OUT_DIR = Path.home() / ".osinttoolkit" / "exports"
OUT_DIR.mkdir(parents=True, exist_ok=True)
HIST_DIR = Path.home() / ".osinttoolkit" / "phone_history"
HIST_DIR.mkdir(parents=True, exist_ok=True)

UA = "Mozilla/5.0 (compatible; ostinttol)"

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


# ─────────────────────── SMS email gateways ───────────────────────

SMS_GATEWAYS = {
    "US": [
        ("AT&T",        "@txt.att.net"),
        ("AT&T MMS",    "@mms.att.net"),
        ("T-Mobile",    "@tmomail.net"),
        ("Verizon",     "@vtext.com"),
        ("Verizon MMS", "@vzwpix.com"),
        ("Sprint",      "@messaging.sprintpcs.com"),
        ("Boost Mobile", "@myboostmobile.com"),
        ("Cricket",     "@sms.mycricket.com"),
        ("MetroPCS",    "@mymetropcs.com"),
        ("US Cellular", "@email.uscc.net"),
        ("Google Fi",   "@msg.fi.google.com"),
        ("Consumer Cellular", "@mailmymobile.net"),
        ("TracFone",    "@mmst5.tracfone.com"),
        ("Straight Talk", "@vtext.com"),
        ("Xfinity Mobile", "@vtext.com"),
        ("Visible",     "@vtext.com"),
        ("Mint Mobile", "@tmomail.net"),
        ("Republic Wireless", "@text.republicwireless.com"),
        ("Page Plus",   "@vtext.com"),
        ("H2O Wireless", "@txt.att.net"),
    ],
    "CA": [
        ("Bell",         "@txt.bell.ca"),
        ("Bell MMS",     "@txt.bellmobility.ca"),
        ("Rogers",       "@pcs.rogers.com"),
        ("Rogers MMS",   "@mms.rogers.com"),
        ("Telus",        "@msg.telus.com"),
        ("Koodo",        "@msg.koodomobile.com"),
        ("Fido",         "@fido.ca"),
        ("Virgin Mobile", "@vmobile.ca"),
        ("Freedom Mobile", "@txt.freedommobile.ca"),
        ("Public Mobile", "@msg.telus.com"),
        ("Chatr",        "@pcs.rogers.com"),
        ("Lucky Mobile", "@msg.telus.com"),
    ],
}


# ─────────────────────── Dork categories ───────────────────────

DORK_CATEGORIES = {
    "social": [
        ('"{q}" site:facebook.com', "Facebook mentions"),
        ('"{q}" site:linkedin.com', "LinkedIn mentions"),
        ('"{q}" site:twitter.com OR site:x.com', "Twitter/X mentions"),
        ('"{q}" site:instagram.com', "Instagram mentions"),
        ('"{q}" site:reddit.com', "Reddit mentions"),
        ('"{q}" site:tiktok.com', "TikTok mentions"),
        ('"{q}" site:vk.com', "VK mentions"),
        ('"{q}" site:t.me', "Telegram mentions"),
        ('"{q}" site:youtube.com', "YouTube mentions"),
    ],
    "documents": [
        ('"{q}" filetype:pdf', "PDF documents"),
        ('"{q}" filetype:doc OR filetype:docx', "Word documents"),
        ('"{q}" filetype:xls OR filetype:xlsx', "Excel spreadsheets"),
        ('"{q}" filetype:csv', "CSV dumps"),
        ('"{q}" filetype:txt', "TXT files"),
        ('"{q}" "contact" filetype:pdf', "Contact sheets"),
    ],
    "fraud": [
        ('"{q}" scam', "Scam reports"),
        ('"{q}" fraud', "Fraud reports"),
        ('"{q}" spam', "Spam reports"),
        ('"{q}" robocall', "Robocall reports"),
        ('"{q}" "do not call"', "DNC mentions"),
        ('"{q}" complaint', "Complaint mentions"),
        ('"{q}" site:800notes.com', "800notes"),
        ('"{q}" site:whocallsme.com', "WhoCallsMe"),
        ('"{q}" site:callercenter.com', "CallerCenter"),
    ],
    "business": [
        ('"{q}" site:yelp.com', "Yelp"),
        ('"{q}" site:yellowpages.com', "Yellow Pages"),
        ('"{q}" site:justdial.com', "JustDial (IN)"),
        ('"{q}" site:indiamart.com', "IndiaMart"),
        ('"{q}" site:sulekha.com', "Sulekha"),
        ('"{q}" "opening hours"', "Business hours"),
        ('"{q}" "contact us"', "Contact pages"),
    ],
    "data": [
        ('"{q}" "@gmail.com"', "Gmail context"),
        ('"{q}" "@yahoo.com"', "Yahoo context"),
        ('"{q}" "@outlook.com"', "Outlook context"),
        ('"{q}" site:pastebin.com', "Pastebin"),
        ('"{q}" site:ghostbin.com', "Ghostbin"),
        ('"{q}" site:rentry.co', "Rentry"),
        ('"{q}" site:paste.ee', "Paste.ee"),
    ],
}


SEARCH_ENGINES = [
    ("Google",     "https://www.google.com/search?q={q}"),
    ("Bing",       "https://www.bing.com/search?q={q}"),
    ("DuckDuckGo", "https://duckduckgo.com/?q={q}"),
    ("Yandex",     "https://yandex.com/search/?text={q}"),
    ("Brave",      "https://search.brave.com/search?q={q}"),
    ("Startpage",  "https://www.startpage.com/sp/search?query={q}"),
    ("Mojeek",     "https://www.mojeek.com/search?q={q}"),
]


DARKWEB_ENGINES = [
    ("Ahmia",       "https://ahmia.fi/search/?q={q}"),
    ("DarkSearch",  "https://darksearch.io/search?query={q}"),
    ("Haystak",     "https://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/"),
    ("Torch",       "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/"),
    ("DeepSearch",  "https://deepsearch.me/"),
]


# ─────────────────────── Pivots ───────────────────────

PIVOT_SITES = [
    ("WhatsApp",    "https://wa.me/{e}"),
    ("Telegram",    "https://t.me/+{e}"),
    ("Viber",       "viber://chat?number=%2B{e}"),
    ("Truecaller",  "https://www.truecaller.com/search/global/{e}"),
    ("TruePeople",  "https://www.truepeoplesearch.com/results?phoneno={e}"),
    ("NumLookup",   "https://www.numlookup.com/?number={e}"),
    ("Sync.me",     "https://sync.me/search/?number=%2B{e}"),
    ("SpyDialer",   "https://www.spydialer.com/default.aspx?phone={e}"),
    ("FastPeople",  "https://www.fastpeoplesearch.com/{e}"),
    ("ThatsThem",   "https://thatsthem.com/phone/{e}"),
    ("Eyecon",      "https://eyeconapps.com/"),
    ("CallApp",     "https://callapp.com/"),
    ("Zlookup",     "https://www.zlookup.com/?phone={e}"),
    ("AnyWho",      "https://www.anywho.com/reverse-phone-lookup/"),
    ("Whitepages",  "https://www.whitepages.com/phone/{e}"),
    ("NumVerify",   "https://numverify.com/?number={e}"),
    ("IPQualityScore", "https://www.ipqualityscore.com/reverse-phone-lookup/lookup/{e}"),
    ("ReversePhoneLookup", "https://www.reversephonelookup.com/?phone={e}"),
]


# ─────────────────────── Core parse helpers ───────────────────────

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


# ─────────────────────── OVH Telecom check ───────────────────────

def _ovh_check(e164_digits):
    """Query OVH Telecom API to see if number is in their VoIP range. Free, no key."""
    try:
        r = requests.get(
            "https://api.ovh.com/1.0/telephony/number/detailedZones",
            headers={"User-Agent": UA}, timeout=10,
        )
        if r.status_code != 200:
            return {"available": False, "reason": f"ovh api {r.status_code}"}
        zones = r.json() or []
        # range check: e164 as int falls inside any zone range
        try:
            val = int(e164_digits)
        except Exception:
            return {"available": False, "reason": "invalid digits"}
        for z in zones:
            try:
                start = int(str(z.get("prefix", "")) + str(z.get("zone", "")))
                count = int(z.get("count", 0))
                if start <= val < start + count:
                    return {
                        "available": True,
                        "matched": {
                            "prefix": z.get("prefix"),
                            "zone": z.get("zone"),
                            "country": z.get("country"),
                            "city": z.get("city"),
                            "type": z.get("type"),
                        },
                    }
            except Exception:
                continue
        return {"available": False, "reason": "no matching OVH zone"}
    except Exception as e:
        return {"available": False, "reason": type(e).__name__}


# ─────────────────────── FTC / USA Caller Lookup ───────────────────────

def _ftc_complaints(e164_digits):
    """Query the free USA Caller Lookup API for FTC Do Not Call complaints."""
    try:
        r = requests.get(
            f"https://www.usacallerlookup.com/api/number/{e164_digits}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _area_code_info(npa):
    """US area code metadata (NANPA) via USA Caller Lookup."""
    try:
        r = requests.get(
            f"https://www.usacallerlookup.com/api/area-code/{npa}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


# ─────────────────────── Free carrier APIs ───────────────────────

def _veriphone_lookup(e164_digits):
    """Veriphone free tier — 1000 lookups/month, no key needed for demo."""
    try:
        r = requests.get(
            f"https://api.veriphone.io/v2/verify",
            params={"phone": f"+{e164_digits}"},
            headers={"User-Agent": UA}, timeout=10,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _omkar_lookup(e164_digits):
    """OmkarCloud carrier lookup API playground — no key for demo."""
    try:
        r = requests.get(
            "https://carrier-lookup-api.omkar.cloud/lookup",
            params={"phone": f"+{e164_digits}"},
            headers={"User-Agent": UA}, timeout=10,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _libphonenumber_api(e164_digits):
    """Public libphonenumber REST wrapper."""
    try:
        r = requests.get(
            "https://libphonenumberapi.com/api/validate",
            params={"number": f"+{e164_digits}"},
            headers={"User-Agent": UA}, timeout=10,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


# ─────────────────────── Account existence checks ───────────────────────

def _instagram_check(e164_digits):
    """Silent Instagram phone-registration check."""
    try:
        r = requests.post(
            "https://www.instagram.com/api/v1/users/check_phone_number/",
            data={"phone_number": f"+{e164_digits}"},
            headers={
                "User-Agent": UA,
                "X-IG-App-ID": "936619743392459",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=10,
        )
        if r.status_code == 200:
            j = r.json()
            return {
                "registered": j.get("is_taken") is True,
                "raw": j,
            }
    except Exception:
        pass
    return None


def _snapchat_check(e164_digits):
    """Silent Snapchat recovery endpoint check."""
    try:
        r = requests.post(
            "https://accounts.snapchat.com/accounts/merlin/recover/username",
            data={"phone_number": f"+{e164_digits}"},
            headers={"User-Agent": UA}, timeout=10,
        )
        t = (r.text or "").lower()
        return {
            "registered": "no account" not in t and "not found" not in t and r.status_code in (200, 302),
            "status": r.status_code,
        }
    except Exception:
        pass
    return None


def _amazon_check(e164_digits):
    """Amazon forgot-password existence check."""
    try:
        r = requests.get(
            "https://www.amazon.com/ap/forgotpassword",
            params={"phone": f"+{e164_digits}"},
            headers={"User-Agent": UA}, timeout=10,
        )
        t = (r.text or "").lower()
        # if we hit the recovery form = registered
        return {
            "registered": "verification" in t or "reset" in t,
            "status": r.status_code,
        }
    except Exception:
        pass
    return None


def _telegram_check(e164_digits):
    """Telegram existence check via the public recovery page."""
    try:
        r = requests.get(
            "https://telegram.org/support",
            params={"phone": f"+{e164_digits}"},
            headers={"User-Agent": UA}, timeout=10,
        )
        return {"status": r.status_code}
    except Exception:
        return None


def _whatsapp_probe(e164_digits):
    """WhatsApp wa.me probe (limited — page identical for exists/not)."""
    try:
        r = requests.get(
            f"https://wa.me/{e164_digits}",
            headers={"User-Agent": UA},
            timeout=10,
            allow_redirects=True,
        )
        # not conclusive from web — just build link
        return {"status": r.status_code, "url": f"https://wa.me/{e164_digits}"}
    except Exception:
        return None


# ─────────────────────── Breach check ───────────────────────

def _hibp_phone(e164_digits, api_key=None):
    """HIBP v3 breachedaccount — key optional, silently skipped without."""
    if not api_key:
        return None
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{e164_digits}",
            headers={"User-Agent": UA, "hibp-api-key": api_key},
            timeout=12,
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            return []
    except Exception:
        pass
    return None


def _pastebin_search(e164_digits):
    """psbdmp — public paste search endpoint."""
    try:
        r = requests.get(
            "https://psbdmp.ws/api/v3/search/" + e164_digits,
            headers={"User-Agent": UA}, timeout=10,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


# ─────────────────────── Pivots + dorks ───────────────────────

def _pivots(e164_digits):
    return [(name, url.format(e=e164_digits)) for name, url in PIVOT_SITES]


def _search_engine_links(e164, raw_digits):
    out = []
    q = f'"{e164}"'
    q_raw = f'"{raw_digits}"'
    for name, tmpl in SEARCH_ENGINES:
        out.append((name, tmpl.format(q=requests.utils.quote(q))))
        out.append((name + " (raw)", tmpl.format(q=requests.utils.quote(q_raw))))
    return out


def _darkweb_links(e164):
    q = requests.utils.quote(f'"{e164}"')
    return [(name, tmpl.format(q=q)) for name, tmpl in DARKWEB_ENGINES
            if "{q}" in tmpl]


def _dorks(raw_digits, e164):
    all_dorks = []
    qs = [raw_digits, e164.lstrip("+"), e164]
    for cat, patterns in DORK_CATEGORIES.items():
        for q in qs:
            for tmpl, label in patterns:
                all_dorks.append((cat, label, tmpl.format(q=q)))
    return all_dorks


# ─────────────────────── SMS gateway addresses ───────────────────────

def _sms_gateways(e164_digits, region):
    out = []
    if region in SMS_GATEWAYS:
        for carrier_name, suffix in SMS_GATEWAYS[region]:
            out.append((region, carrier_name, f"{e164_digits}{suffix}"))
    return out


# ─────────────────────── Deep links ───────────────────────

def _deep_links(e164_digits):
    return [
        ("WhatsApp",  f"https://wa.me/{e164_digits}"),
        ("Telegram",  f"https://t.me/+{e164_digits}"),
        ("Viber",     f"viber://chat?number=%2B{e164_digits}"),
        ("Signal",    f"https://signal.me/#p/+{e164_digits}"),
        ("Skype",     f"skype:+{e164_digits}?call"),
        ("Facetime",  f"facetime://+{e164_digits}"),
        ("SMS",       f"sms:+{e164_digits}"),
        ("Tel",       f"tel:+{e164_digits}"),
    ]


# ─────────────────────── Exposure score ───────────────────────

def _exposure_score(meta, ovh, ftc, accounts, breaches, pastes, line_type):
    """0-100 heuristic — higher = more exposed."""
    score = 0
    reasons = []

    if line_type == "mobile":
        score += 15
        reasons.append("mobile line — carries messaging/calls")
    elif line_type == "voip":
        score += 25
        reasons.append("VoIP line — often tied to online services")
    elif line_type == "fixed line":
        score += 5
        reasons.append("fixed line — low online footprint expected")

    if ovh.get("available"):
        score += 5
        reasons.append("OVH Telecom VoIP block")

    if ftc and (ftc.get("complaints") or {}).get("total", 0) > 0:
        c = ftc["complaints"]["total"]
        if c > 100:
            score += 20
        elif c > 10:
            score += 12
        else:
            score += 5
        reasons.append(f"{c} FTC complaint(s) recorded")

    for svc, res in (accounts or {}).items():
        if res and res.get("registered"):
            score += 8
            reasons.append(f"registered on {svc}")

    if breaches:
        score += min(20, len(breaches) * 4)
        reasons.append(f"{len(breaches)} breach record(s)")

    if pastes and pastes.get("count"):
        score += min(10, pastes["count"])
        reasons.append(f"{pastes['count']} paste hit(s)")

    return min(score, 100), reasons


# ─────────────────────── History ───────────────────────

def _history_path(e164_digits):
    safe = re.sub(r"[^0-9]", "_", e164_digits)[:24]
    return HIST_DIR / f"{safe}.json"


def _load_history(e164_digits):
    p = _history_path(e164_digits)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _save_history(e164_digits, snapshot):
    p = _history_path(e164_digits)
    p.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False,
                            default=str), encoding="utf-8")


def _diff_history(prev, current):
    if not prev:
        return []
    diffs = []
    keys = ("carrier", "geocoded", "line_type", "region")
    pmeta = prev.get("meta") or {}
    cmeta = current.get("meta") or {}
    for k in keys:
        if pmeta.get(k) != cmeta.get(k):
            diffs.append(f"{k}: {pmeta.get(k)} → {cmeta.get(k)}")
    if prev.get("exposure_score") != current.get("exposure_score"):
        diffs.append(
            f"exposure score: {prev.get('exposure_score')} → "
            f"{current.get('exposure_score')}"
        )
    return diffs


# ─────────────────────── Render ───────────────────────

def _render(raw, fmt, meta, pivots, ovh, ftc, area_code,
            free_apis, accounts, breaches, pastes,
            sms_gws, engine_links, dw_links, dorks,
            deep_links, score, reasons, history_diffs):
    console.print(Panel.fit(
        f"[bg]PHONE LOOKUP[/bg]  [dg]{fmt.get('e164', raw)}[/dg]",
        border_style="bd", padding=(0, 2),
    ))

    # formats
    ft = Table(border_style="bd", title="[bg]formats[/bg]",
               show_header=False, padding=(0, 2))
    ft.add_column("k", style="dg", no_wrap=True)
    ft.add_column("v", style="g")
    for k in ("e164", "international", "national", "rfc3966"):
        if fmt.get(k):
            ft.add_row(k, fmt[k])
    console.print(ft)

    # metadata
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

    # exposure
    score_color = "green" if score < 30 else "yellow" if score < 70 else "red"
    console.print(Panel.fit(
        f"[bg]exposure score[/bg]  "
        f"[{score_color}]{score}/100[/{score_color}]",
        border_style="bd", padding=(0, 2),
    ))
    for r in reasons:
        console.print(f"[dg]  · {r}[/dg]")
    console.print()

    # OVH
    if ovh:
        if ovh.get("available"):
            m = ovh.get("matched") or {}
            console.print(f"[green]  OVH Telecom VoIP block matched: "
                          f"{m.get('country')} / {m.get('city')} / {m.get('type')}[/green]\n")
        else:
            console.print(f"[dg]  OVH Telecom: {ovh.get('reason', 'no match')}[/dg]\n")

    # FTC
    if ftc:
        ftbl = Table(border_style="bd",
                     title="[bg]ftc do not call[/bg]",
                     show_header=False, padding=(0, 2))
        ftbl.add_column("k", style="dg", no_wrap=True)
        ftbl.add_column("v", style="g", overflow="fold")
        loc = ftc.get("location") or {}
        if loc:
            ftbl.add_row("city", str(loc.get("city") or "—"))
            ftbl.add_row("state", str(loc.get("state") or "—"))
            ftbl.add_row("carrier", str(loc.get("carrier") or "—"))
        comp = ftc.get("complaints") or {}
        ftbl.add_row("total complaints", str(comp.get("total") or 0))
        for s in (comp.get("top_subjects") or [])[:5]:
            ftbl.add_row("  subject", f"{s.get('subject')} ({s.get('count')})")
        console.print(ftbl)

    # area code
    if area_code:
        at = Table(border_style="bd", title="[bg]area code (NANPA)[/bg]",
                   show_header=False, padding=(0, 2))
        at.add_column("k", style="dg", no_wrap=True)
        at.add_column("v", style="g")
        at.add_row("state", str(area_code.get("state") or "—"))
        at.add_row("timezone", str(area_code.get("timezone") or "—"))
        cities = area_code.get("top_cities") or []
        if cities:
            at.add_row("top cities", ", ".join(cities[:5]))
        console.print(at)

    # free APIs
    if free_apis:
        fat = Table(border_style="bd", title="[bg]carrier apis[/bg]",
                    show_header=True, padding=(0, 2))
        fat.add_column("source", style="bg")
        fat.add_column("field", style="dg")
        fat.add_column("value", style="g", overflow="fold")
        for src, data in free_apis.items():
            if not data:
                continue
            for k, v in data.items():
                if isinstance(v, (str, int, float, bool)):
                    fat.add_row(src, k, str(v)[:80])
        console.print(fat)

    # accounts
    if accounts:
        act = Table(border_style="bd", title="[bg]account existence[/bg]",
                    show_header=True, padding=(0, 2))
        act.add_column("service", style="bg")
        act.add_column("registered", style="g")
        act.add_column("detail", style="dg", overflow="fold")
        for svc, res in accounts.items():
            if not res:
                continue
            reg = "[green]yes[/green]" if res.get("registered") else "[dg]no[/dg]"
            act.add_row(svc, reg, str(res.get("status", "")))
        console.print(act)

    # breaches
    if breaches is not None:
        if breaches:
            bt = Table(border_style="bd",
                       title=f"[bg]breaches ({len(breaches)})[/bg]",
                       show_header=True, padding=(0, 2))
            bt.add_column("name", style="bg", overflow="fold")
            bt.add_column("domain", style="dg")
            bt.add_column("date", style="dg")
            bt.add_column("pwn count", style="g", justify="right")
            for b in breaches[:30]:
                bt.add_row(
                    b.get("Name") or "—",
                    b.get("Domain") or "—",
                    (b.get("BreachDate") or "—")[:10],
                    f"{b.get('PwnCount', 0):,}",
                )
            console.print(bt)
        else:
            console.print("[dg]  breaches: none[/dg]\n")

    if pastes and pastes.get("count"):
        console.print(f"[yellow]  pastebin hits: {pastes['count']}[/yellow]")
        for p in (pastes.get("data") or [])[:5]:
            console.print(f"[yellow]    · {p.get('id', '?')} ({p.get('date', '?')})[/yellow]")
        console.print()

    # SMS gateways
    if sms_gws:
        st = Table(border_style="bd",
                   title=f"[bg]sms/email gateways ({len(sms_gws)})[/bg]",
                   show_header=True, padding=(0, 2))
        st.add_column("region", style="dg")
        st.add_column("carrier", style="bg")
        st.add_column("address", style="g", overflow="fold")
        for r, c, a in sms_gws:
            st.add_row(r, c, a)
        console.print(st)

    # pivots
    pt = Table(border_style="bd", title="[bg]pivot links[/bg]",
               show_header=True, padding=(0, 2))
    pt.add_column("service", style="bg")
    pt.add_column("url", style="g", overflow="fold")
    for svc, url in pivots:
        pt.add_row(svc, url)
    console.print(pt)

    # deep links
    dt = Table(border_style="bd", title="[bg]deep links[/bg]",
               show_header=True, padding=(0, 2))
    dt.add_column("app", style="bg")
    dt.add_column("link", style="g", overflow="fold")
    for app, url in deep_links:
        dt.add_row(app, url)
    console.print(dt)

    # search engines
    set_ = Table(border_style="bd", title="[bg]search engines[/bg]",
                 show_header=True, padding=(0, 2))
    set_.add_column("engine", style="bg")
    set_.add_column("query", style="dg")
    set_.add_column("url", style="g", overflow="fold")
    for name, url in engine_links:
        set_.add_row(name, "phone", url)
    console.print(set_)

    # darkweb
    if dw_links:
        dwt = Table(border_style="bd", title="[bg]darkweb engines[/bg]",
                    show_header=True, padding=(0, 2))
        dwt.add_column("engine", style="bg")
        dwt.add_column("url", style="g", overflow="fold")
        for name, url in dw_links:
            dwt.add_row(name, url)
        console.print(dwt)

    # dorks
    if dorks:
        grp = {}
        for cat, label, d in dorks:
            grp.setdefault(cat, []).append((label, d))
        for cat, items in grp.items():
            dtbl = Table(border_style="bd",
                         title=f"[bg]dorks — {cat} ({len(items)})[/bg]",
                         show_header=True, padding=(0, 2))
            dtbl.add_column("label", style="bg")
            dtbl.add_column("query", style="g", overflow="fold")
            for label, d in items[:20]:
                dtbl.add_row(label, d)
            console.print(dtbl)

    # history diff
    if history_diffs:
        console.print(Panel.fit(
            "[bg]changes since last scan[/bg]",
            border_style="bd", padding=(0, 2),
        ))
        for d in history_diffs:
            console.print(f"[yellow]  · {d}[/yellow]")
        console.print()

    console.print()


# ─────────────────────── Export ───────────────────────

def _export_json(raw, fmt, meta, pivots, ovh, ftc, area_code,
                 free_apis, accounts, breaches, pastes,
                 sms_gws, engine_links, dw_links, dorks,
                 deep_links, score, reasons):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = _digits(raw)[:20]
    p = OUT_DIR / f"phone_{safe}_{ts}.json"
    p.write_text(json.dumps({
        "raw": raw, "formats": fmt, "meta": meta,
        "pivots": [{"service": s, "url": u} for s, u in pivots],
        "ovh": ovh, "ftc": ftc, "area_code": area_code,
        "free_apis": free_apis, "accounts": accounts,
        "breaches": breaches, "pastes": pastes,
        "sms_gateways": [{"region": r, "carrier": c, "addr": a}
                         for r, c, a in sms_gws],
        "search_engines": [{"engine": e, "url": u} for e, u in engine_links],
        "darkweb": [{"engine": e, "url": u} for e, u in dw_links],
        "dorks": [{"category": c, "label": l, "query": d} for c, l, d in dorks],
        "deep_links": [{"app": a, "link": l} for a, l in deep_links],
        "exposure_score": score, "exposure_reasons": reasons,
        "generated": datetime.now().isoformat(timespec="seconds"),
    }, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]")
    return p


def _export_csv(raw, fmt, meta, score, reasons, pivots):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = _digits(raw)[:20]
    p = OUT_DIR / f"phone_{safe}_{ts}.csv"
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["section", "key", "value"])
        for k, v in fmt.items():
            w.writerow(["format", k, v])
        for k, v in meta.items():
            w.writerow(["meta", k, str(v)])
        w.writerow(["exposure", "score", score])
        for i, r in enumerate(reasons):
            w.writerow(["exposure", f"reason_{i}", r])
        for svc, url in pivots:
            w.writerow(["pivot", svc, url])
    console.print(f"[dg]  exported → {p}[/dg]")


def _export_html(raw, fmt, meta, score, reasons, pivots, dorks,
                 sms_gws, deep_links):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = _digits(raw)[:20]
    p = OUT_DIR / f"phone_{safe}_{ts}.html"

    def esc(x):
        return html.escape(str(x))

    rows_fmt = "".join(
        f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in fmt.items())
    rows_meta = "".join(
        f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in meta.items())
    rows_piv = "".join(
        f'<tr><td>{esc(s)}</td><td><a href="{esc(u)}">{esc(u)}</a></td></tr>'
        for s, u in pivots)
    rows_dork = "".join(
        f"<tr><td>{esc(c)}</td><td>{esc(l)}</td><td>{esc(d)}</td></tr>"
        for c, l, d in dorks)
    rows_sms = "".join(
        f"<tr><td>{esc(r)}</td><td>{esc(c)}</td><td>{esc(a)}</td></tr>"
        for r, c, a in sms_gws)
    rows_deep = "".join(
        f'<tr><td>{esc(a)}</td><td><a href="{esc(l)}">{esc(l)}</a></td></tr>'
        for a, l in deep_links)
    reasons_html = "".join(f"<li>{esc(r)}</li>" for r in reasons)

    doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Phone Report — {esc(raw)}</title>
<style>
body {{ background: #111; color: #ddd; font-family: monospace; padding: 2em; }}
h1, h2 {{ color: #9fd4ff; }}
table {{ border-collapse: collapse; margin: 1em 0; }}
td, th {{ border: 1px solid #333; padding: 4px 10px; }}
a {{ color: #8fe388; }}
.score {{ font-size: 2em; color: #f2c14e; }}
</style></head><body>
<h1>Phone Report — {esc(raw)}</h1>
<p>Generated {esc(datetime.now().isoformat(timespec="seconds"))}</p>
<h2>Exposure Score</h2>
<p class="score">{esc(score)}/100</p>
<ul>{reasons_html}</ul>
<h2>Formats</h2><table>{rows_fmt}</table>
<h2>Metadata</h2><table>{rows_meta}</table>
<h2>Pivot Links</h2><table>{rows_piv}</table>
<h2>Deep Links</h2><table>{rows_deep}</table>
<h2>SMS Gateways</h2><table>{rows_sms}</table>
<h2>Dorks</h2><table><tr><th>Category</th><th>Label</th><th>Query</th></tr>{rows_dork}</table>
</body></html>
"""
    p.write_text(doc, encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]")


# ─────────────────────── Runner ───────────────────────

def run():
    raw = input("  phone (any format, e.g. +48...) >> ").strip()
    if not raw:
        print("  [!] empty input")
        return

    if not HAS_PN:
        print("  [!] install phonenumbers: pip install phonenumbers")
        return

    with tqdm(total=8, desc="parsing", ncols=60, bar_format=BAR_FMT) as bar:
        n, err = _parse(raw); bar.update(1)
        if err:
            print(f"  [!] {err}")
            return
        fmt = _formats(n); bar.update(1)
        meta = _meta(n); bar.update(1)

        e164_digits = fmt["e164"].lstrip("+")
        pivots = _pivots(e164_digits); bar.update(1)
        sms_gws = _sms_gateways(e164_digits, meta["region"]); bar.update(1)
        deep_links = _deep_links(e164_digits); bar.update(1)
        dorks = _dorks(_digits(raw), fmt["e164"]); bar.update(1)
        engine_links = _search_engine_links(fmt["e164"], _digits(raw))
        bar.update(1)

    # ---- online queries ----
    ovh = {"available": False, "reason": "skipped"}
    ftc = None
    area_code = None
    free_apis = {}
    accounts = {}
    breaches = None
    pastes = None

    if meta["region"] in ("US", "CA"):
        with console.status("[dg]querying FTC DNC data...[/dg]",
                            spinner="dots"):
            ftc = _ftc_complaints(e164_digits)
            npa = e164_digits[1:4] if meta["region"] == "US" else None
            if npa:
                area_code = _area_code_info(npa)

    with console.status("[dg]checking OVH VoIP...[/dg]", spinner="dots"):
        ovh = _ovh_check(e164_digits)

    with console.status("[dg]free carrier APIs...[/dg]", spinner="dots"):
        free_apis["veriphone"] = _veriphone_lookup(e164_digits)
        free_apis["omkar"] = _omkar_lookup(e164_digits)

    with console.status("[dg]silent account checks...[/dg]", spinner="dots"):
        accounts["Instagram"] = _instagram_check(e164_digits)
        accounts["Snapchat"] = _snapchat_check(e164_digits)
        accounts["Amazon"] = _amazon_check(e164_digits)

    with console.status("[dg]paste search...[/dg]", spinner="dots"):
        pastes = _pastebin_search(e164_digits)

    # HIBP — key from config if set
    cfg_path = Path("config") / "config.json"
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            hibp_key = cfg.get("hibp_api_key")
            if hibp_key:
                with console.status("[dg]HIBP breach lookup...[/dg]",
                                    spinner="dots"):
                    breaches = _hibp_phone(e164_digits, hibp_key)
        except Exception:
            pass

    score, reasons = _exposure_score(meta, ovh, ftc, accounts,
                                     breaches, pastes, meta["line_type"])

    # ---- history diff ----
    snapshot = {
        "meta": meta,
        "ovh": ovh,
        "exposure_score": score,
        "exposure_reasons": reasons,
        "generated": datetime.now().isoformat(timespec="seconds"),
    }
    prev = _load_history(e164_digits)
    history_diffs = _diff_history(prev, snapshot)

    _render(raw, fmt, meta, pivots, ovh, ftc, area_code,
            free_apis, accounts, breaches, pastes,
            sms_gws, engine_links, _darkweb_links(fmt["e164"]), dorks,
            deep_links, score, reasons, history_diffs)

    if input("  export? [j/c/h/N] >> ").strip().lower() in ("y", "j"):
        _export_json(raw, fmt, meta, pivots, ovh, ftc, area_code,
                     free_apis, accounts, breaches, pastes,
                     sms_gws, engine_links, _darkweb_links(fmt["e164"]),
                     dorks, deep_links, score, reasons)
    choice = input("  export csv? [y/N] >> ").strip().lower()
    if choice == "y":
        _export_csv(raw, fmt, meta, score, reasons, pivots)
    choice = input("  export html? [y/N] >> ").strip().lower()
    if choice == "y":
        _export_html(raw, fmt, meta, score, reasons, pivots, dorks,
                     sms_gws, deep_links)

    _save_history(e164_digits, snapshot)
