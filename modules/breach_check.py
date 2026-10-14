"""
breach_check.py — Multi-source breach & credential exposure analysis.

Pipeline:
  1. target classification (email / password / domain)
  2. syntax validation & MX record lookup
  3. HaveIBeenPwned breaches (key optional via HIBP_API_KEY env)
  4. HaveIBeenPwned pastes (same key)
  5. HaveIBeenPwned password k-anonymity (keyless)
  6. EmailRep.io reputation
  7. Gravatar profile existence (md5)
  8. Offline known-breach correlation
  9. Pattern & strength analysis
 10. Rich output + optional JSON export
"""

import hashlib
import json
import os
import re
import socket
import time
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

OUT_DIR = Path.home() / ".osinttoolkit" / "exports"
OUT_DIR.mkdir(parents=True, exist_ok=True)

UA = "Mozilla/5.0 (compatible; doxtoolkit/2.0)"
HIBP_KEY = os.environ.get("HIBP_API_KEY", "").strip()

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "tempmail.com", "temp-mail.org", "throwawaymail.com", "yopmail.com",
    "sharklasers.com", "trashmail.com", "getnada.com", "maildrop.cc",
    "dispostable.com", "fakeinbox.com", "mintemail.com", "mailnesia.com",
}

# Curated dataset — headliners from the big breach wave 2012–2024.
KNOWN_BREACHES = [
    {"name": "LinkedIn", "date": "2012-06", "records": 164_000_000,
     "classes": ["Emails", "Passwords"]},
    {"name": "Adobe", "date": "2013-10", "records": 153_000_000,
     "classes": ["Emails", "Encrypted passwords", "Hints"]},
    {"name": "Tumblr", "date": "2013", "records": 65_000_000,
     "classes": ["Emails", "Hashed passwords"]},
    {"name": "MySpace", "date": "2013", "records": 360_000_000,
     "classes": ["Emails", "Passwords"]},
    {"name": "Dropbox", "date": "2012", "records": 68_000_000,
     "classes": ["Emails", "Hashed passwords"]},
    {"name": "Ashley Madison", "date": "2015-07", "records": 32_000_000,
     "classes": ["Emails", "Passwords", "Payment info"]},
    {"name": "Yahoo", "date": "2014", "records": 500_000_000,
     "classes": ["Emails", "Hashed passwords", "Security questions"]},
    {"name": "FriendFinder", "date": "2016-10", "records": 412_000_000,
     "classes": ["Emails", "Passwords"]},
    {"name": "Equifax", "date": "2017-09", "records": 147_000_000,
     "classes": ["SSN", "Names", "Addresses", "DOB"]},
    {"name": "Deloitte", "date": "2017", "records": 5_000_000,
     "classes": ["Emails", "Passwords", "IP addresses"]},
    {"name": "MyFitnessPal", "date": "2018-02", "records": 144_000_000,
     "classes": ["Emails", "Hashed passwords"]},
    {"name": "Under Armour", "date": "2018", "records": 150_000_000,
     "classes": ["Emails", "Hashed passwords"]},
    {"name": "Chegg", "date": "2018-04", "records": 40_000_000,
     "classes": ["Emails", "Passwords", "Addresses"]},
    {"name": "Facebook", "date": "2019", "records": 533_000_000,
     "classes": ["Names", "Phone numbers", "Emails", "DOB"]},
    {"name": "Collection #1", "date": "2019-01", "records": 773_000_000,
     "classes": ["Emails", "Passwords"]},
    {"name": "Canva", "date": "2019-05", "records": 137_000_000,
     "classes": ["Emails", "Hashed passwords", "Names"]},
    {"name": "Tokopedia", "date": "2020-05", "records": 91_000_000,
     "classes": ["Emails", "Hashed passwords"]},
    {"name": "Twitter", "date": "2022-01", "records": 200_000_000,
     "classes": ["Emails", "Phone numbers"]},
    {"name": "LastPass", "date": "2022-08", "records": 25_000_000,
     "classes": ["Emails", "Encrypted vaults"]},
    {"name": "Twitter (v2)", "date": "2023", "records": 235_000_000,
     "classes": ["Emails", "Handles"]},
    {"name": "Deezer", "date": "2022-11", "records": 229_000_000,
     "classes": ["Emails", "DOB", "IPs"]},
    {"name": "AT&T", "date": "2024-03", "records": 73_000_000,
     "classes": ["SSN", "Passwords", "PINs"]},
    {"name": "National Public Data", "date": "2024-04", "records": 2_900_000_000,
     "classes": ["SSN", "Names", "Addresses"]},
    {"name": "Internet Archive", "date": "2024-09", "records": 31_000_000,
     "classes": ["Emails", "Hashed passwords"]},
    {"name": "MOVEit", "date": "2023-05", "records": 60_000_000,
     "classes": ["Names", "Financial", "SSN"]},
]


# ───────────────────────── validation ─────────────────────────

def _classify(target: str) -> str:
    if EMAIL_RE.match(target):
        return "email"
    if re.fullmatch(r"[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", target):
        return "domain"
    if len(target) >= 4:
        return "password"
    return "unknown"


def _mx_lookup(domain: str):
    """Query Google's public resolver for MX records (no dnspython needed)."""
    try:
        r = requests.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": "MX"},
            headers={"User-Agent": UA},
            timeout=8,
        )
        d = r.json()
        answers = d.get("Answer") or []
        out = []
        for a in answers:
            if a.get("type") == 15:  # MX
                parts = a.get("data", "").split()
                if len(parts) == 2:
                    out.append((int(parts[0]), parts[1].rstrip(".")))
        return sorted(out)
    except Exception:
        return []


def _disposable(domain: str) -> bool:
    return domain.lower() in DISPOSABLE


# ───────────────────────── HIBP ─────────────────────────

def _hibp_breaches(email: str):
    headers = {"User-Agent": UA, "hibp-api-key": HIBP_KEY}
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/"
            f"{email}?truncateResponse=false",
            headers=headers, timeout=12,
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code in (404, 401):
            return []
        return None
    except Exception:
        return None


def _hibp_pastes(email: str):
    headers = {"User-Agent": UA, "hibp-api-key": HIBP_KEY}
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
            headers=headers, timeout=12,
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code in (404, 401):
            return []
        return None
    except Exception:
        return None


def _hibp_password(password: str):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": UA}, timeout=10,
        )
        r.raise_for_status()
    except Exception:
        return None
    for line in r.text.splitlines():
        h, _, count = line.partition(":")
        if h.strip() == suffix:
            return int(count)
    return 0


# ───────────────────────── reputation ─────────────────────────

def _emailrep(email: str):
    try:
        r = requests.get(
            f"https://emailrep.io/{email}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None


def _gravatar(email: str):
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    try:
        r = requests.get(
            f"https://www.gravatar.com/avatar/{h}?d=404",
            headers={"User-Agent": UA}, timeout=8,
        )
        if r.status_code == 200:
            return f"https://www.gravatar.com/{h}"
    except Exception:
        pass
    return None


# ───────────────────────── offline correlation ─────────────────────────

def _offline_domain_hits(email: str):
    domain = email.split("@", 1)[1].lower()
    hits = []
    for b in KNOWN_BREACHES:
        # very rough — breach of a domain doesn't mean this email, but if
        # the provider domain matches a breached service, it's worth flagging.
        if domain in b["name"].lower().replace(" ", ""):
            hits.append(b)
    return hits


# ───────────────────────── password analysis ─────────────────────────

COMMON_PATTERNS = [
    ("all lowercase letters", re.compile(r"^[a-z]+$")),
    ("all uppercase letters", re.compile(r"^[A-Z]+$")),
    ("letters only", re.compile(r"^[A-Za-z]+$")),
    ("digits only", re.compile(r"^\d+$")),
    ("ends with 123", re.compile(r"123$")),
    ("starts with capital + digits", re.compile(r"^[A-Z][a-z]+\d+$")),
    ("contains year 19xx/20xx", re.compile(r"(19|20)\d{2}")),
    ("keyboard walk", re.compile(r"(qwer|asdf|zxcv|1234)", re.I)),
]


def _password_analysis(pw: str):
    out = {
        "length": len(pw),
        "has_lower": bool(re.search(r"[a-z]", pw)),
        "has_upper": bool(re.search(r"[A-Z]", pw)),
        "has_digit": bool(re.search(r"\d", pw)),
        "has_symbol": bool(re.search(r"[^A-Za-z0-9]", pw)),
        "patterns": [],
    }
    for label, rx in COMMON_PATTERNS:
        if rx.search(pw):
            out["patterns"].append(label)
    return out


# ───────────────────────── render ─────────────────────────

def _render_email(target, mx, breaches, pastes, rep, grav, offline, pw_count):
    console.print(Panel.fit(
        f"[bg]BREACH REPORT[/bg]  [dg]{target}[/dg]",
        border_style="bd", padding=(0, 2),
    ))

    domain = target.split("@", 1)[1].lower()

    meta = Table(border_style="bd", show_header=False, padding=(0, 2))
    meta.add_column("k", style="dg", no_wrap=True)
    meta.add_column("v", style="g")
    meta.add_row("domain", domain)
    meta.add_row("disposable", "yes" if _disposable(domain) else "no")
    if mx:
        meta.add_row("mx", ", ".join(f"{prio} {host}" for prio, host in mx[:3]))
    else:
        meta.add_row("mx", "— (no MX records)")
    meta.add_row("gravatar", grav or "—")
    console.print(meta)

    if breaches is None:
        console.print("[dg]  HIBP breach endpoint unavailable "
                      "(set HIBP_API_KEY for full results)[/dg]")
    elif breaches:
        bt = Table(border_style="bd", title="[bg]hibp breaches[/bg]",
                   show_header=True, padding=(0, 2))
        bt.add_column("name", style="bg")
        bt.add_column("date", style="dg")
        bt.add_column("pwn count", style="g", justify="right")
        bt.add_column("data classes", style="g", overflow="fold")
        for b in breaches:
            bt.add_row(
                b.get("Name", "?"),
                b.get("BreachDate", "?"),
                f"{b.get('PwnCount', 0):,}",
                ", ".join(b.get("DataClasses", [])),
            )
        console.print(bt)
    else:
        console.print("[dg]  no HIBP breach records[/dg]")

    if pastes:
        pt = Table(border_style="bd", title="[bg]hibp pastes[/bg]",
                   show_header=True, padding=(0, 2))
        pt.add_column("source", style="bg")
        pt.add_column("date", style="dg")
        pt.add_column("id", style="dg")
        pt.add_column("emails", style="g", justify="right")
        for p in pastes:
            pt.add_row(
                p.get("Source", "?"),
                p.get("Date", "?"),
                p.get("Id", "?"),
                str(p.get("EmailCount", "?")),
            )
        console.print(pt)

    if rep:
        rt = Table(border_style="bd", title="[bg]emailrep[/bg]",
                   show_header=False, padding=(0, 2))
        rt.add_column("k", style="dg", no_wrap=True)
        rt.add_column("v", style="g")
        for k in ("reputation", "suspicious", "references",
                  "blacklisted", "malicious_activity", "credentials_leaked",
                  "data_breach", "profiles"):
            v = rep.get(k)
            if v not in (None, "", []):
                rt.add_row(k, str(v))
        console.print(rt)

    if offline:
        ot = Table(border_style="bd",
                   title="[bg]known breach correlation (offline)[/bg]",
                   show_header=True, padding=(0, 2))
        ot.add_column("name", style="bg")
        ot.add_column("date", style="dg")
        ot.add_column("records", style="g", justify="right")
        ot.add_column("classes", style="g", overflow="fold")
        for b in offline:
            ot.add_row(b["name"], b["date"], f"{b['records']:,}",
                       ", ".join(b["classes"]))
        console.print(ot)

    if pw_count is not None:
        if pw_count > 0:
            console.print(f"[g]  password seen {pw_count:,} times in "
                          f"pwned-passwords corpus[/g]")
        else:
            console.print("[dg]  password not present in pwned-passwords "
                          "corpus[/dg]")
    console.print()


def _render_password(pw, count, analysis):
    console.print(Panel.fit(
        "[bg]PASSWORD ANALYSIS[/bg]", border_style="bd", padding=(0, 2),
    ))

    t = Table(border_style="bd", show_header=False, padding=(0, 2))
    t.add_column("k", style="dg", no_wrap=True)
    t.add_column("v", style="g")
    t.add_row("length", str(analysis["length"]))
    t.add_row("lowercase", "yes" if analysis["has_lower"] else "no")
    t.add_row("uppercase", "yes" if analysis["has_upper"] else "no")
    t.add_row("digits", "yes" if analysis["has_digit"] else "no")
    t.add_row("symbols", "yes" if analysis["has_symbol"] else "no")
    t.add_row("patterns", ", ".join(analysis["patterns"]) or "—")
    t.add_row("pwned count", "unavailable" if count is None
              else f"{count:,}")
    console.print(t)
    console.print()


# ───────────────────────── export ─────────────────────────

def _export(target, payload):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target)[:32]
    p = OUT_DIR / f"breach_{safe}_{ts}.json"
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                 encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]\n")


# ───────────────────────── entry ─────────────────────────

def run():
    target = input("  email / password / domain >> ").strip()
    if not target:
        print("  [!] empty target")
        return

    kind = _classify(target)

    if kind == "password":
        with tqdm(total=10, desc="checking password",
                  ncols=60, bar_format=BAR_FMT) as bar:
            for _ in range(10):
                time.sleep(0.02)
                bar.update(1)
        count = _hibp_password(target)
        analysis = _password_analysis(target)
        _render_password(target, count, analysis)
        return

    if kind == "email":
        domain = target.split("@", 1)[1].lower()

        with tqdm(total=6, desc=f"analyzing {target}",
                  ncols=60, bar_format=BAR_FMT) as bar:
            mx = _mx_lookup(domain); bar.update(1)
            breaches = _hibp_breaches(target); bar.update(1)
            pastes = _hibp_pastes(target); bar.update(1)
            rep = _emailrep(target); bar.update(1)
            grav = _gravatar(target); bar.update(1)
            offline = _offline_domain_hits(target); bar.update(1)

        _render_email(target, mx, breaches, pastes, rep, grav, offline, None)

        if input("  export report? [y/N] >> ").strip().lower() == "y":
            _export(target, {
                "target": target,
                "kind": kind,
                "mx": mx,
                "hibp_breaches": breaches,
                "hibp_pastes": pastes,
                "emailrep": rep,
                "gravatar": grav,
                "offline_correlation": offline,
                "generated": datetime.now().isoformat(timespec="seconds"),
            })
        return

    if kind == "domain":
        mx = _mx_lookup(target)
        console.print(Panel.fit(
            f"[bg]DOMAIN LOOKUP[/bg]  [dg]{target}[/dg]",
            border_style="bd", padding=(0, 2),
        ))
        t = Table(border_style="bd", show_header=False, padding=(0, 2))
        t.add_column("k", style="dg", no_wrap=True)
        t.add_column("v", style="g")
        t.add_row("disposable", "yes" if _disposable(target) else "no")
        if mx:
            t.add_row("mx", ", ".join(f"{prio} {host}" for prio, host in mx))
        else:
            t.add_row("mx", "—")
        try:
            t.add_row("a record", socket.gethostbyname(target))
        except Exception:
            t.add_row("a record", "—")
        console.print(t)
        console.print()
        return

    print("  [!] unrecognized target (need email, domain, or password)")
