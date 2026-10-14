"""
email_lookup.py — Deep email intelligence.

Complementary to breach_check: focuses on registration footprints,
key server presence, avatar discovery, and reputation. Runs holehe-style
registration probes against a curated set of services.
"""

import hashlib
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
}))

BAR_FMT = "\033[38;5;245m  {desc} |{bar} | {percentage:3.0f}%\033[0m".replace(" | ", " | ")
OUT_DIR = Path.home() / ".doxtoolkit" / "exports"
OUT_DIR.mkdir(parents=True, exist_ok=True)

UA = "Mozilla/5.0 (compatible; osinttoolkit/2.0)"
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


# registration probes: (service, endpoint, method, body_kw, "not registered" markers)
PROBES = [
    ("Pinterest",
     "https://www.pinterest.com/resource/EmailExistsResource/get/",
     "GET",
     lambda e: {"data": json.dumps({"options": {"email": e}})},
     ("\"true\"",)),
    ("Spotify",
     "https://www.spotify.com/api/signup/validate",
     "POST",
     lambda e: {"email": e},
     ("already",)),
    ("Firefox",
     "https://api.accounts.firefox.com/v1/account/status",
     "POST",
     lambda e: {"email": e},
     ("false",)),
    ("Adobe",
     "https://auth.services.adobe.com/signup/v2/users/email",
     "POST",
     lambda e: {"email": e},
     ("taken",)),
    ("WordPress",
     "https://public-api.wordpress.com/rest/v1.1/users/email/exists",
     "GET",
     lambda e: {"email": e},
     ("\"exists\":true",)),
    ("Flickr",
     "https://identity.flickr.com/api/email",
     "POST",
     lambda e: {"email": e},
     ("taken",)),
    ("Envato",
     "https://account.envato.com/api/check_email",
     "POST",
     lambda e: {"email": e},
     ("taken",)),
    ("LastPass",
     "https://lastpass.com/create_account.php",
     "POST",
     lambda e: {"check": "avail", "username": e},
     ("not available", "taken")),
    ("Duolingo",
     "https://www.duolingo.com/2017-06-30/users",
     "POST",
     lambda e: {"email": e},
     ("already",)),
    ("Xbox",
     "https://login.live.com/GetCredentialType.srf",
     "POST",
     lambda e: {"username": e, "isOtherMSAccountOnly": True},
     ("existing",)),
]


def _valid(email):
    return bool(EMAIL_RE.match(email))


def _gravatar(email):
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


def _emailrep(email):
    try:
        r = requests.get(
            f"https://emailrep.io/{email}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _pgp_keys(email):
    """Look for the email in open PGP key servers."""
    sources = [
        ("keys.openpgp.org",
         f"https://keys.openpgp.org/vks/v1/by-email/{email}"),
        ("keyserver.ubuntu.com",
         f"https://keyserver.ubuntu.com/pks/lookup?op=get&search={email}"),
        ("pgp.mit.edu",
         f"https://pgp.mit.edu/pks/lookup?op=get&search={email}"),
    ]
    hits = []
    for name, url in sources:
        try:
            r = requests.get(url, headers={"User-Agent": UA}, timeout=8)
            if r.status_code == 200 and "BEGIN PGP PUBLIC KEY" in r.text:
                hits.append({"server": name, "url": url,
                             "size": len(r.text)})
        except Exception:
            continue
    return hits


def _mx(domain):
    try:
        r = requests.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": "MX"},
            headers={"User-Agent": UA}, timeout=8,
        )
        d = r.json()
        out = []
        for a in d.get("Answer") or []:
            if a.get("type") == 15:
                parts = a.get("data", "").split()
                if len(parts) == 2:
                    out.append((int(parts[0]), parts[1].rstrip(".")))
        return sorted(out)
    except Exception:
        return []


def _probe(service, endpoint, method, body_fn, markers, email, timeout=10):
    try:
        if method == "GET":
            r = requests.get(endpoint,
                             params=body_fn(email),
                             headers={"User-Agent": UA},
                             timeout=timeout)
        else:
            r = requests.post(endpoint,
                              data=body_fn(email),
                              headers={"User-Agent": UA},
                              timeout=timeout)
        text = r.text.lower()
        if any(m.lower() in text for m in markers):
            return (service, "REGISTERED", r.status_code)
        return (service, "not found", r.status_code)
    except Exception:
        return (service, "error", None)


def _render(email, mx, grav, rep, keys, probes):
    console.print(Panel.fit(
        f"[bg]EMAIL LOOKUP[/bg]  [dg]{email}[/dg]",
        border_style="bd", padding=(0, 2),
    ))

    m = Table(border_style="bd", title="[bg]identity[/bg]",
              show_header=False, padding=(0, 2))
    m.add_column("k", style="dg", no_wrap=True)
    m.add_column("v", style="g")
    m.add_row("domain", email.split("@", 1)[1].lower())
    m.add_row("mx", ", ".join(f"{p} {h}" for p, h in mx[:3]) or "—")
    m.add_row("gravatar", grav or "—")
    console.print(m)

    if rep:
        r = Table(border_style="bd", title="[bg]emailrep[/bg]",
                  show_header=False, padding=(0, 2))
        r.add_column("k", style="dg", no_wrap=True)
        r.add_column("v", style="g")
        for k in ("reputation", "suspicious", "references", "blacklisted",
                  "credentials_leaked", "data_breach", "profiles",
                  "malicious_activity", "domain_exists", "spam"):
            v = rep.get(k)
            if v not in (None, "", []):
                r.add_row(k, str(v))
        console.print(r)

    if keys:
        kt = Table(border_style="bd", title="[bg]pgp keys[/bg]",
                   show_header=True, padding=(0, 2))
        kt.add_column("server", style="bg")
        kt.add_column("size", style="dg", justify="right")
        kt.add_column("url", style="g", overflow="fold")
        for k in keys:
            kt.add_row(k["server"], f"{k['size']}b", k["url"])
        console.print(kt)

    pt = Table(border_style="bd",
               title="[bg]registration probes[/bg]",
               show_header=True, padding=(0, 2))
    pt.add_column("service", style="bg")
    pt.add_column("status", style="g")
    pt.add_column("code", style="dg", justify="right")
    for svc, status, code in sorted(probes, key=lambda x: x[0].lower()):
        pt.add_row(svc, status, str(code or "-"))
    console.print(pt)

    console.print()


def _export(email, mx, grav, rep, keys, probes):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", email)[:40]
    p = OUT_DIR / f"email_{safe}_{ts}.json"
    p.write_text(json.dumps({
        "email": email,
        "mx": mx,
        "gravatar": grav,
        "emailrep": rep,
        "pgp_keys": keys,
        "probes": [{"service": s, "status": st, "code": c}
                   for s, st, c in probes],
        "generated": datetime.now().isoformat(timespec="seconds"),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]\n")


def run():
    email = input("  email >> ").strip().lower()
    if not _valid(email):
        print("  [!] invalid email")
        return

    domain = email.split("@", 1)[1].lower()

    with tqdm(total=3, desc="basics", ncols=60, bar_format=BAR_FMT) as bar:
        mx = _mx(domain); bar.update(1)
        grav = _gravatar(email); bar.update(1)
        rep = _emailrep(email); bar.update(1)

    with tqdm(total=2, desc="keys + probes", ncols=60,
              bar_format=BAR_FMT) as bar:
        keys = _pgp_keys(email); bar.update(1)
        probes = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = [
                ex.submit(_probe, svc, ep, m, body_fn, mk, email)
                for svc, ep, m, body_fn, mk in PROBES
            ]
            for f in as_completed(futs):
                probes.append(f.result())
        bar.update(1)

    _render(email, mx, grav, rep, keys, probes)

    if input("  export? [y/N] >> ").strip().lower() == "y":
        _export(email, mx, grav, rep, keys, probes)
