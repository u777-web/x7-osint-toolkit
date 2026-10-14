"""
correlation.py — field correlation + pivot engine.

Combines loose identifiers (alias, email, phone, name, domain, IP,
location) into a single target profile and emits ready-to-click pivot
links for each. Pure URL construction — no API keys required to run.
"""

import time
from urllib.parse import quote

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme

console = Console(
    theme=Theme(
        {
            "g":  "grey70",
            "dg": "grey50",
            "bg": "grey93",
            "bd": "grey37",
        }
    )
)


# ---------------- normalizers ----------------

def _alias(raw: str) -> str:
    return raw.strip().lower().lstrip("@")


def _email(raw: str) -> str:
    return raw.strip().lower()


def _phone(raw: str) -> str:
    return "".join(ch for ch in raw if ch.isdigit())


def _loc(raw: str) -> str:
    return quote(raw.strip(), safe="")


def _name(raw: str) -> str:
    return raw.strip()


def _domain(raw: str) -> str:
    d = raw.strip().lower()
    for pre in ("http://", "https://"):
        if d.startswith(pre):
            d = d[len(pre):]
    return d.rstrip("/").split("/")[0]


def _ip(raw: str) -> str:
    return raw.strip()


# ---------------- pivot builders ----------------

def _pivot_alias(a: str):
    if not a:
        return []
    return [
        ("Alias", "GitHub",        f"https://github.com/{a}"),
        ("Alias", "GitLab",        f"https://gitlab.com/{a}"),
        ("Alias", "Twitter/X",     f"https://x.com/{a}"),
        ("Alias", "Reddit",        f"https://www.reddit.com/user/{a}"),
        ("Alias", "Telegram",      f"https://t.me/{a}"),
        ("Alias", "Instagram",     f"https://www.instagram.com/{a}/"),
        ("Alias", "TikTok",        f"https://www.tiktok.com/@{a}"),
        ("Alias", "Keybase",       f"https://keybase.io/{a}"),
        ("Alias", "HackerNews",    f"https://news.ycombinator.com/user?id={a}"),
        ("Alias", "Whatsmyname",   f"https://whatsmyname.app/?q={a}"),
        ("Alias", "Namechk",       f"https://namechk.com/{a}"),
        ("Alias", "Sherlock (web)",f"https://sherlock-project.github.io/?q={a}"),
        ("Alias", "IDCrawl",       f"https://www.idcrawl.com/u/{a}"),
    ]


def _pivot_email(e: str):
    if not e:
        return []
    return [
        ("Email", "HIBP",          f"https://haveibeenpwned.com/account/{e}"),
        ("Email", "Hunter.io",     f"https://hunter.io/email-verifier/{e}"),
        ("Email", "EmailRep",      f"https://emailrep.io/{e}"),
        ("Email", "Gravatar",      f"https://gravatar.com/{e}"),
        ("Email", "Epieos",        f"https://epieos.com/?q={e}"),
        ("Email", "GHunt (repo)",  "https://github.com/mxrch/GHunt"),
        ("Email", "Leak-Lookup",   f"https://leak-lookup.com/search?type=email_address&query={e}"),
        ("Email", "DeHashed (web)",f"https://dehashed.com/search?query={e}"),
    ]


def _pivot_phone(ph: str):
    if not ph:
        return []
    return [
        ("Phone", "WhatsApp",      f"https://wa.me/{ph}"),
        ("Phone", "Truecaller",    f"https://www.truecaller.com/search/global/{ph}"),
        ("Phone", "TruePeople",    f"https://www.truepeoplesearch.com/results?phoneno={ph}"),
        ("Phone", "FastPeople",    f"https://www.fastpeoplesearch.com/{ph}"),
        ("Phone", "ThatsThem",     f"https://thatsthem.com/phone/{ph}"),
        ("Phone", "Spokeo",        f"https://www.spokeo.com/phone-search/{ph}"),
        ("Phone", "NumLookup",     f"https://www.numlookup.com/?q={ph}"),
        ("Phone", "Whitepages",    f"https://www.whitepages.com/phone/{ph}"),
    ]


def _pivot_location(l: str):
    if not l:
        return []
    return [
        ("Location", "Google Maps",   f"https://www.google.com/maps/search/{l}"),
        ("Location", "OpenStreetMap", f"https://www.openstreetmap.org/search?query={l}"),
        ("Location", "Bing Maps",     f"https://www.bing.com/maps?q={l}"),
        ("Location", "Geohack",       f"https://geohack.toolforge.org/geohack.php?params={l}"),
    ]


def _pivot_name(n: str):
    if not n:
        return []
    q = quote(n, safe="")
    q_plus = n.replace(" ", "+")
    return [
        ("Name", "Google Search",  f'https://www.google.com/search?q="{q_plus}"'),
        ("Name", "Bing Search",    f'https://www.bing.com/search?q="{q_plus}"'),
        ("Name", "DuckDuckGo",     f'https://duckduckgo.com/?q="{q_plus}"'),
        ("Name", "Whitepages",     f"https://www.whitepages.com/name/{q_plus}"),
        ("Name", "TruePeople",     f"https://www.truepeoplesearch.com/results?name={q_plus}"),
        ("Name", "FastPeople",     f"https://www.fastpeoplesearch.com/name/{q_plus}"),
        ("Name", "Spokeo",         f"https://www.spokeo.com/{q_plus}"),
        ("Name", "WebMii",         f"https://webmii.com/people?n={q_plus}"),
        ("Name", "ThatsThem",      f"https://thatsthem.com/name/{q_plus}"),
        ("Name", "Radaris",        f"https://radaris.com/p/{q_plus}"),
    ]


def _pivot_domain(d: str):
    if not d:
        return []
    return [
        ("Domain", "VirusTotal",      f"https://www.virustotal.com/gui/domain/{d}"),
        ("Domain", "SecurityTrails",  f"https://securitytrails.com/domain/{d}"),
        ("Domain", "Wayback Machine", f"https://web.archive.org/web/*/{d}"),
        ("Domain", "Censys Domain",   f"https://search.censys.io/domains?q={d}"),
        ("Domain", "urlscan.io",      f"https://urlscan.io/domain/{d}"),
        ("Domain", "Shodan",          f"https://www.shodan.io/search?query={d}"),
        ("Domain", "DNSdumpster",     f"https://dnsdumpster.com/"),
        ("Domain", "crt.sh",          f"https://crt.sh/?q={d}"),
        ("Domain", "WHOIS (ICANN)",   f"https://lookup.icann.org/en/lookup?name={d}"),
        ("Domain", "ViewDNS",         f"https://viewdns.info/whois/?domain={d}"),
        ("Domain", "mxtoolbox",       f"https://mxtoolbox.com/SuperTool.aspx?action=a%3a{d}"),
        ("Domain", "BuiltWith",       f"https://builtwith.com/{d}"),
        ("Domain", "SimilarWeb",      f"https://www.similarweb.com/website/{d}/"),
        ("Domain", "AbuseIPDB",       f"https://www.abuseipdb.com/whois/{d}"),
    ]


def _pivot_ip(ip: str):
    if not ip:
        return []
    return [
        ("IP", "Shodan",        f"https://www.shodan.io/host/{ip}"),
        ("IP", "IPinfo",        f"https://ipinfo.io/{ip}"),
        ("IP", "Censys",        f"https://search.censys.io/hosts/{ip}"),
        ("IP", "VirusTotal",    f"https://www.virustotal.com/gui/ip-address/{ip}"),
        ("IP", "AbuseIPDB",     f"https://www.abuseipdb.com/check/{ip}"),
        ("IP", "GreyNoise",     f"https://viz.greynoise.io/ip/{ip}"),
        ("IP", "AlienVault OTX",f"https://otx.alienvault.com/indicator/ip/{ip}"),
        ("IP", "urlscan.io",    f"https://urlscan.io/ip/{ip}"),
        ("IP", "BGPView",       f"https://bgpview.io/ip/{ip}"),
        ("IP", "ViewDNS revIP", f"https://viewdns.info/reverseip/?host={ip}"),
        ("IP", "HackerTarget",  f"https://hackertarget.com/reverse-ip-lookup/?q={ip}"),
        ("IP", "ThreatCrowd",   f"https://www.threatminer.org/host.php?q={ip}"),
        ("IP", "RIPE Stat",     f"https://stat.ripe.net/{ip}"),
    ]


def _pivot_links(p: dict):
    links = []
    links += _pivot_alias(p["alias"])
    links += _pivot_email(p["email"])
    links += _pivot_phone(p["phone"])
    links += _pivot_name(p["name"])
    links += _pivot_domain(p["domain"])
    links += _pivot_ip(p["ip"])
    links += _pivot_location(p["location"])
    return links


# ---------------- runner ----------------

def run():
    console.print(
        Panel.fit(
            "[bg]CORRELATION ENGINE[/bg]\n[dg]combine fields into a target profile[/dg]",
            border_style="bd",
            padding=(0, 2),
        )
    )

    raw = {
        "alias":    input("  alias / handle    >> "),
        "email":    input("  email             >> "),
        "phone":    input("  phone             >> "),
        "name":     input("  full name         >> "),
        "domain":   input("  domain / website  >> "),
        "ip":       input("  ip address        >> "),
        "location": input("  location          >> "),
        "notes":    input("  notes             >> "),
    }

    profile = {
        "alias":    _alias(raw["alias"]),
        "email":    _email(raw["email"]),
        "phone":    _phone(raw["phone"]),
        "name":     _name(raw["name"]),
        "domain":   _domain(raw["domain"]),
        "ip":       _ip(raw["ip"]),
        "location": _loc(raw["location"]),
        "notes":    raw["notes"].strip(),
    }

    with console.status("[dg]correlating data...[/dg]", spinner="dots"):
        time.sleep(1.2)

    pt = Table(
        title="[bg]profile[/bg]",
        border_style="bd",
        title_style="bg",
        show_header=False,
        padding=(0, 2),
    )
    pt.add_column("field", style="dg", no_wrap=True)
    pt.add_column("value", style="g")
    for k, v in profile.items():
        if v:
            pt.add_row(k, v)
    console.print(pt)

    links = _pivot_links(profile)
    if links:
        lt = Table(
            title="[bg]pivot links[/bg]",
            border_style="bd",
            title_style="bg",
            show_header=True,
            padding=(0, 2),
        )
        lt.add_column("field",   style="dg")
        lt.add_column("service", style="g", no_wrap=True)
        lt.add_column("url",     style="g", overflow="fold")
        for field, svc, url in links:
            lt.add_row(field, svc, url)
        console.print(lt)
    else:
        console.print("[dg]  no pivots — provide at least one field[/dg]")

    console.print()
