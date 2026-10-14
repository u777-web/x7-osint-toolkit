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


def _alias(raw: str) -> str:
    return raw.strip().lower()


def _email(raw: str) -> str:
    return raw.strip().lower()


def _phone(raw: str) -> str:
    return "".join(ch for ch in raw if ch.isdigit())


def _loc(raw: str) -> str:
    return quote(raw.strip(), safe="")


def _pivot_links(p: dict):
    links = []
    a, e, ph, l = p["alias"], p["email"], p["phone"], p["location"]

    if a:
        links += [
            ("Alias", "GitHub",      f"https://github.com/{a}"),
            ("Alias", "Twitter/X",   f"https://x.com/{a}"),
            ("Alias", "Reddit",      f"https://www.reddit.com/user/{a}"),
            ("Alias", "Telegram",    f"https://t.me/{a}"),
            ("Alias", "Instagram",   f"https://www.instagram.com/{a}/"),
            ("Alias", "TikTok",      f"https://www.tiktok.com/@{a}"),
            ("Alias", "Keybase",     f"https://keybase.io/{a}"),
            ("Alias", "WhatsMyName", f"https://whatsmyname.app/?q={a}"),
            ("Alias", "Namechk",     f"https://namechk.com/{a}"),
        ]

    if e:
        links += [
            ("Email", "HIBP",      f"https://haveibeenpwned.com/account/{e}"),
            ("Email", "Hunter.io", f"https://hunter.io/email-verifier/{e}"),
            ("Email", "EmailRep",  f"https://emailrep.io/{e}"),
            ("Email", "Gravatar",  f"https://gravatar.com/{e}"),
        ]

    if ph:
        links += [
            ("Phone", "WhatsApp",   f"https://wa.me/{ph}"),
            ("Phone", "Truecaller", f"https://www.truecaller.com/search/global/{ph}"),
            ("Phone", "TruePeople", f"https://www.truepeoplesearch.com/results?phoneno={ph}"),
        ]

    if l:
        links += [
            ("Location", "Google Maps",   f"https://www.google.com/maps/search/{l}"),
            ("Location", "OpenStreetMap", f"https://www.openstreetmap.org/search?query={l}"),
        ]

    return links


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
        "location": input("  location          >> "),
        "notes":    input("  notes             >> "),
    }

    profile = {
        "alias":    _alias(raw["alias"]),
        "email":    _email(raw["email"]),
        "phone":    _phone(raw["phone"]),
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
        lt.add_column("service", style="g")
        lt.add_column("url",     style="g", overflow="fold")
        for field, svc, url in links:
            lt.add_row(field, svc, url)
        console.print(lt)
    else:
        console.print("[dg]  no pivots — provide at least one field[/dg]")

    console.print()