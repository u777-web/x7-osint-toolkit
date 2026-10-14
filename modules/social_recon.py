"""
social_recon.py — Social media footprint aggregation.

Given a handle or display name, this module:
  · walks a curated set of social platforms
  · pulls avatar URLs (Gravatar md5, unavatar.io fallback)
  · probes Wayback Machine for historical captures
  · generates targeted dork queries for Google/Bing/Yandex
  · correlates handle variants (dots, underscores, digits)
  · exports everything as json
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

BAR_FMT = "\033[38;5;245m  {desc} |{bar}| {percentage:3.0f}%\033[0m"
OUT_DIR = Path.home() / ".osinttoolkit" / "exports"
OUT_DIR.mkdir(parents=True, exist_ok=True)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/122.0 Safari/537.36")


PLATFORMS = [
    # name, profile url, tags, negative signatures
    ("Instagram", "https://www.instagram.com/{u}/", ("social",),
     ("sorry, this page isn't available", "page not found")),
    ("Twitter/X", "https://x.com/{u}", ("social",),
     ("this account doesn’t exist", "user not found")),
    ("TikTok", "https://www.tiktok.com/@{u}", ("social",),
     ("couldn't find this account",)),
    ("Facebook", "https://www.facebook.com/{u}", ("social",),
     ("page isn't available", "content isn't available")),
    ("Reddit", "https://www.reddit.com/user/{u}", ("social",),
     ("page not found",)),
    ("Pinterest", "https://www.pinterest.com/{u}/", ("social",)),
    ("Tumblr", "https://{u}.tumblr.com", ("social",)),
    ("Snapchat", "https://www.snapchat.com/add/{u}", ("social",)),
    ("Threads", "https://www.threads.net/@{u}", ("social",),
     ("page not found",)),
    ("Bluesky", "https://bsky.app/profile/{u}", ("social",)),
    ("Mastodon", "https://mastodon.social/@{u}", ("social",)),
    ("Telegram", "https://t.me/{u}", ("social",),
     ("if you have telegram, you can contact",)),
    ("Discord", "https://discord.com/users/{u}", ("social",)),

    ("YouTube", "https://www.youtube.com/@{u}", ("media",),
     ("this page isn't available",)),
    ("Twitch", "https://www.twitch.tv/{u}", ("media",)),
    ("Vimeo", "https://vimeo.com/{u}", ("media",)),
    ("SoundCloud", "https://soundcloud.com/{u}", ("media",)),
    ("Spotify", "https://open.spotify.com/user/{u}", ("media",)),
    ("Bandcamp", "https://bandcamp.com/{u}", ("media",)),

    ("GitHub", "https://github.com/{u}", ("dev",), ("not found",)),
    ("GitLab", "https://gitlab.com/{u}", ("dev",)),
    ("Codeberg", "https://codeberg.org/{u}", ("dev",)),
    ("Bitbucket", "https://bitbucket.org/{u}/", ("dev",)),
    ("Keybase", "https://keybase.io/{u}", ("dev",)),
    ("Replit", "https://replit.com/@{u}", ("dev",)),
    ("Codepen", "https://codepen.io/{u}", ("dev",)),
    ("DevTo", "https://dev.to/{u}", ("dev",)),

    ("Steam", "https://steamcommunity.com/id/{u}", ("gaming",)),
    ("Roblox", "https://www.roblox.com/user.aspx?username={u}", ("gaming",)),
    ("Xbox", "https://xboxgamertag.com/search/{u}", ("gaming",)),
    ("PSN", "https://psnprofiles.com/{u}", ("gaming",)),
    ("Chess", "https://www.chess.com/member/{u}", ("gaming",)),
    ("Lichess", "https://lichess.org/@/{u}", ("gaming",)),

    ("LinkedIn", "https://www.linkedin.com/in/{u}", ("pro",)),
    ("Medium", "https://medium.com/@{u}", ("pro",)),
    ("Substack", "https://{u}.substack.com", ("pro",)),
    ("Behance", "https://www.behance.net/{u}", ("pro",)),
    ("Dribbble", "https://dribbble.com/{u}", ("pro",)),
    ("AboutMe", "https://about.me/{u}", ("pro",)),

    ("Patreon", "https://www.patreon.com/{u}", ("other",)),
    ("Kofi", "https://ko-fi.com/{u}", ("other",)),
    ("Linktree", "https://linktr.ee/{u}", ("other",)),
    ("Imgur", "https://imgur.com/user/{u}", ("other",)),
    ("Flickr", "https://www.flickr.com/people/{u}", ("other",)),
    ("Letterboxd", "https://letterboxd.com/{u}/", ("other",)),
    ("Strava", "https://www.strava.com/athletes/{u}", ("other",)),
    ("Venmo", "https://account.venmo.com/u/{u}", ("other",)),
]


def _variants(handle: str):
    """generate plausible handle variants"""
    h = handle.strip().lower()
    out = {h}
    if "." in h:
        out.add(h.replace(".", "_"))
        out.add(h.replace(".", ""))
    if "_" in h:
        out.add(h.replace("_", "."))
        out.add(h.replace("_", ""))
    base = re.sub(r"[._\d]+$", "", h)
    if base and base != h:
        out.add(base)
    return sorted(out)


# ───────────────────────── checks ─────────────────────────

def _check_platform(plat, handle, timeout=9):
    name, url_t, tags, negs = plat
    url = url_t.format(u=handle)
    try:
        r = requests.get(
            url,
            headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"},
            timeout=timeout,
            allow_redirects=True,
        )
        text = r.text.lower()
        if any(s in text for s in negs):
            return (name, url, "MISSING", r.status_code, tags)
        if r.status_code == 200:
            return (name, url, "FOUND", r.status_code, tags)
        if r.status_code == 404:
            return (name, url, "MISSING", r.status_code, tags)
        return (name, url, f"HTTP {r.status_code}", r.status_code, tags)
    except Exception:
        return (name, url, "ERROR", None, tags)


def _gravatar(handle_or_email):
    h = hashlib.md5(handle_or_email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{h}?d=404"
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=8)
        if r.status_code == 200:
            return f"https://www.gravatar.com/{h}"
    except Exception:
        pass
    return None


def _unavatar(handle):
    for src in ("twitter", "github", "instagram", "reddit"):
        url = f"https://unavatar.io/{src}/{handle}"
        try:
            r = requests.get(url, headers={"User-Agent": UA},
                             timeout=8, allow_redirects=True)
            if r.status_code == 200 and r.headers.get("content-type", "").startswith("image"):
                return url
        except Exception:
            continue
    return None


def _wayback(url):
    try:
        r = requests.get(
            "https://archive.org/wayback/available",
            params={"url": url},
            headers={"User-Agent": UA},
            timeout=10,
        )
        d = r.json()
        snap = d.get("archived_snapshots", {}).get("closest")
        if snap and snap.get("available"):
            return snap.get("url")
    except Exception:
        pass
    return None


# ───────────────────────── dorks ─────────────────────────

DORK_TEMPLATES = [
    '"{h}" site:linkedin.com',
    '"{h}" site:twitter.com OR site:x.com',
    '"{h}" site:instagram.com',
    '"{h}" site:facebook.com',
    '"{h}" site:reddit.com',
    '"{h}" site:github.com',
    '"{h}" site:pastebin.com',
    '"{h}" site:docs.google.com',
    '"{h}" filetype:pdf',
    '"{h}" filetype:docx',
    '"{h}" -site:instagram.com -site:twitter.com',
    '"{h}" "@gmail.com" OR "@outlook.com" OR "@yahoo.com"',
    '"{h}" inurl:cv OR inurl:resume',
    '"{h}" intitle:"index of"',
]


def _dorks(handle):
    return [d.format(h=handle) for d in DORK_TEMPLATES]


# ───────────────────────── render ─────────────────────────

def _render(handle, variants, results, avatars, waybacks):
    found = [r for r in results if r[2] == "FOUND"]

    console.print(Panel.fit(
        f"[bg]SOCIAL RECON[/bg]  [dg]{handle}[/dg]  ·  "
        f"[g]{len(found)}/{len(results)} hits[/g]",
        border_style="bd", padding=(0, 2),
    ))

    if variants and len(variants) > 1:
        console.print(f"[dg]  variants tested: "
                      f"{', '.join(variants)}[/dg]\n")

    if found:
        t = Table(border_style="bd", show_header=True, padding=(0, 2))
        t.add_column("#", style="dg", justify="right")
        t.add_column("platform", style="bg")
        t.add_column("tags", style="dg")
        t.add_column("url", style="g", overflow="fold")
        for i, (name, url, _, _, tags) in enumerate(
            sorted(found, key=lambda x: x[0].lower()), 1
        ):
            t.add_row(str(i), name, ",".join(tags), url)
        console.print(t)

    if avatars:
        at = Table(border_style="bd", title="[bg]avatars[/bg]",
                   show_header=True, padding=(0, 2))
        at.add_column("source", style="dg")
        at.add_column("url", style="g", overflow="fold")
        for k, v in avatars.items():
            if v:
                at.add_row(k, v)
        console.print(at)

    if waybacks:
        wt = Table(border_style="bd", title="[bg]wayback captures[/bg]",
                   show_header=True, padding=(0, 2))
        wt.add_column("platform", style="dg")
        wt.add_column("snapshot", style="g", overflow="fold")
        for k, v in waybacks.items():
            wt.add_row(k, v)
        console.print(wt)

    dt = Table(border_style="bd", title="[bg]suggested dorks[/bg]",
               show_header=False, padding=(0, 2))
    dt.add_column("q", style="g", overflow="fold")
    for d in _dorks(handle):
        dt.add_row(d)
    console.print(dt)

    console.print()


def _export(handle, results, avatars, waybacks):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", handle)[:32]
    p = OUT_DIR / f"social_{safe}_{ts}.json"
    p.write_text(json.dumps({
        "handle": handle,
        "results": [
            {"platform": r[0], "url": r[1], "status": r[2],
             "code": r[3], "tags": list(r[4])}
            for r in results
        ],
        "avatars": avatars,
        "wayback": waybacks,
        "dorks": _dorks(handle),
        "generated": datetime.now().isoformat(timespec="seconds"),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]\n")


# ───────────────────────── entry ─────────────────────────

def run():
    handle = input("  handle >> ").strip()
    if not handle:
        print("  [!] empty handle")
        return

    variants = _variants(handle)
    primary = variants[0]

    results = []
    with tqdm(total=len(PLATFORMS), desc=f"scanning {primary}",
              ncols=60, bar_format=BAR_FMT) as bar:
        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = [ex.submit(_check_platform, p, primary) for p in PLATFORMS]
            for f in as_completed(futs):
                results.append(f.result())
                bar.update(1)

    with tqdm(total=3, desc="avatars + archive",
              ncols=60, bar_format=BAR_FMT) as bar:
        avatars = {
            "gravatar": _gravatar(f"{primary}@gmail.com"),
            "unavatar": _unavatar(primary),
        }
        bar.update(2)

        found_urls = [r[1] for r in results if r[2] == "FOUND"][:5]
        waybacks = {}
        for url in found_urls:
            snap = _wayback(url)
            if snap:
                waybacks[url] = snap
            bar.update(0.34)
        bar.update(1)

    _render(primary, variants, results, avatars, waybacks)

    if input("  export results? [y/N] >> ").strip().lower() == "y":
        _export(primary, results, avatars, waybacks)
