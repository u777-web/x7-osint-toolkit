"""
username_enum.py — Username enumeration across many platforms.

Each platform carries its own detection rule (status codes + body
signatures) so false positives don't leak in. Threads are pooled with
per-thread sessions, retry/backoff enabled, and exports go to json/csv.
"""

import csv
import json
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme
from tqdm import tqdm

console = Console(theme=Theme({
    "g": "grey70", "dg": "grey50", "bg": "grey93", "bd": "grey37",
}))

BAR_FMT = "\033[38;5;245m  {desc} |{bar}| {percentage:3.0f}%\033[0m"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; rv:122.0) Gecko/20100101 Firefox/122.0",
]

OUT_DIR = Path.home() / ".osinttool" / "exports"
OUT_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class Platform:
    name: str
    url: str
    tags: tuple = ()
    method: str = "GET"
    positive_status: tuple = (200,)
    negative_status: tuple = (404,)
    positive_strings: tuple = ()
    negative_strings: tuple = ()
    follow_redirects: bool = True
    headers: dict = field(default_factory=dict)
    payload: Optional[dict] = None


# {u} is replaced with the username.
PLATFORMS = [
    # ---------------- dev ----------------
    Platform("GitHub", "https://github.com/{u}", tags=("dev",),
             negative_strings=("not found",)),
    Platform("GitLab", "https://gitlab.com/{u}", tags=("dev",)),
    Platform("Bitbucket", "https://bitbucket.org/{u}/", tags=("dev",)),
    Platform("Codeberg", "https://codeberg.org/{u}", tags=("dev",)),
    Platform("SourceForge", "https://sourceforge.net/u/{u}/profile",
             tags=("dev",)),
    Platform("Replit", "https://replit.com/@{u}", tags=("dev",)),
    Platform("Codepen", "https://codepen.io/{u}", tags=("dev",)),
    Platform("DevTo", "https://dev.to/{u}", tags=("dev",)),
    Platform("HackerNews", "https://news.ycombinator.com/user?id={u}",
             tags=("dev",), negative_strings=("no such user",)),
    Platform("Keybase", "https://keybase.io/{u}", tags=("dev",)),
    Platform("StackOverflow", "https://stackoverflow.com/users/{u}",
             tags=("dev",), negative_status=(404,)),
    Platform("HuggingFace", "https://huggingface.co/{u}", tags=("dev",),
             negative_status=(404,)),
    Platform("DockerHub", "https://hub.docker.com/u/{u}", tags=("dev",),
             negative_status=(404,)),
    Platform("NPM", "https://www.npmjs.com/~{u}", tags=("dev",),
             negative_status=(404,)),
    Platform("Pypi", "https://pypi.org/user/{u}/", tags=("dev",),
             negative_status=(404,)),
    Platform("Codewars", "https://www.codewars.com/users/{u}", tags=("dev",),
             negative_status=(404,)),

    # ---------------- social ----------------
    Platform("Reddit", "https://www.reddit.com/user/{u}/about.json",
             tags=("social",), negative_status=(404,)),
    Platform("Twitter", "https://x.com/{u}", tags=("social",),
             negative_strings=("this account doesn’t exist",
                               "user not found",)),
    Platform("Instagram", "https://www.instagram.com/{u}/", tags=("social",),
             negative_strings=("sorry, this page isn't available",
                               "page not found",)),
    Platform("TikTok", "https://www.tiktok.com/@{u}", tags=("social",),
             negative_strings=("couldn't find this account",)),
    Platform("Telegram", "https://t.me/{u}", tags=("social",),
             negative_strings=("if you have telegram, you can contact",)),
    Platform("Pinterest", "https://www.pinterest.com/{u}/", tags=("social",)),
    Platform("Tumblr", "https://{u}.tumblr.com/", tags=("social",)),
    Platform("Mastodon", "https://mastodon.social/@{u}", tags=("social",)),
    Platform("Xing", "https://www.xing.com/profile/{u}", tags=("social",)),
    Platform("Threads", "https://www.threads.net/@{u}", tags=("social",),
             negative_strings=("sorry, this page isn't available",)),
    Platform("VKontakte", "https://vk.com/{u}", tags=("social",)),
    Platform("Gab", "https://gab.com/{u}", tags=("social",)),
    Platform("Minds", "https://www.minds.com/{u}", tags=("social",)),
    Platform("TruthSocial", "https://truthsocial.com/@{u}", tags=("social",)),
    Platform("Blogger", "https://{u}.blogspot.com", tags=("social",),
             negative_strings=("blog not found",)),
    Platform("Foursquare", "https://foursquare.com/{u}", tags=("social",)),

    # ---------------- media ----------------
    Platform("YouTube", "https://www.youtube.com/@{u}", tags=("media",),
             negative_strings=("this page isn't available",)),
    Platform("Twitch", "https://www.twitch.tv/{u}", tags=("media",)),
    Platform("Vimeo", "https://vimeo.com/{u}", tags=("media",)),
    Platform("SoundCloud", "https://soundcloud.com/{u}", tags=("media",)),
    Platform("Spotify", "https://open.spotify.com/user/{u}", tags=("media",)),
    Platform("LastFM", "https://www.last.fm/user/{u}", tags=("media",)),
    Platform("Bandcamp", "https://bandcamp.com/{u}", tags=("media",)),
    Platform("Mixcloud", "https://www.mixcloud.com/{u}/", tags=("media",)),
    Platform("ArtStation", "https://www.artstation.com/{u}", tags=("media",)),
    Platform("DeviantArt", "https://www.deviantart.com/{u}", tags=("media",)),
    Platform("Giphy", "https://giphy.com/{u}", tags=("media",)),
    Platform("CDBaby", "https://store.cdbaby.com/{u}", tags=("media",)),

    # ---------------- gaming ----------------
    Platform("Steam", "https://steamcommunity.com/id/{u}", tags=("gaming",)),
    Platform("Roblox", "https://www.roblox.com/user.aspx?username={u}",
             tags=("gaming",)),
    Platform("Xbox", "https://xboxgamertag.com/search/{u}", tags=("gaming",)),
    Platform("PSN", "https://psnprofiles.com/{u}", tags=("gaming",)),
    Platform("Chess", "https://www.chess.com/member/{u}", tags=("gaming",)),
    Platform("Lichess", "https://lichess.org/@/{u}", tags=("gaming",)),
    Platform("Minecraft", "https://namemc.com/search?q={u}", tags=("gaming",),
             negative_strings=("no player with this name",)),
    Platform("Osu", "https://osu.ppy.sh/users/{u}", tags=("gaming",)),
    Platform("Kongregate", "https://www.kongregate.com/accounts/{u}",
             tags=("gaming",)),
    Platform("ItchIO", "https://{u}.itch.io", tags=("gaming",)),
    Platform("GameJolt", "https://gamejolt.com/@{u}", tags=("gaming",)),
    Platform("Speedrun", "https://www.speedrun.com/user/{u}",
             tags=("gaming",)),

    # ---------------- pro ----------------
    Platform("LinkedIn", "https://www.linkedin.com/in/{u}", tags=("pro",),
             negative_status=(404,)),
    Platform("AngelList", "https://angel.co/u/{u}", tags=("pro",)),
    Platform("Behance", "https://www.behance.net/{u}", tags=("pro",)),
    Platform("Dribbble", "https://dribbble.com/{u}", tags=("pro",)),
    Platform("Medium", "https://medium.com/@{u}", tags=("pro",)),
    Platform("Substack", "https://{u}.substack.com", tags=("pro",)),
    Platform("AboutMe", "https://about.me/{u}", tags=("pro",)),

    # ---------------- forums ----------------
    Platform("Disqus", "https://disqus.com/{u}", tags=("forums",)),
    Platform("Quora", "https://www.quora.com/profile/{u}", tags=("forums",)),
    Platform("HackTheBox", "https://app.hackthebox.com/profile/{u}",
             tags=("forums",)),
    Platform("TryHackMe", "https://tryhackme.com/p/{u}", tags=("forums",)),
    Platform("Kaggle", "https://www.kaggle.com/{u}", tags=("forums",),
             negative_status=(404,)),

    # ---------------- crypto ----------------
    Platform("Etherscan", "https://etherscan.io/address/{u}",
             tags=("crypto",)),
    Platform("OpenSea", "https://opensea.io/{u}", tags=("crypto",),
             negative_status=(404,)),
    Platform("Rarible", "https://rarible.com/{u}", tags=("crypto",)),
    Platform("CoinMarketCap",
             "https://coinmarketcap.com/community/user/{u}",
             tags=("crypto",)),

    # ---------------- other ----------------
    Platform("Patreon", "https://www.patreon.com/{u}", tags=("other",)),
    Platform("Kofi", "https://ko-fi.com/{u}", tags=("other",)),
    Platform("BuyMeACoffee", "https://buymeacoffee.com/{u}", tags=("other",)),
    Platform("Linktree", "https://linktr.ee/{u}", tags=("other",)),
    Platform("Imgur", "https://imgur.com/user/{u}", tags=("other",)),
    Platform("Flickr", "https://www.flickr.com/people/{u}", tags=("other",)),
    Platform("Gravatar", "https://gravatar.com/{u}", tags=("other",)),
    Platform("Snapchat", "https://www.snapchat.com/add/{u}", tags=("other",)),
    Platform("Duolingo", "https://www.duolingo.com/profile/{u}",
             tags=("other",)),
    Platform("Goodreads", "https://www.goodreads.com/{u}", tags=("other",)),
    Platform("Wattpad", "https://www.wattpad.com/user/{u}", tags=("other",)),
    Platform("MyAnimeList", "https://myanimelist.net/profile/{u}",
             tags=("other",)),
    Platform("Trakt", "https://trakt.tv/users/{u}", tags=("other",)),
    Platform("Letterboxd", "https://letterboxd.com/{u}/", tags=("other",)),
    Platform("Strava", "https://www.strava.com/athletes/{u}",
             tags=("other",)),
    Platform("Venmo", "https://account.venmo.com/u/{u}", tags=("other",)),
    Platform("CashApp", "https://cash.app/${u}", tags=("other",)),
    Platform("PayPal", "https://www.paypal.com/paypalme/{u}",
             tags=("other",)),
    Platform("Bitly", "https://bit.ly/{u}", tags=("other",)),
    Platform("Beacons", "https://beacons.ai/{u}", tags=("other",)),
    Platform("Carrd", "https://{u}.carrd.co", tags=("other",)),
]


@dataclass
class Result:
    platform: str
    url: str
    status: str  # FOUND / MISSING / UNKNOWN / ERROR
    code: Optional[int] = None
    elapsed: float = 0.0
    tags: tuple = ()


_thread_local = threading.local()


def _session():
    if not hasattr(_thread_local, "sess"):
        s = requests.Session()
        retry = Retry(
            total=2, backoff_factor=0.4,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "POST"],
        )
        s.mount("https://", HTTPAdapter(max_retries=retry))
        s.mount("http://", HTTPAdapter(max_retries=retry))
        _thread_local.sess = s
    return _thread_local.sess


def _headers(extra=None):
    h = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": ("text/html,application/xhtml+xml,application/xml;"
                   "q=0.9,*/*;q=0.8"),
    }
    if extra:
        h.update(extra)
    return h


def _check(platform: Platform, username: str, timeout=10) -> Result:
    url = platform.url.format(u=username)
    s = _session()
    start = time.time()
    try:
        if platform.method.upper() == "POST":
            r = s.post(url, data=platform.payload,
                       headers=_headers(platform.headers),
                       timeout=timeout,
                       allow_redirects=platform.follow_redirects)
        else:
            r = s.get(url, headers=_headers(platform.headers),
                      timeout=timeout,
                      allow_redirects=platform.follow_redirects)
        elapsed = time.time() - start
        text = r.text.lower()

        for sig in platform.negative_strings:
            if sig in text:
                return Result(platform.name, url, "MISSING",
                              r.status_code, elapsed, platform.tags)

        for sig in platform.positive_strings:
            if sig in text:
                return Result(platform.name, url, "FOUND",
                              r.status_code, elapsed, platform.tags)

        if r.status_code in platform.positive_status:
            return Result(platform.name, url, "FOUND",
                          r.status_code, elapsed, platform.tags)
        if r.status_code in platform.negative_status:
            return Result(platform.name, url, "MISSING",
                          r.status_code, elapsed, platform.tags)
        return Result(platform.name, url, "UNKNOWN",
                      r.status_code, elapsed, platform.tags)
    except requests.RequestException:
        return Result(platform.name, url, "ERROR",
                      None, time.time() - start, platform.tags)


def _render(results, username):
    found = [r for r in results if r.status == "FOUND"]
    console.print(Panel.fit(
        f"[bg]USERNAME ENUM[/bg]  [dg]{username}[/dg]  ·  "
        f"[g]{len(found)}/{len(results)} found[/g]",
        border_style="bd", padding=(0, 2),
    ))

    if not found:
        console.print("[dg]  no matches[/dg]\n")
        return

    t = Table(border_style="bd", show_header=True, padding=(0, 2))
    t.add_column("#", style="dg", justify="right")
    t.add_column("platform", style="bg")
    t.add_column("tags", style="dg")
    t.add_column("code", style="dg")
    t.add_column("url", style="g", overflow="fold")
    for i, r in enumerate(sorted(found, key=lambda x: x.platform.lower()), 1):
        t.add_row(str(i), r.platform, ",".join(r.tags),
                  str(r.code or "-"), r.url)
    console.print(t)
    console.print()


def _export(username, results):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = f"enum_{username}_{ts}"

    payload = {
        "username": username,
        "scanned": len(results),
        "found": sum(1 for r in results if r.status == "FOUND"),
        "results": [r.__dict__ for r in results],
        "generated": datetime.now().isoformat(timespec="seconds"),
    }
    jp = OUT_DIR / f"{stem}.json"
    jp.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                  encoding="utf-8")

    cp = OUT_DIR / f"{stem}.csv"
    with cp.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["platform", "status", "code", "elapsed", "tags", "url"])
        for r in results:
            w.writerow([r.platform, r.status, r.code or "",
                        f"{r.elapsed:.3f}", ",".join(r.tags), r.url])

    console.print(f"[dg]  exported → {jp}[/dg]")
    console.print(f"[dg]  exported → {cp}[/dg]\n")


def run():
    username = input("  username >> ").strip()
    if not username:
        print("  [!] empty username")
        return

    results = []
    with tqdm(total=len(PLATFORMS), desc=f"scanning {username}",
              ncols=60, bar_format=BAR_FMT) as bar:
        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = [ex.submit(_check, p, username) for p in PLATFORMS]
            for f in as_completed(futs):
                results.append(f.result())
                bar.update(1)

    _render(results, username)

    if input("  export results? [y/N] >> ").strip().lower() == "y":
        _export(username, results)
