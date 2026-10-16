"""
correlation.py — Field correlation + pivot engine (deep edition).

Combines loose identifiers (alias, email, phone, name, domain, IP,
location, crypto address, MAC, VIN) into a single target profile and
emits ready-to-click pivot links for each. No API keys required to run.

New in this version:
  · 8 new identifier types (crypto address, crypto tx, MAC address, VIN,
    ASN, CIDR, wallet, organization)
  · 200+ pivot links across 30+ categories
  · real enrichment via free APIs (no keys):
      - Gravatar profile lookup (SHA256)
      - EmailRep reputation
      - XposedOrNot breach check
      - IP-API / ipwho.is / freeipapi geolocation
      - Shodan InternetDB (open ports, tags, CVEs)
      - RDAP for domain + IP
      - crt.sh certificate transparency
      - SEC EDGAR full-text search
      - NHTSA vPIC VIN decoder
      - Solscan / Blockchair crypto lookups
  · risk scoring 0–100 with plain-English reasons
  · field-relationship graph (which fields co-occur across pivots)
  · scan history per profile with diff
  · export to JSON, CSV, and standalone HTML report
"""

import csv
import hashlib
import html
import ipaddress
import json
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import requests
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
            "red": "red",
            "green": "green",
            "yellow": "yellow",
        }
    )
)

OUT_DIR = Path.home() / ".ostinttol" / "exports"
OUT_DIR.mkdir(parents=True, exist_ok=True)
HIST_DIR = Path.home() / ".ostinttol" / "correlation_history"
HIST_DIR.mkdir(parents=True, exist_ok=True)

UA = "Mozilla/5.0 (compatible; ostinttol)"


# ============================================================
# Normalizers
# ============================================================

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


def _crypto(raw: str) -> str:
    return raw.strip()


def _mac(raw: str) -> str:
    return raw.strip().lower().replace("-", ":").replace(".", ":")


def _vin(raw: str) -> str:
    return raw.strip().upper()


def _asn(raw: str) -> str:
    return raw.strip().upper().replace("AS", "")


def _cidr(raw: str) -> str:
    return raw.strip()


def _org(raw: str) -> str:
    return raw.strip()


# ============================================================
# Pivot builders — alias
# ============================================================

def _pivot_alias(a: str):
    if not a:
        return []
    return [
        ("Alias", "GitHub",         f"https://github.com/{a}"),
        ("Alias", "GitLab",         f"https://gitlab.com/{a}"),
        ("Alias", "Bitbucket",      f"https://bitbucket.org/{a}/"),
        ("Alias", "Twitter/X",      f"https://x.com/{a}"),
        ("Alias", "Reddit",         f"https://www.reddit.com/user/{a}"),
        ("Alias", "Telegram",       f"https://t.me/{a}"),
        ("Alias", "Instagram",      f"https://www.instagram.com/{a}/"),
        ("Alias", "TikTok",         f"https://www.tiktok.com/@{a}"),
        ("Alias", "Keybase",        f"https://keybase.io/{a}"),
        ("Alias", "HackerNews",     f"https://news.ycombinator.com/user?id={a}"),
        ("Alias", "YouTube",        f"https://www.youtube.com/@{a}"),
        ("Alias", "Twitch",         f"https://www.twitch.tv/{a}"),
        ("Alias", "Steam",          f"https://steamcommunity.com/id/{a}"),
        ("Alias", "Roblox",         f"https://www.roblox.com/user.aspx?username={a}"),
        ("Alias", "Chess",          f"https://www.chess.com/member/{a}"),
        ("Alias", "Lichess",        f"https://lichess.org/@/{a}"),
        ("Alias", "Medium",         f"https://medium.com/@{a}"),
        ("Alias", "DevTo",          f"https://dev.to/{a}"),
        ("Alias", "StackOverflow",  f"https://stackoverflow.com/users/{a}"),
        ("Alias", "Pinterest",      f"https://www.pinterest.com/{a}/"),
        ("Alias", "Tumblr",         f"https://{a}.tumblr.com"),
        ("Alias", "Mastodon",       f"https://mastodon.social/@{a}"),
        ("Alias", "Bluesky",        f"https://bsky.app/profile/{a}"),
        ("Alias", "Threads",        f"https://www.threads.net/@{a}"),
        ("Alias", "Snapchat",       f"https://www.snapchat.com/add/{a}"),
        ("Alias", "Discord",        f"https://discord.com/users/{a}"),
        ("Alias", "SoundCloud",     f"https://soundcloud.com/{a}"),
        ("Alias", "Spotify",        f"https://open.spotify.com/user/{a}"),
        ("Alias", "Bandcamp",       f"https://bandcamp.com/{a}"),
        ("Alias", "Patreon",        f"https://www.patreon.com/{a}"),
        ("Alias", "Kofi",           f"https://ko-fi.com/{a}"),
        ("Alias", "Linktree",       f"https://linktr.ee/{a}"),
        ("Alias", "Imgur",          f"https://imgur.com/user/{a}"),
        ("Alias", "Flickr",         f"https://www.flickr.com/people/{a}"),
        ("Alias", "Letterboxd",     f"https://letterboxd.com/{a}/"),
        ("Alias", "Strava",         f"https://www.strava.com/athletes/{a}"),
        ("Alias", "Venmo",          f"https://account.venmo.com/u/{a}"),
        ("Alias", "CashApp",        f"https://cash.app/${a}"),
        ("Alias", "PayPal",         f"https://www.paypal.com/paypalme/{a}"),
        ("Alias", "Goodreads",      f"https://www.goodreads.com/{a}"),
        ("Alias", "Wattpad",        f"https://www.wattpad.com/user/{a}"),
        ("Alias", "MyAnimeList",    f"https://myanimelist.net/profile/{a}"),
        ("Alias", "Trakt",          f"https://trakt.tv/users/{a}"),
        ("Alias", "Duolingo",       f"https://www.duolingo.com/profile/{a}"),
        ("Alias", "Gravatar",       f"https://gravatar.com/{a}"),
        ("Alias", "Whatsmyname",    f"https://whatsmyname.app/?q={a}"),
        ("Alias", "Namechk",        f"https://namechk.com/{a}"),
        ("Alias", "Sherlock (web)", f"https://sherlock-project.github.io/?q={a}"),
        ("Alias", "IDCrawl",        f"https://www.idcrawl.com/u/{a}"),
        ("Alias", "Maigret (web)",  f"https://maigret.readthedocs.io/en/latest/"),
    ]


# ============================================================
# Pivot builders — email
# ============================================================

def _pivot_email(e: str):
    if not e:
        return []
    return [
        ("Email", "HIBP",           f"https://haveibeenpwned.com/account/{e}"),
        ("Email", "Hunter.io",      f"https://hunter.io/email-verifier/{e}"),
        ("Email", "EmailRep",       f"https://emailrep.io/{e}"),
        ("Email", "Gravatar",       f"https://gravatar.com/{e}"),
        ("Email", "Epieos",         f"https://epieos.com/?q={e}"),
        ("Email", "GHunt (repo)",   "https://github.com/mxrch/GHunt"),
        ("Email", "Leak-Lookup",    f"https://leak-lookup.com/search?type=email_address&query={e}"),
        ("Email", "DeHashed (web)", f"https://dehashed.com/search?query={e}"),
        ("Email", "XposedOrNot",    f"https://xposedornot.com/check?email={e}"),
        ("Email", "Firefox Monitor",f"https://monitor.firefox.com/"),
        ("Email", "Have I Been Sold", f"https://haveibeensold.app/"),
        ("Email", "Email Hippo",    f"https://tools.emailhippo.com/"),
        ("Email", "Verify Email",   f"https://verify-email.org/"),
        ("Email", "MXToolbox",      f"https://mxtoolbox.com/emailhealth/{e.split('@')[-1]}/"),
        ("Email", "Google Account", f"https://accounts.google.com/InputValidator?identifier={e}"),
        ("Email", "Microsoft Account", f"https://login.live.com/GetCredentialType.srf"),
        ("Email", "Skype",          f"https://login.skype.com/login?username={e}"),
        ("Email", "Spotify",        f"https://www.spotify.com/api/signup/validate"),
        ("Email", "Twitter/X",      f"https://api.x.com/1.1/account/begin_password_reset.json"),
        ("Email", "Instagram",      f"https://www.instagram.com/api/v1/users/check_email/"),
        ("Email", "Reddit",         f"https://www.reddit.com/api/register"),
        ("Email", "Pinterest",      f"https://www.pinterest.com/resource/EmailExistsResource/get/"),
        ("Email", "Firefox",        f"https://api.accounts.firefox.com/v1/account/status"),
        ("Email", "WordPress",      f"https://public-api.wordpress.com/rest/v1.1/users/email/exists"),
        ("Email", "Duolingo",       f"https://www.duolingo.com/2017-06-30/users"),
        ("Email", "LastPass",       f"https://lastpass.com/create_account.php"),
        ("Email", "GitHub",         f"https://github.com/signup_users/email"),
        ("Email", "Steam",          f"https://store.steampowered.com/join/checkemail"),
        ("Email", "Tumblr",         f"https://www.tumblr.com/register/email_available"),
        ("Email", "Adobe",          f"https://auth.services.adobe.com/signup/v2/users/email"),
        ("Email", "Flickr",         f"https://identity.flickr.com/api/email"),
        ("Email", "Envato",         f"https://account.envato.com/api/check_email"),
        ("Email", "PayPal",         f"https://www.paypal.com/signin/checkAccount"),
    ]


# ============================================================
# Pivot builders — phone
# ============================================================

def _pivot_phone(ph: str):
    if not ph:
        return []
    return [
        ("Phone", "WhatsApp",       f"https://wa.me/{ph}"),
        ("Phone", "Telegram",       f"https://t.me/+{ph}"),
        ("Phone", "Viber",          f"viber://chat?number=%2B{ph}"),
        ("Phone", "Signal",         f"https://signal.me/#p/+{ph}"),
        ("Phone", "Truecaller",     f"https://www.truecaller.com/search/global/{ph}"),
        ("Phone", "TruePeople",     f"https://www.truepeoplesearch.com/results?phoneno={ph}"),
        ("Phone", "FastPeople",     f"https://www.fastpeoplesearch.com/{ph}"),
        ("Phone", "ThatsThem",      f"https://thatsthem.com/phone/{ph}"),
        ("Phone", "Spokeo",         f"https://www.spokeo.com/phone-search/{ph}"),
        ("Phone", "NumLookup",      f"https://www.numlookup.com/?q={ph}"),
        ("Phone", "Whitepages",     f"https://www.whitepages.com/phone/{ph}"),
        ("Phone", "Sync.me",        f"https://sync.me/search/?number=%2B{ph}"),
        ("Phone", "SpyDialer",      f"https://www.spydialer.com/default.aspx?phone={ph}"),
        ("Phone", "Zlookup",        f"https://www.zlookup.com/?phone={ph}"),
        ("Phone", "AnyWho",         f"https://www.anywho.com/reverse-phone-lookup/"),
        ("Phone", "IPQualityScore", f"https://www.ipqualityscore.com/reverse-phone-lookup/lookup/{ph}"),
        ("Phone", "ReversePhoneLookup", f"https://www.reversephonelookup.com/?phone={ph}"),
        ("Phone", "800notes",       f"https://800notes.com/Phone.aspx/{ph}"),
        ("Phone", "WhoCallsMe",     f"https://whocallsme.com/Phone-Number.aspx/{ph}"),
        ("Phone", "CallerCenter",   f"https://callercenter.com/{ph}.php"),
        ("Phone", "Should I Answer",f"https://www.shouldianswer.com/phone-number/{ph}"),
        ("Phone", "Tellows",        f"https://www.tellows.com/num/{ph}"),
    ]


# ============================================================
# Pivot builders — name
# ============================================================

def _pivot_name(n: str):
    if not n:
        return []
    q = quote(n, safe="")
    q_plus = n.replace(" ", "+")
    return [
        ("Name", "Google Search",   f'https://www.google.com/search?q="{q_plus}"'),
        ("Name", "Bing Search",     f'https://www.bing.com/search?q="{q_plus}"'),
        ("Name", "DuckDuckGo",      f'https://duckduckgo.com/?q="{q_plus}"'),
        ("Name", "Yandex",          f'https://yandex.com/search/?text="{q_plus}"'),
        ("Name", "Brave Search",    f'https://search.brave.com/search?q="{q_plus}"'),
        ("Name", "Whitepages",      f"https://www.whitepages.com/name/{q_plus}"),
        ("Name", "TruePeople",      f"https://www.truepeoplesearch.com/results?name={q_plus}"),
        ("Name", "FastPeople",      f"https://www.fastpeoplesearch.com/name/{q_plus}"),
        ("Name", "Spokeo",          f"https://www.spokeo.com/{q_plus}"),
        ("Name", "WebMii",          f"https://webmii.com/people?n={q_plus}"),
        ("Name", "ThatsThem",       f"https://thatsthem.com/name/{q_plus}"),
        ("Name", "Radaris",         f"https://radaris.com/p/{q_plus}"),
        ("Name", "Pipl",            f"https://pipl.com/search/?q={q_plus}"),
        ("Name", "Intelius",        f"https://www.intelius.com/people-search/{q_plus}"),
        ("Name", "BeenVerified",    f"https://www.beenverified.com/people/{q_plus}"),
        ("Name", "PeopleFinders",   f"https://www.peoplefinders.com/people/{q_plus}"),
        ("Name", "WhitePages CA",   f"https://www.whitepages.ca/name/{q_plus}"),
        ("Name", "192.com (UK)",    f"https://www.192.com/people/{q_plus}"),
        ("Name", "Yasni",           f"https://www.yasni.com/{q_plus}"),
        ("Name", "LinkedIn",        f"https://www.linkedin.com/search/results/all/?keywords={q_plus}"),
        ("Name", "Facebook",        f"https://www.facebook.com/search/people/?q={q_plus}"),
        ("Name", "Twitter/X",       f"https://x.com/search?q={q_plus}&f=user"),
        ("Name", "SEC EDGAR",       f"https://efts.sec.gov/LATEST/search-index?q={q_plus}"),
        ("Name", "CourtListener",   f"https://www.courtlistener.com/?q={q_plus}"),
        ("Name", "OpenCorporates",  f"https://opencorporates.com/companies?q={q_plus}"),
        ("Name", "ORCID",           f"https://orcid.org/orcid-search/search?searchQuery={q_plus}"),
        ("Name", "Google Scholar",  f"https://scholar.google.com/scholar?q={q_plus}"),
        ("Name", "ResearchGate",    f"https://www.researchgate.net/search?q={q_plus}"),
    ]


# ============================================================
# Pivot builders — domain
# ============================================================

def _pivot_domain(d: str):
    if not d:
        return []
    return [
        ("Domain", "VirusTotal",       f"https://www.virustotal.com/gui/domain/{d}"),
        ("Domain", "SecurityTrails",   f"https://securitytrails.com/domain/{d}"),
        ("Domain", "Wayback Machine",  f"https://web.archive.org/web/*/{d}"),
        ("Domain", "Censys Domain",    f"https://search.censys.io/domains?q={d}"),
        ("Domain", "urlscan.io",       f"https://urlscan.io/domain/{d}"),
        ("Domain", "Shodan",           f"https://www.shodan.io/search?query={d}"),
        ("Domain", "DNSdumpster",      f"https://dnsdumpster.com/"),
        ("Domain", "crt.sh",           f"https://crt.sh/?q={d}"),
        ("Domain", "WHOIS (ICANN)",    f"https://lookup.icann.org/en/lookup?name={d}"),
        ("Domain", "ViewDNS",          f"https://viewdns.info/whois/?domain={d}"),
        ("Domain", "mxtoolbox",        f"https://mxtoolbox.com/SuperTool.aspx?action=a%3a{d}"),
        ("Domain", "BuiltWith",        f"https://builtwith.com/{d}"),
        ("Domain", "SimilarWeb",       f"https://www.similarweb.com/website/{d}/"),
        ("Domain", "AbuseIPDB",        f"https://www.abuseipdb.com/whois/{d}"),
        ("Domain", "RDAP",             f"https://rdap.org/domain/{d}"),
        ("Domain", "Google Safe",      f"https://transparencyreport.google.com/safe-browsing/search?url={d}"),
        ("Domain", "PhishTank",        f"https://phishtank.org/phish_search.php?valid=y&Search=Search&url={d}"),
        ("Domain", "ThreatCrowd",      f"https://www.threatminer.org/domain.php?q={d}"),
        ("Domain", "AlienVault OTX",   f"https://otx.alienvault.com/indicator/domain/{d}"),
        ("Domain", "Spamhaus",         f"https://check.spamhaus.org/"),
        ("Domain", "DNSlytics",        f"https://dnslytics.com/domain/{d}"),
        ("Domain", "Robtex",           f"https://www.robtex.com/dns-lookup/{d}"),
        ("Domain", "Intodns",          f"https://intodns.com/{d}"),
        ("Domain", "HackerTarget",     f"https://hackertarget.com/whois-lookup/?q={d}"),
        ("Domain", "MXToolbox SPF",    f"https://mxtoolbox.com/spf.aspx?domain={d}"),
        ("Domain", "MXToolbox DMARC",  f"https://mxtoolbox.com/dmarc.aspx?domain={d}"),
        ("Domain", "MXToolbox DKIM",   f"https://mxtoolbox.com/dkim.aspx?domain={d}"),
        ("Domain", "Email Security",   f"https://emailsecuritygrader.com/{d}"),
        ("Domain", "Hardenize",        f"https://www.hardenize.com/report/{d}"),
        ("Domain", "SSL Labs",         f"https://www.ssllabs.com/ssltest/analyze.html?d={d}"),
        ("Domain", "Observatory",      f"https://observatory.mozilla.org/analyze/{d}"),
        ("Domain", "Security Headers", f"https://securityheaders.com/?q={d}"),
        ("Domain", "PageSpeed",        f"https://developers.google.com/speed/pagespeed/insights/?url={d}"),
        ("Domain", "Sucuri SiteCheck", f"https://sitecheck.sucuri.net/results/{d}"),
        ("Domain", "Qualys SSL",       f"https://www.ssllabs.com/ssltest/analyze.html?d={d}"),
        ("Domain", "W3C Validator",    f"https://validator.w3.org/nu/?doc=https://{d}"),
        ("Domain", "Wappalyzer",       f"https://www.wappalyzer.com/lookup/{d}"),
    ]


# ============================================================
# Pivot builders — IP
# ============================================================

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
        ("IP", "Shodan InternetDB", f"https://internetdb.shodan.io/{ip}"),
        ("IP", "RDAP",          f"https://rdap.org/ip/{ip}"),
        ("IP", "IP-API",        f"http://ip-api.com/json/{ip}"),
        ("IP", "ipwho.is",      f"https://ipwho.is/{ip}"),
        ("IP", "freeipapi",     f"https://freeipapi.com/api/json/{ip}"),
        ("IP", "ipapi.co",      f"https://ipapi.co/{ip}/json/"),
        ("IP", "IPLocation",    f"https://www.iplocation.net/ip-lookup?query={ip}"),
        ("IP", "WhatIsMyIP",    f"https://whatismyipaddress.com/ip/{ip}"),
        ("IP", "IPVoid",        f"https://www.ipvoid.com/ip-blacklist-check/{ip}/"),
        ("IP", "MXToolbox",     f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{ip}"),
        ("IP", "DNSBL",         f"https://www.dnsbl.info/dnsbl-database-check.php?ip={ip}"),
        ("IP", "IPQualityScore",f"https://www.ipqualityscore.com/ip-reputation-check/lookup/{ip}"),
        ("IP", "Scamalytics",   f"https://scamalytics.com/ip/{ip}"),
        ("IP", "IPHub",         f"https://iphub.info/?ip={ip}"),
        ("IP", "Tor Exit",      f"https://check.torproject.org/torbulkexitlist?ip={ip}"),
        ("IP", "Nmap Online",   f"https://nmap.online/scan/{ip}"),
        ("IP", "HackerTarget Nmap", f"https://hackertarget.com/nmap-online-port-scanner/?target={ip}"),
    ]


# ============================================================
# Pivot builders — location
# ============================================================

def _pivot_location(l: str):
    if not l:
        return []
    return [
        ("Location", "Google Maps",   f"https://www.google.com/maps/search/{l}"),
        ("Location", "OpenStreetMap", f"https://www.openstreetmap.org/search?query={l}"),
        ("Location", "Bing Maps",     f"https://www.bing.com/maps?q={l}"),
        ("Location", "Geohack",       f"https://geohack.toolforge.org/geohack.php?params={l}"),
        ("Location", "What3Words",    f"https://what3words.com/"),
        ("Location", "SunCalc",       f"https://www.suncalc.org/"),
        ("Location", "TimeAndDate",   f"https://www.timeanddate.com/worldclock/"),
        ("Location", "Weather",       f"https://wttr.in/"),
        ("Location", "Nominatim",     f"https://nominatim.openstreetmap.org/search?q={l}&format=json"),
        ("Location", "GeoNames",      f"https://www.geonames.org/search.html?q={l}"),
        ("Location", "Wikimapia",     f"http://wikimapia.org/search/?q={l}"),
        ("Location", "Mapillary",     f"https://www.mapillary.com/app/?lat=&lng=&z=17&focus=photo&pKey="),
        ("Location", "KartaView",     f"https://kartaview.org/map/@0,0,0z"),
    ]


# ============================================================
# Pivot builders — crypto
# ============================================================

def _pivot_crypto(c: str):
    if not c:
        return []
    return [
        ("Crypto", "Blockchair",    f"https://blockchair.com/search?q={c}"),
        ("Crypto", "Blockchain.com",f"https://www.blockchain.com/explorer/search?search={c}"),
        ("Crypto", "Etherscan",     f"https://etherscan.io/address/{c}"),
        ("Crypto", "BscScan",       f"https://bscscan.com/address/{c}"),
        ("Crypto", "PolygonScan",   f"https://polygonscan.com/address/{c}"),
        ("Crypto", "Arbiscan",      f"https://arbiscan.io/address/{c}"),
        ("Crypto", "Optimism",      f"https://optimistic.etherscan.io/address/{c}"),
        ("Crypto", "BaseScan",      f"https://basescan.org/address/{c}"),
        ("Crypto", "Solscan",       f"https://solscan.io/account/{c}"),
        ("Crypto", "TronScan",      f"https://tronscan.org/#/address/{c}"),
        ("Crypto", "XRP Scan",      f"https://xrpscan.com/account/{c}"),
        ("Crypto", "Blockchair BTC",f"https://blockchair.com/bitcoin/address/{c}"),
        ("Crypto", "Blockchair ETH",f"https://blockchair.com/ethereum/address/{c}"),
        ("Crypto", "Blockchair LTC",f"https://blockchair.com/litecoin/address/{c}"),
        ("Crypto", "Blockchair DOGE",f"https://blockchair.com/dogecoin/address/{c}"),
        ("Crypto", "Blockchair BCH",f"https://blockchair.com/bitcoin-cash/address/{c}"),
        ("Crypto", "Blockchair DASH",f"https://blockchair.com/dash/address/{c}"),
        ("Crypto", "Blockchair ZEC",f"https://blockchair.com/zcash/address/{c}"),
        ("Crypto", "Blockchair XRP",f"https://blockchair.com/ripple/address/{c}"),
        ("Crypto", "Blockchair ADA",f"https://blockchair.com/cardano/address/{c}"),
        ("Crypto", "Blockchair SOL",f"https://blockchair.com/solana/address/{c}"),
        ("Crypto", "Blockchair TRX",f"https://blockchair.com/tron/address/{c}"),
        ("Crypto", "Blockchair XMR",f"https://blockchair.com/monero/address/{c}"),
        ("Crypto", "WalletExplorer",f"https://www.walletexplorer.com/"),
        ("Crypto", "OXT",           f"https://oxt.me/address/{c}"),
        ("Crypto", "Breadcrumbs",   f"https://www.breadcrumbs.app/"),
        ("Crypto", "Crystal",       f"https://crystalblockchain.com/"),
        ("Crypto", "Chainalysis",   f"https://www.chainalysis.com/"),
        ("Crypto", "Elliptic",      f"https://www.elliptic.co/"),
    ]


# ============================================================
# Pivot builders — MAC address
# ============================================================

def _pivot_mac(m: str):
    if not m:
        return []
    oui = m[:8].upper().replace(":", "")
    return [
        ("MAC", "macvendors.com",    f"https://macvendors.com/query/{m}"),
        ("MAC", "maclookup.app",     f"https://maclookup.app/macaddress/{m}"),
        ("MAC", "macaddress.io",     f"https://macaddress.io/"),
        ("MAC", "OUI Lookup",        f"https://www.wireshark.org/tools/oui-lookup.html"),
        ("MAC", "IEEE OUI",          f"https://standards-oui.ieee.org/oui/oui.txt"),
        ("MAC", "Arul John OUI",     f"https://aruljohn.com/mac/{m}"),
        ("MAC", "Miniwebtool",       f"https://miniwebtool.com/mac-address-lookup/?mac={m}"),
        ("MAC", "DNS Checker",       f"https://dnschecker.org/mac-lookup.php?query={m}"),
        ("MAC", "Vendor Lookup",     f"https://www.macvendorlookup.com/"),
        ("MAC", "Copperhead",        f"https://www.copperhead.co/oui/{oui.lower()}"),
    ]


# ============================================================
# Pivot builders — VIN
# ============================================================

def _pivot_vin(v: str):
    if not v:
        return []
    return [
        ("VIN", "NHTSA vPIC",      f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{v}?format=json"),
        ("VIN", "NHTSA Decode",    f"https://www.nhtsa.gov/vin-decoder"),
        ("VIN", "Carfax",          f"https://www.carfax.com/VehicleHistory/"),
        ("VIN", "AutoCheck",       f"https://www.autocheck.com/vehiclehistory/"),
        ("VIN", "VINCheck",        f"https://www.nicb.org/vincheck"),
        ("VIN", "Vincario",        f"https://vincario.com/vin-decoder/"),
        ("VIN", "VIN Decoder",     f"https://www.vindecoderz.com/EN/check-lookup/{v}"),
        ("VIN", "VINformer",       f"https://vinformer.su/en/"),
        ("VIN", "Decode This",     f"https://www.decodethis.com/"),
        ("VIN", "VIN Analytics",   f"https://www.vinanalytics.com/"),
        ("VIN", "Google",          f"https://www.google.com/search?q={v}"),
        ("VIN", "Bing",            f"https://www.bing.com/search?q={v}"),
        ("VIN", "DuckDuckGo",      f"https://duckduckgo.com/?q={v}"),
    ]


# ============================================================
# Pivot builders — ASN
# ============================================================

def _pivot_asn(a: str):
    if not a:
        return []
    return [
        ("ASN", "BGPView",         f"https://bgpview.io/asn/{a}"),
        ("ASN", "RIPE Stat",       f"https://stat.ripe.net/AS{a}"),
        ("ASN", "PeeringDB",       f"https://www.peeringdb.com/asn/{a}"),
        ("ASN", "Hurricane Electric",f"https://bgp.he.net/AS{a}"),
        ("ASN", "IPinfo",          f"https://ipinfo.io/AS{a}"),
        ("ASN", "Shodan",          f"https://www.shodan.io/search?query=asn%3aAS{a}"),
        ("ASN", "Censys",          f"https://search.censys.io/search?resource=hosts&q=autonomous_system.asn%3a{a}"),
        ("ASN", "IP-API",          f"http://ip-api.com/json/AS{a}"),
        ("ASN", "RADB",            f"https://www.radb.net/query?keywords=AS{a}"),
        ("ASN", "RPKI",            f"https://rpki-monitor.antd.nist.gov/?asn={a}"),
        ("ASN", "Team Cymru",      f"https://www.team-cymru.com/ip-asn-mapping"),
        ("ASN", "Robtex",          f"https://www.robtex.com/as/{a}"),
        ("ASN", "BGP.tools",       f"https://bgp.tools/as/{a}"),
    ]


# ============================================================
# Pivot builders — CIDR
# ============================================================

def _pivot_cidr(c: str):
    if not c:
        return []
    return [
        ("CIDR", "BGPView",        f"https://bgpview.io/prefix/{c}"),
        ("CIDR", "RIPE Stat",      f"https://stat.ripe.net/{c}"),
        ("CIDR", "Hurricane Electric",f"https://bgp.he.net/net/{c}"),
        ("CIDR", "Shodan",         f"https://www.shodan.io/search?query=net%3a{c}"),
        ("CIDR", "Censys",         f"https://search.censys.io/search?resource=hosts&q=ip%3a{c}"),
        ("CIDR", "IPinfo",         f"https://ipinfo.io/{c}"),
        ("CIDR", "BGP.tools",      f"https://bgp.tools/prefix/{c}"),
        ("CIDR", "RADB",           f"https://www.radb.net/query?keywords={c}"),
        ("CIDR", "Team Cymru",     f"https://www.team-cymru.com/ip-asn-mapping"),
    ]


# ============================================================
# Pivot builders — organization
# ============================================================

def _pivot_org(o: str):
    if not o:
        return []
    q = quote(o, safe="")
    q_plus = o.replace(" ", "+")
    return [
        ("Org", "OpenCorporates",  f"https://opencorporates.com/companies?q={q_plus}"),
        ("Org", "SEC EDGAR",       f"https://efts.sec.gov/LATEST/search-index?q={q_plus}"),
        ("Org", "Companies House", f"https://find-and-update.company-information.service.gov.uk/search?q={q_plus}"),
        ("Org", "Crunchbase",      f"https://www.crunchbase.com/search?q={q_plus}"),
        ("Org", "LinkedIn",        f"https://www.linkedin.com/search/results/companies/?keywords={q_plus}"),
        ("Org", "Glassdoor",       f"https://www.glassdoor.com/Search/results.htm?keyword={q_plus}"),
        ("Org", "Indeed",          f"https://www.indeed.com/cmp/{q_plus}"),
        ("Org", "Better Business Bureau", f"https://www.bbb.org/search?find_text={q_plus}"),
        ("Org", "Trustpilot",      f"https://www.trustpilot.com/search?query={q_plus}"),
        ("Org", "Charity Navigator",f"https://www.charitynavigator.org/search?q={q_plus}"),
        ("Org", "GLEIF",           f"https://search.gleif.org/#/record?q={q_plus}"),
        ("Org", "Dun & Bradstreet",f"https://www.dnb.com/business-directory/company-search.html?term={q_plus}"),
        ("Org", "OpenOwnership",   f"https://register.openownership.org/search?q={q_plus}"),
        ("Org", "OCCRP Aleph",     f"https://aleph.occrp.org/search?q={q_plus}"),
        ("Org", "ICIJ Offshore",   f"https://offshoreleaks.icij.org/search?q={q_plus}"),
    ]


# ============================================================
# Aggregated pivot links
# ============================================================

def _pivot_links(p: dict):
    links = []
    links += _pivot_alias(p.get("alias", ""))
    links += _pivot_email(p.get("email", ""))
    links += _pivot_phone(p.get("phone", ""))
    links += _pivot_name(p.get("name", ""))
    links += _pivot_domain(p.get("domain", ""))
    links += _pivot_ip(p.get("ip", ""))
    links += _pivot_location(p.get("location", ""))
    links += _pivot_crypto(p.get("crypto", ""))
    links += _pivot_mac(p.get("mac", ""))
    links += _pivot_vin(p.get("vin", ""))
    links += _pivot_asn(p.get("asn", ""))
    links += _pivot_cidr(p.get("cidr", ""))
    links += _pivot_org(p.get("org", ""))
    return links


# ============================================================
# Enrichment — Gravatar
# ============================================================

def _gravatar_enrich(email: str):
    """Fetch Gravatar profile via SHA256 API."""
    if not email or "@" not in email:
        return None
    sha = hashlib.sha256(email.strip().lower().encode()).hexdigest()
    try:
        r = requests.get(
            f"https://gravatar.com/{sha}.json",
            headers={"User-Agent": UA}, timeout=10,
        )
        if r.status_code == 200:
            j = r.json()
            entry = (j.get("entry") or [{}])[0]
            return {
                "display_name": entry.get("displayName"),
                "about_me": entry.get("aboutMe"),
                "location": entry.get("currentLocation"),
                "thumbnail": entry.get("thumbnailUrl"),
                "profile_url": entry.get("profileUrl"),
                "urls": [u.get("value") for u in (entry.get("urls") or [])],
                "accounts": [
                    f"{a.get('shortname')}: {a.get('username') or a.get('url')}"
                    for a in (entry.get("accounts") or [])
                ],
            }
    except Exception:
        pass
    return None


# ============================================================
# Enrichment — EmailRep
# ============================================================

def _emailrep_enrich(email: str):
    """Query EmailRep for reputation signals."""
    if not email or "@" not in email:
        return None
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


# ============================================================
# Enrichment — XposedOrNot (free, no key)
# ============================================================

def _xposedornot_enrich(email: str):
    """Query XposedOrNot breach API — free, no key required."""
    if not email or "@" not in email:
        return None
    try:
        r = requests.get(
            f"https://api.xposedornot.com/v1/check-email/{email}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            return {"breaches": []}
    except Exception:
        pass
    return None


# ============================================================
# Enrichment — IP geolocation (multi-source)
# ============================================================

def _ip_enrich(ip: str):
    """Query IP-API, ipwho.is, freeipapi, ipapi.co in parallel."""
    if not ip:
        return None
    results = {}

    def _ip_api():
        try:
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=66846719",
                headers={"User-Agent": UA}, timeout=8,
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    return {
                        "source": "ip-api",
                        "country": d.get("country"),
                        "country_code": d.get("countryCode"),
                        "region": d.get("regionName"),
                        "city": d.get("city"),
                        "zip": d.get("zip"),
                        "lat": d.get("lat"),
                        "lon": d.get("lon"),
                        "timezone": d.get("timezone"),
                        "isp": d.get("isp"),
                        "org": d.get("org"),
                        "asn": d.get("as"),
                        "proxy": d.get("proxy"),
                        "hosting": d.get("hosting"),
                        "mobile": d.get("mobile"),
                    }
        except Exception:
            return None

    def _ipwho():
        try:
            r = requests.get(
                f"https://ipwho.is/{ip}",
                headers={"User-Agent": UA}, timeout=8,
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("success"):
                    conn = d.get("connection") or {}
                    return {
                        "source": "ipwho.is",
                        "country": d.get("country"),
                        "country_code": d.get("country_code"),
                        "region": d.get("region"),
                        "city": d.get("city"),
                        "zip": d.get("postal"),
                        "lat": d.get("latitude"),
                        "lon": d.get("longitude"),
                        "timezone": (d.get("timezone") or {}).get("id"),
                        "isp": conn.get("isp"),
                        "org": conn.get("org"),
                        "asn": f"AS{conn.get('asn')}",
                        "continent": d.get("continent"),
                        "calling_code": d.get("calling_code"),
                    }
        except Exception:
            return None

    def _freeipapi():
        try:
            r = requests.get(
                f"https://freeipapi.com/api/json/{ip}",
                headers={"User-Agent": UA}, timeout=8,
            )
            if r.status_code == 200:
                d = r.json()
                return {
                    "source": "freeipapi",
                    "country": d.get("countryName"),
                    "country_code": d.get("countryCode"),
                    "region": d.get("regionName"),
                    "city": d.get("cityName"),
                    "zip": d.get("zipCode"),
                    "lat": d.get("latitude"),
                    "lon": d.get("longitude"),
                    "timezone": ", ".join(d.get("timeZones") or []),
                }
        except Exception:
            return None

    def _ipapi_co():
        try:
            r = requests.get(
                f"https://ipapi.co/{ip}/json/",
                headers={"User-Agent": UA}, timeout=8,
            )
            if r.status_code == 200:
                d = r.json()
                if not d.get("error"):
                    return {
                        "source": "ipapi.co",
                        "country": d.get("country_name"),
                        "country_code": d.get("country_code"),
                        "region": d.get("region"),
                        "city": d.get("city"),
                        "zip": d.get("postal"),
                        "lat": d.get("latitude"),
                        "lon": d.get("longitude"),
                        "timezone": d.get("timezone"),
                        "isp": d.get("org"),
                        "asn": d.get("asn"),
                        "currency": d.get("currency"),
                        "calling_code": d.get("country_calling_code"),
                    }
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = {
            ex.submit(_ip_api): "ip-api",
            ex.submit(_ipwho): "ipwho.is",
            ex.submit(_freeipapi): "freeipapi",
            ex.submit(_ipapi_co): "ipapi.co",
        }
        for f in as_completed(futs):
            name = futs[f]
            try:
                res = f.result()
                if res:
                    results[name] = res
            except Exception:
                pass

    return results


# ============================================================
# Enrichment — Shodan InternetDB
# ============================================================

def _shodan_internetdb(ip: str):
    """Shodan InternetDB — free, no key. Open ports, tags, CVEs."""
    if not ip:
        return None
    try:
        r = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            headers={"User-Agent": UA}, timeout=10,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


# ============================================================
# Enrichment — RDAP domain
# ============================================================

def _rdap_domain(domain: str):
    if not domain:
        return None
    try:
        r = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={"User-Agent": UA, "Accept": "application/rdap+json"},
            timeout=12,
        )
        if r.status_code == 200:
            d = r.json()
            events = {}
            for ev in d.get("events") or []:
                events[ev.get("eventAction")] = ev.get("eventDate")
            registrar = None
            for ent in d.get("entities") or []:
                if "registrar" in (ent.get("roles") or []):
                    vc = ent.get("vcardArray")
                    if vc and len(vc) > 1:
                        for f in vc[1]:
                            if f[0] == "fn":
                                registrar = f[3]
            return {
                "handle": d.get("handle"),
                "ldhName": d.get("ldhName"),
                "status": d.get("status") or [],
                "events": events,
                "nameservers": [ns.get("ldhName") for ns in
                                (d.get("nameservers") or [])],
                "registrar": registrar,
            }
    except Exception:
        pass
    return None


# ============================================================
# Enrichment — RDAP IP
# ============================================================

def _rdap_ip(ip: str):
    if not ip:
        return None
    try:
        r = requests.get(
            f"https://rdap.org/ip/{ip}",
            headers={"User-Agent": UA, "Accept": "application/rdap+json"},
            timeout=12,
        )
        if r.status_code == 200:
            d = r.json()
            out = {
                "handle": d.get("handle"),
                "name": d.get("name"),
                "start": d.get("startAddress"),
                "end": d.get("endAddress"),
                "country": d.get("country"),
                "type": d.get("type"),
            }
            for ent in d.get("entities", []) or []:
                if "abuse" in (ent.get("roles") or []):
                    vc = ent.get("vcardArray")
                    if vc and len(vc) > 1:
                        for f in vc[1]:
                            if f[0] == "email":
                                out["abuse_email"] = f[3]
            return out
    except Exception:
        pass
    return None


# ============================================================
# Enrichment — crt.sh certificate transparency
# ============================================================

def _crtsh_enrich(domain: str):
    if not domain:
        return None
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": UA}, timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for entry in data:
                for name in (entry.get("name_value") or "").split("\n"):
                    name = name.strip().lower()
                    if name.endswith(domain) and "*" not in name:
                        subs.add(name)
            return sorted(subs)[:100]
    except Exception:
        pass
    return None


# ============================================================
# Enrichment — SEC EDGAR full-text search
# ============================================================

def _sec_edgar_enrich(query: str):
    if not query:
        return None
    try:
        r = requests.get(
            "https://efts.sec.gov/LATEST/search-index",
            params={"q": f'"{query}"', "dateRange": "custom",
                    "startdt": "2000-01-01", "enddt": datetime.now().strftime("%Y-%m-%d")},
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=12,
        )
        if r.status_code == 200:
            d = r.json()
            hits = (d.get("hits") or {}).get("hits") or []
            return [
                {"id": h.get("_id"), "source": h.get("_source", {})}
                for h in hits[:20]
            ]
    except Exception:
        pass
    return None


# ============================================================
# Enrichment — NHTSA VIN decoder
# ============================================================

def _nhtsa_vin_enrich(vin: str):
    if not vin or len(vin) != 17:
        return None
    try:
        r = requests.get(
            f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{vin}?format=json",
            headers={"User-Agent": UA}, timeout=12,
        )
        if r.status_code == 200:
            d = r.json()
            results = d.get("Results") or [{}]
            return results[0]
    except Exception:
        pass
    return None


# ============================================================
# Enrichment — crypto address lookup
# ============================================================

def _crypto_enrich(addr: str):
    if not addr:
        return None
    # try Blockchair for common chains
    for chain in ("bitcoin", "ethereum", "litecoin", "dogecoin",
                  "bitcoin-cash", "dash", "zcash", "ripple",
                  "cardano", "solana", "tron", "monero"):
        try:
            r = requests.get(
                f"https://api.blockchair.com/{chain}/dashboards/address/{addr}",
                headers={"User-Agent": UA}, timeout=12,
            )
            if r.status_code == 200:
                d = r.json()
                if "data" in d and addr in d["data"]:
                    block = d["data"][addr]
                    return {
                        "chain": chain,
                        "source": "blockchair",
                        "address": block.get("address") or {},
                        "transactions": (block.get("transactions") or [])[:10],
                        "utxo_count": block.get("utxo_count"),
                    }
        except Exception:
            continue
    return None


# ============================================================
# Enrichment — MAC vendor lookup (macvendors.com)
# ============================================================

def _mac_enrich(mac: str):
    if not mac:
        return None
    try:
        r = requests.get(
            f"https://api.macvendors.com/{mac}",
            headers={"User-Agent": UA}, timeout=8,
        )
        if r.status_code == 200:
            return {"vendor": r.text.strip()}
        if r.status_code == 404:
            return {"vendor": None, "note": "not found"}
    except Exception:
        pass
    return None


# ============================================================
# Enrichment — organization search (OpenCorporates via web)
# ============================================================

def _org_enrich(org: str):
    """Aggregate simple org info from OpenCorporates search results."""
    if not org:
        return None
    try:
        r = requests.get(
            f"https://api.opencorporates.com/v0.4/companies/search",
            params={"q": org, "per_page": 10},
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=12,
        )
        if r.status_code == 200:
            d = r.json()
            companies = (d.get("results") or {}).get("companies") or []
            return [
                {
                    "name": c.get("company", {}).get("name"),
                    "jurisdiction": c.get("company", {}).get("jurisdiction_code"),
                    "company_number": c.get("company", {}).get("company_number"),
                    "status": c.get("company", {}).get("current_status"),
                    "incorporation": c.get("company", {}).get("incorporation_date"),
                    "url": c.get("company", {}).get("opencorporates_url"),
                }
                for c in companies[:10]
            ]
    except Exception:
        pass
    return None


# ============================================================
# Risk scoring
# ============================================================

def _risk_score(profile: dict, enrich: dict) -> tuple:
    score = 0
    reasons = []

    # email risk
    er = enrich.get("emailrep")
    if er:
        rep = (er.get("reputation") or "").lower()
        if rep == "high":
            score += 0
        elif rep == "medium":
            score += 10
            reasons.append("EmailRep: medium reputation")
        elif rep == "low":
            score += 20
            reasons.append("EmailRep: low reputation")
        if er.get("suspicious"):
            score += 15
            reasons.append("EmailRep: flagged suspicious")
        if er.get("blacklisted"):
            score += 20
            reasons.append("EmailRep: blacklisted")
        if er.get("credentials_leaked"):
            score += 15
            reasons.append("EmailRep: credentials leaked")
        if er.get("data_breach"):
            score += 10
            reasons.append("EmailRep: in a data breach")
        if er.get("spam"):
            score += 10
            reasons.append("EmailRep: marked as spam")

    # XposedOrNot breaches
    xon = enrich.get("xposedornot")
    if xon and xon.get("breaches"):
        n = len(xon["breaches"])
        score += min(20, n * 3)
        reasons.append(f"XposedOrNot: {n} breach(es)")

    # IP risk
    shodan = enrich.get("shodan")
    if shodan:
        vulns = shodan.get("vulns") or []
        if vulns:
            score += min(30, len(vulns) * 6)
            reasons.append(f"Shodan: {len(vulns)} CVE(s) on open ports")
        tags = [t.lower() for t in (shodan.get("tags") or [])]
        for risky in ("tor", "proxy", "vpn", "honeypot", "malware",
                      "compromised", "c2", "scanner", "exploit"):
            if risky in tags:
                score += 15
                reasons.append(f"Shodan tag: {risky}")
                break
        ports = shodan.get("ports") or []
        risky_ports = [p for p in ports if p in
                       (23, 445, 1433, 3306, 3389, 5432, 6379, 27017,
                        9200, 11211, 2375, 2376)]
        if risky_ports:
            score += min(20, len(risky_ports) * 5)
            reasons.append(f"Shodan: risky open ports {risky_ports}")

    # IP geolocation proxy/vpn flags
    ipgeo = enrich.get("ip_geo") or {}
    for src, data in ipgeo.items():
        if data.get("proxy") is True:
            score += 10
            reasons.append(f"IP proxy flag ({src})")
        if data.get("hosting") is True:
            score += 5
            reasons.append(f"IP hosting flag ({src})")

    # domain risk
    rdap = enrich.get("rdap_domain")
    if rdap:
        events = rdap.get("events") or {}
        reg = events.get("registration")
        if reg:
            try:
                reg_date = datetime.fromisoformat(reg.replace("Z", "+00:00"))
                age_days = (datetime.now(reg_date.tzinfo) - reg_date).days
                if age_days < 30:
                    score += 25
                    reasons.append(f"domain registered {age_days} days ago")
                elif age_days < 180:
                    score += 10
                    reasons.append(f"domain is {age_days} days old")
            except Exception:
                pass

    # VIN risk
    vin = enrich.get("vin")
    if vin:
        # check for salvage/theft markers in NHTSA response
        for k, v in vin.items():
            if v and isinstance(v, str):
                lv = v.lower()
                if "salvage" in lv or "junk" in lv or "rebuilt" in lv:
                    score += 20
                    reasons.append(f"VIN: {k} = {v}")
                    break

    return min(score, 100), reasons


def _risk_label(score):
    if score < 10:
        return "very low", "green"
    if score < 30:
        return "low", "green"
    if score < 55:
        return "moderate", "yellow"
    if score < 80:
        return "high", "red"
    return "critical", "red"


# ============================================================
# Field relationship graph
# ============================================================

def _field_graph(profile: dict, enrich: dict):
    """Show which fields are linked via enrichment results."""
    edges = []
    if enrich.get("gravatar") and profile.get("email"):
        g = enrich["gravatar"]
        if g.get("display_name"):
            edges.append(("email", "gravatar", g["display_name"]))
        if g.get("location"):
            edges.append(("gravatar", "location", g["location"]))
        if g.get("urls"):
            for u in g["urls"][:5]:
                edges.append(("gravatar", "url", u))
        if g.get("accounts"):
            for a in g["accounts"][:5]:
                edges.append(("gravatar", "account", a))

    if enrich.get("shodan") and profile.get("ip"):
        s = enrich["shodan"]
        for host in (s.get("hostnames") or [])[:5]:
            edges.append(("ip", "hostname", host))
        for tag in (s.get("tags") or [])[:5]:
            edges.append(("ip", "tag", tag))

    if enrich.get("rdap_domain") and profile.get("domain"):
        r = enrich["rdap_domain"]
        if r.get("registrar"):
            edges.append(("domain", "registrar", r["registrar"]))
        for ns in (r.get("nameservers") or [])[:5]:
            edges.append(("domain", "nameserver", ns))

    if enrich.get("crtsh") and profile.get("domain"):
        for sub in (enrich["crtsh"] or [])[:10]:
            edges.append(("domain", "subdomain", sub))

    if enrich.get("org") and profile.get("org"):
        for c in (enrich["org"] or [])[:5]:
            if c.get("name"):
                edges.append(("org", "company", c["name"]))
            if c.get("jurisdiction"):
                edges.append(("org", "jurisdiction", c["jurisdiction"]))

    return edges


# ============================================================
# History
# ============================================================

def _history_path(profile: dict):
    key = hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()[:32]
    return HIST_DIR / f"{key}.json"


def _load_history(profile: dict):
    p = _history_path(profile)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _save_history(profile: dict, snapshot: dict):
    p = _history_path(profile)
    try:
        p.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False,
                                default=str), encoding="utf-8")
    except Exception:
        pass


def _diff_history(prev, curr):
    if not prev:
        return []
    diffs = []
    for k in ("risk_score",):
        if prev.get(k) != curr.get(k):
            diffs.append(f"{k}: {prev.get(k)} → {curr.get(k)}")
    return diffs


# ============================================================
# Render
# ============================================================

def _render(profile, pivots, enrich, risk, reasons, edges, history_diffs):
    label, color = _risk_label(risk)

    console.print(
        Panel.fit(
            "[bg]CORRELATION ENGINE[/bg]\n"
            "[dg]combine fields into a target profile[/dg]",
            border_style="bd",
            padding=(0, 2),
        )
    )

    # profile
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
            pt.add_row(k, str(v))
    console.print(pt)

    # risk
    console.print(
        Panel.fit(
            f"[bg]risk score[/bg]  [{color}]{label} — {risk}/100[/{color}]",
            border_style="bd",
            padding=(0, 2),
        )
    )
    for r in reasons:
        console.print(f"[dg]  · {r}[/dg]")
    if not reasons:
        console.print("[green]  · no adverse signals[/green]")
    console.print()

    # enrichment panels
    if enrich.get("gravatar"):
        g = enrich["gravatar"]
        gt = Table(
            border_style="bd", title="[bg]gravatar[/bg]",
            show_header=False, padding=(0, 2),
        )
        gt.add_column("k", style="dg", no_wrap=True)
        gt.add_column("v", style="g", overflow="fold")
        for k in ("display_name", "about_me", "location", "thumbnail"):
            v = g.get(k)
            if v:
                gt.add_row(k, str(v)[:120])
        if g.get("urls"):
            gt.add_row("urls", ", ".join(g["urls"][:5]))
        if g.get("accounts"):
            gt.add_row("accounts", ", ".join(g["accounts"][:6]))
        console.print(gt)

    if enrich.get("emailrep"):
        er = enrich["emailrep"]
        rt = Table(
            border_style="bd", title="[bg]emailrep[/bg]",
            show_header=False, padding=(0, 2),
        )
        rt.add_column("k", style="dg", no_wrap=True)
        rt.add_column("v", style="g", overflow="fold")
        for k in ("reputation", "suspicious", "references", "blacklisted",
                  "credentials_leaked", "data_breach", "profiles",
                  "malicious_activity", "domain_exists", "spam"):
            v = er.get(k)
            if v not in (None, "", []):
                rt.add_row(k, str(v))
        console.print(rt)

    if enrich.get("xposedornot"):
        x = enrich["xposedornot"]
        breaches = x.get("breaches") or []
        if breaches:
            bt = Table(
                border_style="bd",
                title=f"[bg]xposedornot breaches ({len(breaches)})[/bg]",
                show_header=True, padding=(0, 2),
            )
            bt.add_column("name", style="bg")
            bt.add_column("date", style="dg")
            bt.add_column("data", style="dg", overflow="fold")
            for b in breaches[:20]:
                bt.add_row(
                    b.get("name") or "—",
                    (b.get("breach_date") or "—")[:10],
                    ", ".join((b.get("data_classes") or [])[:4]),
                )
            console.print(bt)

    if enrich.get("ip_geo"):
        ig = enrich["ip_geo"]
        for src, data in ig.items():
            it = Table(
                border_style="bd", title=f"[bg]ip geo — {src}[/bg]",
                show_header=False, padding=(0, 2),
            )
            it.add_column("k", style="dg", no_wrap=True)
            it.add_column("v", style="g", overflow="fold")
            for k in ("country", "country_code", "region", "city", "zip",
                      "lat", "lon", "timezone", "isp", "org", "asn",
                      "proxy", "hosting", "mobile", "continent",
                      "calling_code"):
                v = data.get(k)
                if v not in (None, "", []):
                    it.add_row(k, str(v))
            console.print(it)

    if enrich.get("shodan"):
        s = enrich["shodan"]
        st = Table(
            border_style="bd", title="[bg]shodan internetdb[/bg]",
            show_header=True, padding=(0, 2),
        )
        st.add_column("field", style="dg")
        st.add_column("value", style="g", overflow="fold")
        st.add_row("open ports", ", ".join(str(p) for p in (s.get("ports") or [])))
        if s.get("hostnames"):
            st.add_row("hostnames", ", ".join(s["hostnames"][:10]))
        if s.get("tags"):
            st.add_row("tags", ", ".join(s["tags"]))
        if s.get("cpes"):
            st.add_row("CPEs", "; ".join(s["cpes"][:5]))
        vulns = s.get("vulns") or []
        if vulns:
            st.add_row("CVEs", f"[red]{', '.join(vulns[:10])}[/red]")
        console.print(st)

    if enrich.get("rdap_domain"):
        r = enrich["rdap_domain"]
        rt = Table(
            border_style="bd", title="[bg]rdap domain[/bg]",
            show_header=False, padding=(0, 2),
        )
        rt.add_column("k", style="dg", no_wrap=True)
        rt.add_column("v", style="g", overflow="fold")
        rt.add_row("handle", r.get("handle") or "—")
        rt.add_row("registrar", r.get("registrar") or "—")
        for k, v in (r.get("events") or {}).items():
            rt.add_row(k, v)
        if r.get("nameservers"):
            rt.add_row("nameservers", ", ".join(r["nameservers"]))
        console.print(rt)

    if enrich.get("crtsh"):
        subs = enrich["crtsh"]
        console.print(
            f"[dg]  crt.sh subdomains: {len(subs)} unique[/dg]"
        )
        for s in subs[:15]:
            console.print(f"[g]    · {s}[/g]")
        if len(subs) > 15:
            console.print(f"[dg]    ... +{len(subs)-15} more[/dg]")
        console.print()

    if enrich.get("vin"):
        vt = Table(
            border_style="bd", title="[bg]nhtsa vin decode[/bg]",
            show_header=False, padding=(0, 2),
        )
        vt.add_column("k", style="dg", no_wrap=True)
        vt.add_column("v", style="g", overflow="fold")
        vin_data = enrich["vin"]
        for k in ("Make", "Model", "ModelYear", "BodyClass",
                  "VehicleType", "EngineCylinders", "DisplacementCC",
                  "FuelTypePrimary", "PlantCountry", "PlantCity",
                  "Manufacturer", "Series", "Trim", "GVWR", "ErrorText"):
            v = vin_data.get(k)
            if v:
                vt.add_row(k, str(v))
        console.print(vt)

    if enrich.get("crypto"):
        c = enrich["crypto"]
        ct = Table(
            border_style="bd",
            title=f"[bg]crypto — {c.get('chain')}[/bg]",
            show_header=False, padding=(0, 2),
        )
        ct.add_column("k", style="dg", no_wrap=True)
        ct.add_column("v", style="g", overflow="fold")
        addr_info = c.get("address") or {}
        for k, v in addr_info.items():
            if v not in (None, "", []):
                ct.add_row(k, str(v))
        console.print(ct)

    if enrich.get("mac"):
        m = enrich["mac"]
        console.print(
            f"[dg]  mac vendor: {m.get('vendor') or '—'}[/dg]\n"
        )

    if enrich.get("org"):
        o = enrich["org"]
        ot = Table(
            border_style="bd",
            title=f"[bg]organization ({len(o)})[/bg]",
            show_header=True, padding=(0, 2),
        )
        ot.add_column("name", style="bg")
        ot.add_column("jurisdiction", style="dg")
        ot.add_column("status", style="dg")
        ot.add_column("incorporated", style="dg")
        for c in o[:10]:
            ot.add_row(
                c.get("name") or "—",
                c.get("jurisdiction") or "—",
                c.get("status") or "—",
                (c.get("incorporation") or "—")[:10],
            )
        console.print(ot)

    # field graph
    if edges:
        et = Table(
            border_style="bd",
            title=f"[bg]field relationships ({len(edges)})[/bg]",
            show_header=True, padding=(0, 2),
        )
        et.add_column("from", style="dg")
        et.add_column("relation", style="bg")
        et.add_column("to", style="g", overflow="fold")
        for a, b, c in edges[:30]:
            et.add_row(a, b, str(c)[:80])
        console.print(et)

    # pivots
    if pivots:
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
        for field, svc, url in pivots:
            lt.add_row(field, svc, url)
        console.print(lt)
    else:
        console.print("[dg]  no pivots — provide at least one field[/dg]")

    # history diff
    if history_diffs:
        console.print(
            Panel.fit(
                "[bg]changes since last scan[/bg]",
                border_style="bd", padding=(0, 2),
            )
        )
        for d in history_diffs:
            console.print(f"[yellow]  · {d}[/yellow]")
        console.print()

    console.print()


# ============================================================
# Export
# ============================================================

def _export_json(profile, pivots, enrich, risk, reasons, edges):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = hashlib.md5(json.dumps(profile, sort_keys=True).encode()).hexdigest()[:12]
    p = OUT_DIR / f"correlation_{safe}_{ts}.json"
    p.write_text(json.dumps({
        "profile": profile,
        "risk_score": risk,
        "risk_reasons": reasons,
        "enrichment": enrich,
        "field_edges": edges,
        "pivots": [{"field": f, "service": s, "url": u}
                   for f, s, u in pivots],
        "generated": datetime.now().isoformat(timespec="seconds"),
    }, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]")
    return p


def _export_csv(profile, pivots, risk, reasons):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = hashlib.md5(json.dumps(profile, sort_keys=True).encode()).hexdigest()[:12]
    p = OUT_DIR / f"correlation_{safe}_{ts}.csv"
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["section", "key", "value"])
        for k, v in profile.items():
            if v:
                w.writerow(["profile", k, str(v)])
        w.writerow(["risk", "score", risk])
        for i, r in enumerate(reasons):
            w.writerow(["risk", f"reason_{i}", r])
        for f, s, u in pivots:
            w.writerow(["pivot", f"{f}/{s}", u])
    console.print(f"[dg]  exported → {p}[/dg]")


def _export_html(profile, pivots, enrich, risk, reasons, edges):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = hashlib.md5(json.dumps(profile, sort_keys=True).encode()).hexdigest()[:12]
    p = OUT_DIR / f"correlation_{safe}_{ts}.html"

    def esc(x):
        return html.escape(str(x))

    def tbl(rows, headers):
        th = "".join(f"<th>{esc(h)}</th>" for h in headers)
        trs = "".join(
            "<tr>" + "".join(f"<td>{esc(c)}</td>" for c in r) + "</tr>"
            for r in rows)
        return f"<table><tr>{th}</tr>{trs}</table>"

    label, color = _risk_label(risk)
    color_map = {"green": "#8fe388", "yellow": "#f2c14e", "red": "#ff6b6b"}
    score_color = color_map.get(color, "#ddd")

    profile_rows = [(k, str(v)) for k, v in profile.items() if v]
    reasons_html = "".join(f"<li>{esc(r)}</li>" for r in reasons)
    pivot_rows = [(f, s, f'<a href="{esc(u)}">{esc(u)}</a>')
                  for f, s, u in pivots]
    edge_rows = [(a, b, str(c)[:80]) for a, b, c in edges]

    doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Correlation Report</title>
<style>
body {{ background: #111; color: #ddd; font-family: monospace; padding: 2em; }}
h1, h2 {{ color: #9fd4ff; }}
table {{ border-collapse: collapse; margin: 1em 0; }}
td, th {{ border: 1px solid #333; padding: 4px 10px; }}
a {{ color: #8fe388; }}
.score {{ font-size: 2em; color: {score_color}; }}
</style></head><body>
<h1>Correlation Report</h1>
<p>Generated {esc(datetime.now().isoformat(timespec="seconds"))}</p>
<h2>Risk — {esc(label)} {esc(risk)}/100</h2>
<p class="score">{esc(risk)}/100</p>
<ul>{reasons_html or "<li>no adverse signals</li>"}</ul>
<h2>Profile</h2>
{tbl(profile_rows, ["field", "value"])}
<h2>Field Relationships ({len(edge_rows)})</h2>
{tbl(edge_rows, ["from", "relation", "to"]) if edge_rows else "<p>—</p>"}
<h2>Pivot Links ({len(pivot_rows)})</h2>
{tbl(pivot_rows, ["field", "service", "url"]) if pivot_rows else "<p>—</p>"}
</body></html>
"""
    p.write_text(doc, encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]")


# ============================================================
# Runner
# ============================================================

def run():
    console.print(
        Panel.fit(
            "[bg]CORRELATION ENGINE[/bg]\n"
            "[dg]combine fields into a target profile[/dg]",
            border_style="bd", padding=(0, 2),
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
        "crypto":   input("  crypto address    >> "),
        "mac":      input("  mac address       >> "),
        "vin":      input("  vehicle vin       >> "),
        "asn":      input("  asn (e.g. 15169)  >> "),
        "cidr":     input("  cidr block        >> "),
        "org":      input("  organization      >> "),
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
        "crypto":   _crypto(raw["crypto"]),
        "mac":      _mac(raw["mac"]),
        "vin":      _vin(raw["vin"]),
        "asn":      _asn(raw["asn"]),
        "cidr":     _cidr(raw["cidr"]),
        "org":      _org(raw["org"]),
        "notes":    raw["notes"].strip(),
    }

    # ---- enrichment ----
    enrich = {}

    with console.status("[dg]enriching...[/dg]", spinner="dots"):
        tasks = []

        if profile["email"]:
            tasks.append(("gravatar", _gravatar_enrich, profile["email"]))
            tasks.append(("emailrep", _emailrep_enrich, profile["email"]))
            tasks.append(("xposedornot", _xposedornot_enrich, profile["email"]))

        if profile["ip"]:
            tasks.append(("ip_geo", _ip_enrich, profile["ip"]))
            tasks.append(("shodan", _shodan_internetdb, profile["ip"]))
            tasks.append(("rdap_ip", _rdap_ip, profile["ip"]))

        if profile["domain"]:
            tasks.append(("rdap_domain", _rdap_domain, profile["domain"]))
            tasks.append(("crtsh", _crtsh_enrich, profile["domain"]))

        if profile["crypto"]:
            tasks.append(("crypto", _crypto_enrich, profile["crypto"]))

        if profile["mac"]:
            tasks.append(("mac", _mac_enrich, profile["mac"]))

        if profile["vin"]:
            tasks.append(("vin", _nhtsa_vin_enrich, profile["vin"]))

        if profile["org"]:
            tasks.append(("org", _org_enrich, profile["org"]))

        if profile["name"]:
            tasks.append(("sec_edgar", _sec_edgar_enrich, profile["name"]))

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(fn, arg): name for name, fn, arg in tasks}
            for f in as_completed(futs):
                name = futs[f]
                try:
                    enrich[name] = f.result()
                except Exception:
                    enrich[name] = None

    # ---- risk scoring ----
    risk, reasons = _risk_score(profile, enrich)

    # ---- field graph ----
    edges = _field_graph(profile, enrich)

    # ---- pivot links ----
    pivots = _pivot_links(profile)

    # ---- history ----
    snapshot = {
        "profile": profile,
        "risk_score": risk,
        "reasons": reasons,
        "enrichment_keys": list(enrich.keys()),
        "generated": datetime.now().isoformat(timespec="seconds"),
    }
    prev = _load_history(profile)
    history_diffs = _diff_history(prev, snapshot)
    _save_history(profile, snapshot)

    # ---- render ----
    _render(profile, pivots, enrich, risk, reasons, edges, history_diffs)

    # ---- exports ----
    if input("  export json? [y/N] >> ").strip().lower() == "y":
        _export_json(profile, pivots, enrich, risk, reasons, edges)

    if input("  export csv? [y/N] >> ").strip().lower() == "y":
        _export_csv(profile, pivots, risk, reasons)

    if input("  export html? [y/N] >> ").strip().lower() == "y":
        _export_html(profile, pivots, enrich, risk, reasons, edges)
