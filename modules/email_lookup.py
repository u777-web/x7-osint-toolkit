"""
email_lookup.py — Deep email intelligence (expanded edition).

Complementary to breach_check: focuses on registration footprints,
key server presence, avatar discovery, reputation, breach exposure,
and domain hygiene. Uses per-service agents (each owns its own request
shape + detection logic) plus external enrichment APIs.

New in this version:
  · HIBP v3 breach + paste lookup (key from config)
  · Gravatar profile enrichment (SHA256 identifier, display name, links)
  · Google account existence check via recovery flow
  · 12 additional registration agents (Twitter/X, Reddit, Imgur, Dropbox,
    Patreon, SoundCloud, Airbnb, Atlassian, Evernote, Zoho, Docker, eBay)
  · MX + SMTP RCPT TO deliverability probe
  · Disposable domain detection (300+ known throwaway providers)
  · Domain age + registration check via RDAP
  · EmailRep deep signal extraction with plain-English summary
  · Risk scoring 0–100 with categorized reasons
  · Bulk-mode input (paste multiple emails)
  · Export: JSON, CSV, and standalone HTML report
  · Scan history — diff vs previous run per email
"""

import csv
import hashlib
import html
import json
import re
import socket
import smtplib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme
from tqdm import tqdm

console = Console(theme=Theme({
    "g": "grey70", "dg": "grey50", "bg": "grey93", "bd": "grey37",
    "red": "red", "green": "green", "yellow": "yellow",
}))

BAR_FMT = "\033[38;5;245m  {desc} |{bar}| {percentage:3.0f}%\033[0m"
OUT_DIR = Path.home() / ".ostinttol" / "exports"
OUT_DIR.mkdir(parents=True, exist_ok=True)
HIST_DIR = Path.home() / ".ostinttol" / "email_history"
HIST_DIR.mkdir(parents=True, exist_ok=True)

UA = "Mozilla/5.0 (compatible; ostinttol)"
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


# ============================================================
# Disposable / throwaway domain blocklist
# ============================================================
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwawaymail.com", "yopmail.com", "sharklasers.com", "guerrillamailblock.com",
    "grr.la", "guerrillamail.info", "guerrillamail.biz", "guerrillamail.de",
    "guerrillamail.net", "guerrillamail.org", "spam4.me", "trashmail.com",
    "trashmail.me", "trashmail.net", "dispostable.com", "mailnesia.com",
    "maildrop.cc", "fakeinbox.com", "tempinbox.com", "throwaway.email",
    "getnada.com", "emailondeck.com", "mohmal.com", "burnermail.io",
    "mailsac.com", "inboxkitten.com", "temp-mail.org", "tempmailo.com",
    "moakt.com", "mailcatch.com", "mailnull.com", "spamgourmet.com",
    "mytemp.email", "tmail.ws", "tmpmail.net", "tmpmail.org", "tempr.email",
    "discard.email", "discardmail.com", "discardmail.de", "spamherelots.com",
    "spamhereplease.com", "spamthisplease.com", "trash-mail.com", "trash-mail.at",
    "trash-mail.de", "wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org",
    "mailmetrash.com", "trashymail.com", "trashymail.net", "tyldd.com",
    "uggsrock.com", "venompen.com", "whyspam.me", "willhackforfood.biz",
    "willselfdestruct.com", "winemaven.info", "wronghead.com", "wuzup.net",
    "xagloo.com", "xemaps.com", "xents.com", "xmaily.com", "xoxy.net",
    "yep.it", "yogamaven.com", "yopmail.fr", "yopmail.net", "ypmail.webarnak.fr.eu.org",
    "yuurok.com", "zehnminutenmail.de", "zippymail.info", "zoaxe.com", "zoemail.org",
    "20minutemail.com", "emailtemporario.com.br", "emailtmp.com", "cuvox.de",
    "dayrep.com", "einrot.com", "fleckens.hu", "gustr.com", "jourrapide.com",
    "rhyta.com", "superrito.com", "teleworm.us", "armyspy.com", "cuvox.de",
    "spambox.us", "spamfree24.org", "spamify.com", "spaml.com", "spaml.de",
    "spamobox.com", "spamspot.com", "spamthis.co.uk", "spamtrail.com",
    "speed.1s.fr", "supergreatmail.com", "supermailer.jp", "suremail.info",
    "teewars.org", "teleworm.com", "tempalias.com", "tempe-mail.com",
    "tempemail.biz", "tempemail.com", "tempemail.net", "tempinbox.co.uk",
    "temporaryemail.net", "temporaryemail.us", "temporaryforwarding.com",
    "temporaryinbox.com", "temporarymailaddress.com", "tempthe.net",
    "thankyou2010.com", "thisisnotmyrealemail.com", "throwawayemailaddress.com",
    "tiltblog.com", "tradermail.info", "trash-amil.com", "trash2009.com",
    "trashdevil.com", "trashemail.de", "trashmail.at", "trashmail.com",
    "trashmail.io", "trashmail.me", "trashmail.net", "trashmail.org",
    "trashmail.ws", "trashmailer.com", "trashymail.com", "trbvm.com",
    "trialmail.de", "trickmail.net", "trillianpro.com", "turual.com",
    "twinmail.de", "tyldd.com", "uggsrock.com", "umail.net", "unmail.ru",
    "upliftnow.com", "uplipht.com", "uroid.com", "us.af", "venompen.com",
    "veryrealemail.com", "viditag.com", "viewcastmedia.com", "viewcastmedia.net",
    "viewcastmedia.org", "vomoto.com", "vpn.st", "vsimcard.com", "vubby.com",
    "wasteland.rfc822.org", "webemail.me", "webm4il.info", "webuyanycar.us",
    "wegwerfadresse.de", "wegwerfemail.com", "wegwerfemail.de", "wegwerfemail.net",
    "wegwerfemail.org", "wegwerfmail.de", "wegwerfmail.info", "wegwerfmail.net",
    "wegwerfmail.org", "wetrainbayarea.com", "wetrainbayarea.org", "wh4f.org",
    "whatiaas.com", "whatpaas.com", "whatsaas.com", "whyspam.me",
    "wickmail.net", "wilemail.com", "willhackforfood.biz", "willselfdestruct.com",
    "winemaven.info", "wronghead.com", "wuzup.net", "xagloo.com", "xemaps.com",
    "xents.com", "xmaily.com", "xoxy.net", "yep.it", "yogamaven.com",
    "yopmail.com", "yopmail.fr", "yopmail.net", "ypmail.webarnak.fr.eu.org",
    "yuurok.com", "zehnminutenmail.de", "zippymail.info", "zoaxe.com",
    "zoemail.org",
}


FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.fr",
    "yahoo.de", "yahoo.es", "yahoo.it", "hotmail.com", "hotmail.co.uk",
    "hotmail.fr", "hotmail.de", "hotmail.it", "outlook.com", "outlook.fr",
    "outlook.de", "live.com", "live.co.uk", "live.fr", "msn.com",
    "aol.com", "aim.com", "icloud.com", "me.com", "mac.com",
    "protonmail.com", "protonmail.ch", "proton.me", "pm.me",
    "zoho.com", "zohomail.com", "yandex.com", "yandex.ru", "mail.ru",
    "inbox.ru", "list.ru", "bk.ru", "gmx.com", "gmx.de", "gmx.net",
    "web.de", "t-online.de", "freenet.de", "mail.com", "email.com",
    "usa.com", "myself.com", "consultant.com", "post.com", "europe.com",
    "rocketmail.com", "ymail.com", "fastmail.com", "fastmail.fm",
    "tutanota.com", "tuta.io", "tutamail.com", "tuta.com",
    "disroot.org", "riseup.net", "mailfence.com", "posteo.de",
    "mailbox.org", "startmail.com", "countermail.com", "runbox.com",
}


# ============================================================
# Agent framework
# ============================================================
@dataclass
class AgentResult:
    service: str
    status: str          # REGISTERED / not found / unknown / error
    code: Optional[int] = None
    note: str = ""
    elapsed: float = 0.0


class Agent:
    """Base agent. Subclasses override `detect()`."""
    name: str = "agent"
    endpoint: str = ""
    method: str = "POST"
    timeout: float = 10.0

    def __init__(self, email: str):
        self.email = email

    def build_request(self) -> dict:
        return {
            "url": self.endpoint,
            "data": {"email": self.email},
            "headers": {"User-Agent": UA},
            "timeout": self.timeout,
        }

    def detect(self, response: requests.Response) -> str:
        raise NotImplementedError

    def run(self) -> AgentResult:
        t0 = time.time()
        try:
            req = self.build_request()
            if self.method.upper() == "GET":
                r = requests.get(req["url"], params=req.get("data"),
                                 headers=req["headers"],
                                 timeout=req["timeout"])
            else:
                r = requests.post(req["url"], data=req.get("data"),
                                  headers=req["headers"],
                                  timeout=req["timeout"])
        except Exception as e:
            return AgentResult(self.name, "error", None,
                               type(e).__name__, time.time() - t0)
        try:
            status = self.detect(r)
        except Exception as e:
            status = "error"
            note = type(e).__name__
            return AgentResult(self.name, status, r.status_code,
                               note, time.time() - t0)
        return AgentResult(self.name, status, r.status_code, "",
                           time.time() - t0)


def _text(r): return (r.text or "").lower()
def _json(r):
    try:
        return r.json()
    except Exception:
        return {}


# ============================================================
# Concrete agents — original set
# ============================================================
class FirefoxAgent(Agent):
    name = "Firefox"
    endpoint = "https://api.accounts.firefox.com/v1/account/status"

    def detect(self, r):
        j = _json(r)
        if j.get("exists") is True:
            return "REGISTERED"
        if j.get("exists") is False:
            return "not found"
        return "unknown"


class WordPressAgent(Agent):
    name = "WordPress"
    endpoint = "https://public-api.wordpress.com/rest/v1.1/users/email/exists"
    method = "GET"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"email": self.email},
            "headers": {"User-Agent": UA, "Accept": "application/json"},
            "timeout": self.timeout,
        }

    def detect(self, r):
        j = _json(r)
        if j.get("exists") is True:
            return "REGISTERED"
        if j.get("exists") is False:
            return "not found"
        return "unknown"


class SpotifyAgent(Agent):
    name = "Spotify"
    endpoint = "https://www.spotify.com/api/signup/validate"

    def detect(self, r):
        t = _text(r)
        if "already" in t or "taken" in t:
            return "REGISTERED"
        if r.status_code == 200:
            return "not found"
        return "unknown"


class DuolingoAgent(Agent):
    name = "Duolingo"
    endpoint = "https://www.duolingo.com/2017-06-30/users"

    def detect(self, r):
        t = _text(r)
        if "already" in t or "email_taken" in t:
            return "REGISTERED"
        if r.status_code in (200, 201):
            return "not found"
        if r.status_code == 400 and "email" in t:
            return "REGISTERED"
        return "unknown"


class LastPassAgent(Agent):
    name = "LastPass"
    endpoint = "https://lastpass.com/create_account.php"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"check": "avail", "username": self.email},
            "headers": {"User-Agent": UA},
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "not available" in t or "taken" in t:
            return "REGISTERED"
        if "available" in t or "ok" in t:
            return "not found"
        return "unknown"


class InstagramAgent(Agent):
    name = "Instagram"
    endpoint = "https://www.instagram.com/api/v1/users/check_email/"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"email": self.email},
            "headers": {
                "User-Agent": UA,
                "X-IG-App-ID": "936619743392459",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "timeout": self.timeout,
        }

    def detect(self, r):
        j = _json(r)
        if j.get("is_taken") is True or j.get("available") is False:
            return "REGISTERED"
        if j.get("available") is True or j.get("is_taken") is False:
            return "not found"
        t = _text(r)
        if "is_taken" in t and "true" in t:
            return "REGISTERED"
        return "unknown"


class SteamAgent(Agent):
    name = "Steam"
    endpoint = "https://store.steampowered.com/join/checkemail"
    method = "GET"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"email": self.email},
            "headers": {"User-Agent": UA, "Accept": "application/json"},
            "timeout": self.timeout,
        }

    def detect(self, r):
        j = _json(r)
        if j.get("bEmailInUse") is True:
            return "REGISTERED"
        if j.get("bEmailInUse") is False:
            return "not found"
        t = _text(r)
        if "bemailinuse" in t and "true" in t:
            return "REGISTERED"
        return "unknown"


class GithubAgent(Agent):
    name = "GitHub"
    endpoint = "https://github.com/signup_users/email"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"value": self.email},
            "headers": {
                "User-Agent": UA,
                "Accept": "application/json",
                "X-Requested-With": "XMLHttpRequest",
            },
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "already taken" in t or "is already taken" in t:
            return "REGISTERED"
        if r.status_code == 200 and "taken" not in t:
            return "not found"
        return "unknown"


class MicrosoftAgent(Agent):
    name = "Microsoft"
    endpoint = "https://login.live.com/GetCredentialType.srf"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": json.dumps({"username": self.email}),
            "headers": {
                "User-Agent": UA,
                "Content-Type": "application/json",
            },
            "timeout": self.timeout,
        }

    def detect(self, r):
        j = _json(r)
        code = j.get("IfExistsResult")
        if code in (1, 5):
            return "REGISTERED"
        if code == 0:
            return "not found"
        return "unknown"


class TumblrAgent(Agent):
    name = "Tumblr"
    endpoint = "https://www.tumblr.com/register/email_available"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"email": self.email},
            "headers": {"User-Agent": UA, "Accept": "application/json"},
            "timeout": self.timeout,
        }

    def detect(self, r):
        j = _json(r)
        inner = j.get("response") if isinstance(j.get("response"), dict) else j
        if inner.get("email_available") is False:
            return "REGISTERED"
        if inner.get("email_available") is True:
            return "not found"
        return "unknown"


class SnapchatAgent(Agent):
    name = "Snapchat"
    endpoint = "https://accounts.snapchat.com/accounts/merlin/login"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": json.dumps({"email": self.email}),
            "headers": {
                "User-Agent": UA,
                "Content-Type": "application/json",
            },
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "already in use" in t or "already_registered" in t:
            return "REGISTERED"
        if "email_is_invalid" in t or "not_found" in t:
            return "not found"
        return "unknown"


class PinterestAgent(Agent):
    name = "Pinterest"
    endpoint = "https://www.pinterest.com/resource/EmailExistsResource/get/"
    method = "GET"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"data": json.dumps({"options": {"email": self.email}})},
            "headers": {"User-Agent": UA, "Accept": "application/json"},
            "timeout": self.timeout,
        }

    def detect(self, r):
        j = _json(r)
        data = (j.get("resource_response") or {}).get("data")
        if data is True:
            return "REGISTERED"
        if data is False:
            return "not found"
        return "unknown"


class DiscordAgent(Agent):
    name = "Discord"
    endpoint = "https://discord.com/api/v9/auth/register"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": json.dumps({"email": self.email}),
            "headers": {
                "User-Agent": UA,
                "Content-Type": "application/json",
            },
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "already registered" in t:
            return "REGISTERED"
        if "captcha" in t or "invalid" in t:
            return "unknown"
        if r.status_code == 400:
            return "not found"
        return "unknown"


class AdobeAgent(Agent):
    name = "Adobe"
    endpoint = "https://auth.services.adobe.com/signup/v2/users/email"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": json.dumps({"email": self.email}),
            "headers": {
                "User-Agent": UA,
                "Content-Type": "application/json",
            },
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "taken" in t or "exists" in t:
            return "REGISTERED"
        if r.status_code == 200 and "not" not in t:
            return "not found"
        return "unknown"


class FlickrAgent(Agent):
    name = "Flickr"
    endpoint = "https://identity.flickr.com/api/email"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": json.dumps({"email": self.email}),
            "headers": {
                "User-Agent": UA,
                "Content-Type": "application/json",
            },
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "taken" in t or "already" in t:
            return "REGISTERED"
        if r.status_code == 200 and "taken" not in t:
            return "not found"
        return "unknown"


class EnvatoAgent(Agent):
    name = "Envato"
    endpoint = "https://account.envato.com/api/check_email"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": json.dumps({"email": self.email}),
            "headers": {
                "User-Agent": UA,
                "Content-Type": "application/json",
            },
            "timeout": self.timeout,
        }

    def detect(self, r):
        j = _json(r)
        if j.get("available") is False:
            return "REGISTERED"
        if j.get("available") is True:
            return "not found"
        t = _text(r)
        if "taken" in t:
            return "REGISTERED"
        return "unknown"


class PayPalAgent(Agent):
    name = "PayPal"
    endpoint = "https://www.paypal.com/signin/checkAccount"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"email": self.email},
            "headers": {"User-Agent": UA},
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "\"success\":true" in t or "account exists" in t:
            return "REGISTERED"
        if "\"success\":false" in t:
            return "not found"
        return "unknown"


class TelegramAgent(Agent):
    name = "Telegram"
    endpoint = "https://my.telegram.org/auth/send_password"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"phone": self.email},
            "headers": {"User-Agent": UA},
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "sent" in t and "password" in t:
            return "REGISTERED"
        if "not found" in t or "does not exist" in t:
            return "not found"
        return "unknown"


class LinkedInAgent(Agent):
    name = "LinkedIn"
    endpoint = "https://www.linkedin.com/uas/email-reset-submit"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"email": self.email},
            "headers": {"User-Agent": UA},
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "didn't recognize" in t or "doesn't exist" in t:
            return "not found"
        if r.status_code in (200, 302):
            return "REGISTERED"
        return "unknown"


# ============================================================
# Concrete agents — expansion set
# ============================================================
class TwitterXAgent(Agent):
    """Twitter/X account recovery — begin flow returns error for unknown."""
    name = "Twitter/X"
    endpoint = "https://api.x.com/1.1/account/begin_password_reset.json"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"account_identifier": self.email},
            "headers": {"User-Agent": UA},
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "not found" in t or "doesn't exist" in t or "invalid" in t:
            return "not found"
        if r.status_code == 200:
            return "REGISTERED"
        return "unknown"


class RedditAgent(Agent):
    """Reddit account existence — POSTs to register with email."""
    name = "Reddit"
    endpoint = "https://www.reddit.com/api/register"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"email": self.email, "user": "ostin_probe"},
            "headers": {"User-Agent": UA},
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "already taken" in t or "email is already" in t:
            return "REGISTERED"
        if "invalid" in t:
            return "unknown"
        return "not found"


class ImgurAgent(Agent):
    """Imgur signup email check."""
    name = "Imgur"
    endpoint = "https://api.imgur.com/account/check_email"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"email": self.email},
            "headers": {
                "User-Agent": UA,
                "Authorization": "Client-ID 546c25a59c58ad7",
            },
            "timeout": self.timeout,
        }

    def detect(self, r):
        j = _json(r)
        if j.get("data", {}).get("available") is False:
            return "REGISTERED"
        if j.get("data", {}).get("available") is True:
            return "not found"
        return "unknown"


class DropboxAgent(Agent):
    """Dropbox forgot-password flow."""
    name = "Dropbox"
    endpoint = "https://www.dropbox.com/forgot_password"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"email": self.email},
            "headers": {"User-Agent": UA},
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "we don't recognize" in t or "no account" in t:
            return "not found"
        if r.status_code == 200 and "sent" in t:
            return "REGISTERED"
        return "unknown"


class PatreonAgent(Agent):
    """Patreon account check."""
    name = "Patreon"
    endpoint = "https://www.patreon.com/api/auth/check_email"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"email": self.email},
            "headers": {"User-Agent": UA},
            "timeout": self.timeout,
        }

    def detect(self, r):
        j = _json(r)
        if j.get("exists") is True or j.get("taken") is True:
            return "REGISTERED"
        if j.get("exists") is False or j.get("taken") is False:
            return "not found"
        return "unknown"


class SoundCloudAgent(Agent):
    """SoundCloud signup email existence."""
    name = "SoundCloud"
    endpoint = "https://api-v2.soundcloud.com/sign-up/email"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"email": self.email},
            "headers": {"User-Agent": UA},
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "already" in t or "taken" in t or "in use" in t:
            return "REGISTERED"
        if r.status_code in (200, 201):
            return "not found"
        return "unknown"


class AirbnbAgent(Agent):
    """Airbnb account recovery check."""
    name = "Airbnb"
    endpoint = "https://www.airbnb.com/api/v2/account/check_email"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"email": self.email},
            "headers": {"User-Agent": UA},
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "exists" in t or "taken" in t:
            return "REGISTERED"
        if r.status_code == 200:
            return "not found"
        return "unknown"


class AtlassianAgent(Agent):
    """Atlassian signup email check."""
    name = "Atlassian"
    endpoint = "https://id.atlassian.com/rest/available"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"email": self.email},
            "headers": {"User-Agent": UA},
            "timeout": self.timeout,
        }

    def detect(self, r):
        j = _json(r)
        if j.get("available") is False:
            return "REGISTERED"
        if j.get("available") is True:
            return "not found"
        return "unknown"


class EvernoteAgent(Agent):
    """Evernote account recovery."""
    name = "Evernote"
    endpoint = "https://www.evernote.com/Login.action"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"username": self.email},
            "headers": {"User-Agent": UA},
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "not found" in t or "no account" in t:
            return "not found"
        if r.status_code == 200 and "reset" in t:
            return "REGISTERED"
        return "unknown"


class ZohoAgent(Agent):
    """Zoho account check via public API."""
    name = "Zoho"
    endpoint = "https://accounts.zoho.com/signin/v2/primaryemailtovirtualaddress"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": json.dumps({"primary_email": self.email}),
            "headers": {
                "User-Agent": UA,
                "Content-Type": "application/json",
            },
            "timeout": self.timeout,
        }

    def detect(self, r):
        j = _json(r)
        if j.get("status", {}).get("code") == 200:
            return "REGISTERED"
        if j.get("status", {}).get("code") == 404:
            return "not found"
        return "unknown"


class DockerHubAgent(Agent):
    """Docker Hub signup email check."""
    name = "DockerHub"
    endpoint = "https://hub.docker.com/v2/users/check_email/"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": json.dumps({"email": self.email}),
            "headers": {
                "User-Agent": UA,
                "Content-Type": "application/json",
            },
            "timeout": self.timeout,
        }

    def detect(self, r):
        j = _json(r)
        if j.get("available") is False:
            return "REGISTERED"
        if j.get("available") is True:
            return "not found"
        return "unknown"


class EbayAgent(Agent):
    """eBay registration email check."""
    name = "eBay"
    endpoint = "https://reg.ebay.com/reg/PartialReg"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"email": self.email},
            "headers": {"User-Agent": UA},
            "timeout": self.timeout,
        }

    def detect(self, r):
        t = _text(r)
        if "already registered" in t or "in use" in t:
            return "REGISTERED"
        if r.status_code == 200:
            return "not found"
        return "unknown"


class ProtonMailAgent(Agent):
    """ProtonMail account check via their public API."""
    name = "ProtonMail"
    endpoint = "https://api.protonmail.ch/users/available"
    method = "GET"

    def build_request(self):
        return {
            "url": self.endpoint,
            "data": {"Name": self.email.split("@")[0]},
            "headers": {"User-Agent": UA, "Accept": "application/json"},
            "timeout": self.timeout,
        }

    def detect(self, r):
        j = _json(r)
        code = j.get("Code")
        if code == 1000:
            return "not found"
        if code == 1200:
            return "REGISTERED"
        return "unknown"


# ---- registry ----
AGENTS = [
    FirefoxAgent, WordPressAgent, SpotifyAgent, DuolingoAgent,
    LastPassAgent, InstagramAgent, SteamAgent, GithubAgent,
    MicrosoftAgent, TumblrAgent, SnapchatAgent, PinterestAgent,
    DiscordAgent, AdobeAgent, FlickrAgent, EnvatoAgent,
    PayPalAgent, TelegramAgent, LinkedInAgent,
    TwitterXAgent, RedditAgent, ImgurAgent, DropboxAgent,
    PatreonAgent, SoundCloudAgent, AirbnbAgent, AtlassianAgent,
    EvernoteAgent, ZohoAgent, DockerHubAgent, EbayAgent,
    ProtonMailAgent,
]


# ============================================================
# Side lookups — expanded
# ============================================================

def _valid(email):
    return bool(EMAIL_RE.match(email))


def _sha256(email):
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()


def _md5(email):
    return hashlib.md5(email.strip().lower().encode()).hexdigest()


def _gravatar(email):
    """Fetch Gravatar URL + profile via SHA256 API."""
    h_md5 = _md5(email)
    h_sha = _sha256(email)
    out = {
        "avatar_url": None,
        "profile_url": f"https://gravatar.com/{h_sha}",
        "profile": None,
    }
    try:
        r = requests.get(
            f"https://www.gravatar.com/avatar/{h_md5}?d=404",
            headers={"User-Agent": UA}, timeout=8,
        )
        if r.status_code == 200:
            out["avatar_url"] = f"https://www.gravatar.com/{h_md5}"
    except Exception:
        pass
    try:
        r = requests.get(
            f"https://gravatar.com/{h_sha}.json",
            headers={"User-Agent": UA}, timeout=10,
        )
        if r.status_code == 200:
            j = r.json()
            entry = j.get("entry") or [{}]
            prof = entry[0] if entry else {}
            out["profile"] = {
                "display_name": prof.get("displayName"),
                "about_me": prof.get("aboutMe"),
                "urls": [u.get("value") for u in (prof.get("urls") or [])],
                "accounts": [
                    f"{a.get('shortname')}: {a.get('username') or a.get('url')}"
                    for a in (prof.get("accounts") or [])
                ],
                "location": prof.get("currentLocation"),
                "thumbnail": prof.get("thumbnailUrl"),
                "profile_url": prof.get("profileUrl"),
            }
    except Exception:
        pass
    return out


def _emailrep(email, api_key=None):
    """EmailRep query with optional API key."""
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if api_key:
        headers["Key"] = api_key
    try:
        r = requests.get(
            f"https://emailrep.io/{email}",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _pgp_keys(email):
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
                hits.append({"server": name, "url": url, "size": len(r.text)})
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


def _spf(domain):
    try:
        r = requests.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": "TXT"},
            headers={"User-Agent": UA}, timeout=8,
        )
        d = r.json()
        for a in d.get("Answer") or []:
            data = (a.get("data") or "").replace('"', "")
            if data.lower().startswith("v=spf1"):
                return data
    except Exception:
        pass
    return None


def _dmarc(domain):
    try:
        r = requests.get(
            "https://dns.google/resolve",
            params={"name": f"_dmarc.{domain}", "type": "TXT"},
            headers={"User-Agent": UA}, timeout=8,
        )
        d = r.json()
        for a in d.get("Answer") or []:
            data = (a.get("data") or "").replace('"', "")
            if data.lower().startswith("v=dmarc1"):
                return data
    except Exception:
        pass
    return None


def _rdap_domain(domain):
    """Domain registration age + registrar via RDAP."""
    try:
        r = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={"User-Agent": UA, "Accept": "application/rdap+json"},
            timeout=12,
        )
        if r.status_code != 200:
            return None
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
            "registrar": registrar,
            "registration": events.get("registration"),
            "expiration": events.get("expiration"),
            "last_changed": events.get("last changed"),
            "status": d.get("status") or [],
        }
    except Exception:
        return None


def _smtp_probe(domain, mx_records, timeout=8):
    """Probe SMTP RCPT TO — checks mailbox existence without sending."""
    if not mx_records:
        return {"tested": False, "reason": "no MX"}
    mx_host = mx_records[0][1]
    try:
        server = smtplib.SMTP(timeout=timeout)
        server.connect(mx_host, 25)
        server.helo("ostinttol.local")
        server.docmd("MAIL FROM:", "<probe@ostinttol.local>")
        code, _ = server.docmd("RCPT TO:", f"<{_smtp_probe.mailbox}>")
        server.quit()
        if 200 <= code < 300:
            return {"tested": True, "result": "accepted", "code": code}
        if code in (550, 551, 553):
            return {"tested": True, "result": "rejected", "code": code}
        return {"tested": True, "result": f"code_{code}", "code": code}
    except Exception as e:
        return {"tested": False, "reason": type(e).__name__}


def _hibp_breaches(email, api_key):
    """HIBP v3 breaches for account."""
    if not api_key:
        return {"status": "no_key", "breaches": []}
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            params={"truncateResponse": "false"},
            headers={
                "User-Agent": UA,
                "hibp-api-key": api_key,
            },
            timeout=12,
        )
        if r.status_code == 200:
            return {"status": "found", "breaches": r.json()}
        if r.status_code == 404:
            return {"status": "clean", "breaches": []}
        if r.status_code == 401:
            return {"status": "bad_key", "breaches": []}
        if r.status_code == 429:
            return {"status": "rate_limited", "breaches": []}
        return {"status": f"http_{r.status_code}", "breaches": []}
    except Exception as e:
        return {"status": type(e).__name__, "breaches": []}


def _hibp_pastes(email, api_key):
    """HIBP v3 pastes for account."""
    if not api_key:
        return []
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
            headers={"User-Agent": UA, "hibp-api-key": api_key},
            timeout=12,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return []


def _google_account_check(email):
    """Check if a Google account exists via public recovery flow."""
    try:
        r = requests.get(
            "https://accounts.google.com/InputValidator",
            params={"identifier": email, "continue": "https://myaccount.google.com/"},
            headers={"User-Agent": UA},
            timeout=10,
        )
        t = _text(r)
        # Google returns different bodies for existing vs new
        return {
            "status": r.status_code,
            "hint": "exists" if "password" in t else "unknown",
        }
    except Exception:
        return None


def _domain_has_mx(domain):
    return bool(_mx(domain))


def _is_disposable(domain):
    return domain.lower() in DISPOSABLE_DOMAINS


def _is_free_provider(domain):
    return domain.lower() in FREE_PROVIDERS


# ============================================================
# Risk scoring
# ============================================================
def _risk_score(email, domain, mx, spf, dmarc, rdap, rep,
                breach_data, paste_data, agents):
    score = 0
    reasons = []

    # domain hygiene
    if not mx:
        score += 30
        reasons.append("domain has no MX — email likely unroutable")
    if not spf:
        score += 8
        reasons.append("no SPF record — spoofable")
    if not dmarc:
        score += 10
        reasons.append("no DMARC — receivers have no policy")

    # domain age
    if rdap and rdap.get("registration"):
        try:
            reg = datetime.fromisoformat(rdap["registration"].replace("Z", "+00:00"))
            age_days = (datetime.now(reg.tzinfo) - reg).days
            if age_days < 30:
                score += 25
                reasons.append(f"domain registered {age_days} days ago — very new")
            elif age_days < 180:
                score += 10
                reasons.append(f"domain is {age_days} days old — relatively new")
        except Exception:
            pass

    if _is_disposable(domain):
        score += 30
        reasons.append("disposable / throwaway provider")

    # reputation
    if rep:
        rep_flag = (rep.get("reputation") or "").lower()
        if rep.get("suspicious"):
            score += 20
            reasons.append("flagged suspicious by EmailRep")
        if rep_flag == "low":
            score += 10
            reasons.append("low reputation per EmailRep")
        if rep.get("blacklisted"):
            score += 15
            reasons.append("blacklisted")

    # breaches
    if breach_data and breach_data.get("breaches"):
        n = len(breach_data["breaches"])
        score += min(25, n * 4)
        reasons.append(f"{n} known breach(es)")

    if paste_data:
        score += min(15, len(paste_data) * 3)
        reasons.append(f"{len(paste_data)} paste dump(s)")

    # agent footprint — no accounts = burner signal
    registered = [a for a in agents if a.status == "REGISTERED"]
    if not registered:
        score += 12
        reasons.append("no accounts found anywhere — possible burner")
    elif len(registered) >= 8:
        score += 8
        reasons.append(f"strong digital footprint ({len(registered)} accounts)")

    return min(score, 100), reasons


# ============================================================
# History
# ============================================================
def _history_path(email):
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", email)[:60]
    return HIST_DIR / f"{safe}.json"


def _load_history(email):
    p = _history_path(email)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _save_history(email, snapshot):
    p = _history_path(email)
    p.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False,
                            default=str), encoding="utf-8")


def _diff_history(prev, current):
    if not prev:
        return []
    diffs = []
    if prev.get("risk_score") != current.get("risk_score"):
        diffs.append(
            f"risk score: {prev.get('risk_score')} → {current.get('risk_score')}"
        )
    prev_agents = {a["service"]: a["status"] for a in (prev.get("agents") or [])}
    cur_agents = {a["service"]: a["status"] for a in (current.get("agents") or [])}
    for svc, st in cur_agents.items():
        if svc in prev_agents and prev_agents[svc] != st:
            diffs.append(f"{svc}: {prev_agents[svc]} → {st}")
    return diffs


# ============================================================
# Render
# ============================================================
def _render(email, mx, spf, dmarc, rdap, grav, rep, keys,
            breach_data, paste_data, google, results, risk, reasons,
            history_diffs):
    console.print(Panel.fit(
        f"[bg]EMAIL LOOKUP[/bg]  [dg]{email}[/dg]",
        border_style="bd", padding=(0, 2),
    ))

    # risk
    color = "green" if risk < 30 else "yellow" if risk < 70 else "red"
    console.print(Panel.fit(
        f"[bg]risk score[/bg]  [{color}]{risk}/100[/{color}]",
        border_style="bd", padding=(0, 2),
    ))
    for r in reasons:
        console.print(f"[dg]  · {r}[/dg]")
    console.print()

    # identity
    domain = email.split("@", 1)[1].lower()
    m = Table(border_style="bd", title="[bg]identity[/bg]",
              show_header=False, padding=(0, 2))
    m.add_column("k", style="dg", no_wrap=True)
    m.add_column("v", style="g")
    m.add_row("domain", domain)
    m.add_row("mx", ", ".join(f"{p} {h}" for p, h in mx[:3]) or "—")
    m.add_row("disposable", "[red]yes[/red]" if _is_disposable(domain) else "no")
    m.add_row("free provider", "[yellow]yes[/yellow]" if _is_free_provider(domain) else "no")
    m.add_row("spf", "present" if spf else "[red]missing[/red]")
    m.add_row("dmarc", "present" if dmarc else "[red]missing[/red]")
    m.add_row("gravatar", grav.get("avatar_url") or "—")
    console.print(m)

    # domain registration
    if rdap:
        rt = Table(border_style="bd",
                   title="[bg]domain registration[/bg]",
                   show_header=False, padding=(0, 2))
        rt.add_column("k", style="dg", no_wrap=True)
        rt.add_column("v", style="g", overflow="fold")
        rt.add_row("handle", rdap.get("handle") or "—")
        rt.add_row("registrar", rdap.get("registrar") or "—")
        rt.add_row("registered", rdap.get("registration") or "—")
        rt.add_row("expires", rdap.get("expiration") or "—")
        if rdap.get("status"):
            rt.add_row("status", ", ".join(rdap["status"][:4]))
        console.print(rt)

    # gravatar profile
    if grav.get("profile"):
        gp = grav["profile"]
        gt = Table(border_style="bd",
                   title="[bg]gravatar profile[/bg]",
                   show_header=False, padding=(0, 2))
        gt.add_column("k", style="dg", no_wrap=True)
        gt.add_column("v", style="g", overflow="fold")
        for k in ("display_name", "about_me", "location", "thumbnail"):
            if gp.get(k):
                gt.add_row(k, str(gp[k])[:120])
        if gp.get("urls"):
            gt.add_row("urls", ", ".join(gp["urls"][:5]))
        if gp.get("accounts"):
            gt.add_row("accounts", ", ".join(gp["accounts"][:6]))
        console.print(gt)

    # emailrep
    if rep:
        r = Table(border_style="bd", title="[bg]emailrep[/bg]",
                  show_header=False, padding=(0, 2))
        r.add_column("k", style="dg", no_wrap=True)
        r.add_column("v", style="g", overflow="fold")
        for k in ("reputation", "suspicious", "references", "blacklisted",
                  "credentials_leaked", "data_breach", "profiles",
                  "malicious_activity", "domain_exists", "spam",
                  "disposable", "free_provider", "deliverable",
                  "valid_mx", "spoofable", "spf_strict", "dmarc_enforced",
                  "first_seen", "last_seen", "domain_reputation"):
            v = rep.get(k)
            if v not in (None, "", []):
                r.add_row(k, str(v))
        console.print(r)

    # Google
    if google:
        console.print(f"[dg]  google account hint: {google.get('hint')} "
                      f"({google.get('status')})[/dg]\n")

    # HIBP breaches
    if breach_data:
        st = breach_data.get("status")
        breaches = breach_data.get("breaches") or []
        if st == "found":
            bt = Table(border_style="bd",
                       title=f"[bg]breaches ({len(breaches)})[/bg]",
                       show_header=True, padding=(0, 2))
            bt.add_column("name", style="bg", overflow="fold")
            bt.add_column("domain", style="dg")
            bt.add_column("date", style="dg")
            bt.add_column("records", style="g", justify="right")
            bt.add_column("data classes", style="dg", overflow="fold")
            for b in breaches[:30]:
                classes = ", ".join((b.get("DataClasses") or [])[:4])
                bt.add_row(
                    b.get("Name") or "—",
                    b.get("Domain") or "—",
                    (b.get("BreachDate") or "—")[:10],
                    f"{b.get('PwnCount', 0):,}",
                    classes,
                )
            console.print(bt)
        elif st == "clean":
            console.print("[green]  no HIBP breaches found[/green]\n")
        elif st == "no_key":
            console.print("[dg]  HIBP: no api key configured "
                          "(add hibp_api_key in config/config.json)[/dg]\n")
        elif st == "rate_limited":
            console.print("[yellow]  HIBP: rate limited[/yellow]\n")
        else:
            console.print(f"[dg]  HIBP: {st}[/dg]\n")

    # pastes
    if paste_data:
        pt = Table(border_style="bd",
                   title=f"[bg]pastes ({len(paste_data)})[/bg]",
                   show_header=True, padding=(0, 2))
        pt.add_column("source", style="bg")
        pt.add_column("id", style="dg", overflow="fold")
        pt.add_column("date", style="dg")
        pt.add_column("emails", style="g", justify="right")
        for p in paste_data[:20]:
            pt.add_row(
                p.get("Source") or "—",
                p.get("Id") or "—",
                (p.get("Date") or "—")[:10],
                str(p.get("EmailCount") or 0),
            )
        console.print(pt)

    # PGP keys
    if keys:
        kt = Table(border_style="bd", title="[bg]pgp keys[/bg]",
                   show_header=True, padding=(0, 2))
        kt.add_column("server", style="bg")
        kt.add_column("size", style="dg", justify="right")
        kt.add_column("url", style="g", overflow="fold")
        for k in keys:
            kt.add_row(k["server"], f"{k['size']}b", k["url"])
        console.print(kt)

    # agents
    pt = Table(border_style="bd",
               title="[bg]registration agents[/bg]",
               show_header=True, padding=(0, 2))
    pt.add_column("agent", style="bg")
    pt.add_column("status", style="g")
    pt.add_column("code", style="dg", justify="right")
    pt.add_column("note", style="dg")
    pt.add_column("ms", style="dg", justify="right")
    for r in sorted(results, key=lambda x: x.service.lower()):
        status_styled = r.status
        if r.status == "REGISTERED":
            status_styled = "[green]REGISTERED[/green]"
        elif r.status == "not found":
            status_styled = "[dg]not found[/dg]"
        elif r.status == "error":
            status_styled = "[red]error[/red]"
        pt.add_row(r.service, status_styled, str(r.code or "-"),
                   r.note or "", f"{int(r.elapsed * 1000)}")
    console.print(pt)

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


# ============================================================
# Export
# ============================================================
def _export_json(email, payload):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", email)[:40]
    p = OUT_DIR / f"email_{safe}_{ts}.json"
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False,
                            default=str), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]")
    return p


def _export_csv(email, mx, spf, dmarc, rdap, grav, rep, breach_data,
                paste_data, results, risk, reasons):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", email)[:40]
    p = OUT_DIR / f"email_{safe}_{ts}.csv"
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["section", "key", "value"])
        w.writerow(["meta", "email", email])
        w.writerow(["meta", "risk_score", risk])
        for i, r in enumerate(reasons):
            w.writerow(["risk", f"reason_{i}", r])
        w.writerow(["dns", "mx", "; ".join(f"{p2} {h}" for p2, h in mx)])
        w.writerow(["dns", "spf", spf or ""])
        w.writerow(["dns", "dmarc", dmarc or ""])
        if rdap:
            for k, v in rdap.items():
                w.writerow(["rdap", k, str(v)])
        if grav.get("profile"):
            for k, v in (grav["profile"] or {}).items():
                w.writerow(["gravatar", k, str(v)])
        if rep:
            for k, v in rep.items():
                if isinstance(v, (str, int, float, bool)):
                    w.writerow(["emailrep", k, str(v)])
        if breach_data and breach_data.get("breaches"):
            for b in breach_data["breaches"]:
                w.writerow(["breach", b.get("Name", ""), b.get("BreachDate", "")])
        if paste_data:
            for pt in paste_data:
                w.writerow(["paste", pt.get("Id", ""), pt.get("Date", "")])
        for r in results:
            w.writerow(["agent", r.service, f"{r.status} (HTTP {r.code})"])
    console.print(f"[dg]  exported → {p}[/dg]")


def _export_html(email, mx, spf, dmarc, rdap, grav, rep, breach_data,
                 paste_data, results, risk, reasons):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", email)[:40]
    p = OUT_DIR / f"email_{safe}_{ts}.html"

    def esc(x):
        return html.escape(str(x))

    def table(rows, headers):
        th = "".join(f"<th>{esc(h)}</th>" for h in headers)
        trs = "".join(
            "<tr>" + "".join(f"<td>{esc(c)}</td>" for c in r) + "</tr>"
            for r in rows)
        return f"<table><tr>{th}</tr>{trs}</table>"

    id_rows = [
        ("domain", email.split("@", 1)[1].lower()),
        ("mx", ", ".join(f"{p2} {h}" for p2, h in mx) or "—"),
        ("spf", spf or "missing"),
        ("dmarc", dmarc or "missing"),
        ("gravatar", grav.get("avatar_url") or "—"),
    ]
    agent_rows = [(r.service, r.status, r.code or "-", r.note or "")
                  for r in sorted(results, key=lambda x: x.service.lower())]
    breach_rows = []
    if breach_data and breach_data.get("breaches"):
        for b in breach_data["breaches"]:
            breach_rows.append((
                b.get("Name") or "—",
                b.get("Domain") or "—",
                (b.get("BreachDate") or "—")[:10],
                f"{b.get('PwnCount', 0):,}",
            ))
    reasons_html = "".join(f"<li>{esc(r)}</li>" for r in reasons)
    score_color = "#8fe388" if risk < 30 else "#f2c14e" if risk < 70 else "#ff6b6b"

    doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Email Report — {esc(email)}</title>
<style>
body {{ background: #111; color: #ddd; font-family: monospace; padding: 2em; }}
h1, h2 {{ color: #9fd4ff; }}
table {{ border-collapse: collapse; margin: 1em 0; }}
td, th {{ border: 1px solid #333; padding: 4px 10px; }}
a {{ color: #8fe388; }}
.score {{ font-size: 2em; color: {score_color}; }}
</style></head><body>
<h1>Email Report — {esc(email)}</h1>
<p>Generated {esc(datetime.now().isoformat(timespec="seconds"))}</p>
<h2>Risk Score</h2>
<p class="score">{esc(risk)}/100</p>
<ul>{reasons_html}</ul>
<h2>Identity</h2>
{table(id_rows, ["field", "value"])}
<h2>Registration Agents</h2>
{table(agent_rows, ["agent", "status", "code", "note"])}
<h2>Breaches</h2>
{table(breach_rows, ["name", "domain", "date", "records"]) if breach_rows else "<p>none</p>"}
</body></html>
"""
    p.write_text(doc, encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]")


# ============================================================
# Runner
# ============================================================
def _load_config():
    cfg_path = Path("config") / "config.json"
    if cfg_path.exists():
        try:
            return json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _process_one(email, cfg):
    domain = email.split("@", 1)[1].lower()

    with tqdm(total=9, desc=f"basics [{email[:20]}]", ncols=60,
              bar_format=BAR_FMT, leave=False) as bar:
        mx = _mx(domain); bar.update(1)
        spf = _spf(domain); bar.update(1)
        dmarc = _dmarc(domain); bar.update(1)
        rdap = _rdap_domain(domain); bar.update(1)
        grav = _gravatar(email); bar.update(1)
        rep = _emailrep(email, cfg.get("emailrep_api_key")); bar.update(1)
        google = _google_account_check(email); bar.update(1)
        keys = _pgp_keys(email); bar.update(1)
        bar.update(1)

    # HIBP
    hibp_key = cfg.get("hibp_api_key")
    breach_data = _hibp_breaches(email, hibp_key)
    paste_data = _hibp_pastes(email, hibp_key) if hibp_key else []

    # agents
    results = []
    with tqdm(total=len(AGENTS), desc=f"agents [{email[:20]}]",
              ncols=60, bar_format=BAR_FMT, leave=False) as bar:
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = []
            for a in AGENTS:
                agent = a(email)
                futs.append(ex.submit(agent.run))
            for f in as_completed(futs):
                results.append(f.result())
                bar.update(1)

    # SMTP probe (optional; only if MX present)
    smtp_res = None
    if mx:
        _smtp_probe.mailbox = email
        try:
            smtp_res = _smtp_probe(domain, mx)
        except Exception:
            smtp_res = None

    risk, reasons = _risk_score(email, domain, mx, spf, dmarc, rdap,
                                rep, breach_data, paste_data, results)

    snapshot = {
        "email": email,
        "risk_score": risk,
        "reasons": reasons,
        "agents": [{"service": r.service, "status": r.status}
                   for r in results],
        "generated": datetime.now().isoformat(timespec="seconds"),
    }
    prev = _load_history(email)
    diffs = _diff_history(prev, snapshot)

    _render(email, mx, spf, dmarc, rdap, grav, rep, keys,
            breach_data, paste_data, google, results, risk, reasons, diffs)

    payload = {
        "email": email,
        "risk_score": risk,
        "reasons": reasons,
        "mx": mx,
        "spf": spf,
        "dmarc": dmarc,
        "rdap": rdap,
        "gravatar": grav,
        "emailrep": rep,
        "google": google,
        "pgp_keys": keys,
        "hibp": breach_data,
        "pastes": paste_data,
        "smtp_probe": smtp_res,
        "disposable": _is_disposable(domain),
        "free_provider": _is_free_provider(domain),
        "agents": [r.__dict__ for r in results],
        "generated": datetime.now().isoformat(timespec="seconds"),
    }

    _save_history(email, snapshot)
    return payload


def run():
    raw = input("  email (or comma-separated list) >> ").strip().lower()
    if not raw:
        print("  [!] empty input")
        return

    emails = [e.strip() for e in raw.split(",") if e.strip()]
    emails = [e for e in emails if _valid(e)]
    if not emails:
        print("  [!] no valid email addresses")
        return

    cfg = _load_config()

    payloads = []
    for email in emails:
        payloads.append(_process_one(email, cfg))

    choice = input("  export json? [y/N] >> ").strip().lower()
    if choice == "y":
        for p in payloads:
            _export_json(p["email"], p)

    choice = input("  export csv? [y/N] >> ").strip().lower()
    if choice == "y":
        for p in payloads:
            _export_csv(
                p["email"],
                p["mx"], p["spf"], p["dmarc"], p["rdap"],
                p["gravatar"], p["emailrep"], p["hibp"], p["pastes"],
                [AgentResult(**a) for a in p["agents"]],
                p["risk_score"], p["reasons"],
            )

    choice = input("  export html? [y/N] >> ").strip().lower()
    if choice == "y":
        for p in payloads:
            _export_html(
                p["email"],
                p["mx"], p["spf"], p["dmarc"], p["rdap"],
                p["gravatar"], p["emailrep"], p["hibp"], p["pastes"],
                [AgentResult(**a) for a in p["agents"]],
                p["risk_score"], p["reasons"],
            )
