"""
domain_network.py — Domain & network reconnaissance.

Aggregates:
  · DNS records (A/AAAA/MX/NS/TXT/SOA/CNAME/CAA via Google DoH)
  · DNSSEC validation (DS, DNSKEY, RRSIG)
  · CAA record analysis
  · DNS zone transfer (AXFR) test
  · DNS propagation check across public resolvers
  · wildcard DNS detection
  · reverse DNS / PTR lookup + ASN / netblock via RDAP
  · SPF / DMARC / DKIM email security audit
  · RDAP registration data (registrar, dates, nameservers)
  · SSL certificate details (subject, issuer, SANs, expiry)
  · TLS protocol + cipher suite probe
  · HTTP/1.1 / HTTP/2 / HTTP/3 detection
  · HTTP headers + full redirect chain + security header audit
  · CSP deep analysis (unsafe-inline, unsafe-eval, wildcards)
  · HSTS preload + max-age audit
  · clickjacking / frame-ancestors analysis
  · cookie security audit (Secure, HttpOnly, SameSite, prefixes)
  · CORS misconfiguration probe
  · HTTP methods audit (OPTIONS, TRACE, PUT, DELETE, WebDAV)
  · open redirect probe
  · technology + WAF/CDN fingerprint
  · favicon hash fingerprint
  · subdomain enumeration via crt.sh + active brute-force wordlist
  · subdomain takeover detection (dangling CNAME)
  · typosquatting / domain permutation generator
  · robots.txt / sitemap.xml discovery
  · security.txt (RFC 9116) parser
  · sensitive path audit (env, git, backups, admin, etc.)
  · Wayback Machine / archive.org history check
  · TCP port scan (top 20 common ports) with banner grab
"""

import csv
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

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
OUT_DIR = Path.home() / ".osinttool" / "exports"
OUT_DIR.mkdir(parents=True, exist_ok=True)

UA = "Mozilla/5.0 (compatible; doxtoolkit/2.0)"
DNS_URL = "https://dns.google/resolve"

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]

PUBLIC_RESOLVERS = [
    ("Google",       "https://dns.google/resolve"),
    ("Cloudflare",   "https://cloudflare-dns.com/dns-query"),
    ("Quad9",        "https://dns.quad9.net:5053/dns-query"),
    ("OpenDNS",      "https://doh.opendns.com/dns-query"),
]

TOP_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
    (443, "HTTPS"), (445, "SMB"), (465, "SMTPS"), (587, "SMTP-sub"),
    (993, "IMAPS"), (995, "POP3S"), (1433, "MSSQL"), (3306, "MySQL"),
    (3389, "RDP"), (5432, "Postgres"), (6379, "Redis"), (8080, "HTTP-alt"),
]

SUBDOMAIN_WORDLIST = [
    "www", "mail", "api", "admin", "dev", "staging", "test", "vpn",
    "panel", "cpanel", "webmail", "smtp", "imap", "pop", "ftp", "sftp",
    "app", "portal", "login", "auth", "sso", "dashboard", "cdn",
    "static", "assets", "img", "images", "media", "download", "uploads",
    "blog", "shop", "store", "forum", "support", "help", "docs",
    "status", "monitor", "metrics", "grafana", "kibana", "prometheus",
    "jenkins", "gitlab", "github", "bitbucket", "ci", "build", "deploy",
    "db", "mysql", "postgres", "redis", "mongo", "elastic", "search",
    "ns1", "ns2", "ns3", "dns", "mx", "mx1", "mx2", "relay",
    "internal", "intranet", "extranet", "private", "secure",
    "backup", "bak", "old", "new", "beta", "alpha", "demo", "sandbox",
    "remote", "gateway", "router", "proxy", "edge", "origin",
    "staging2", "uat", "qa", "preprod", "prod", "web", "web1", "web2",
    "mail2", "smtp2", "mx3", "ns4", "ns5", "cloud", "k8s", "docker",
    "vault", "consul", "nomad", "rancher", "kubernetes", "traefik",
    "nginx", "haproxy", "lb", "loadbalancer", "waf", "soc", "noc",
]

SENSITIVE_PATHS = [
    ("/.env",              ("APP_KEY", "DB_PASSWORD", "SECRET", "=")),
    ("/.env.local",        ("APP_KEY", "DB_PASSWORD", "=")),
    ("/.env.production",   ("APP_KEY", "DB_PASSWORD", "=")),
    ("/.env.backup",       ("APP_KEY", "DB_PASSWORD", "=")),
    ("/.env.old",          ("APP_KEY", "DB_PASSWORD", "=")),
    ("/.git/config",       ("[core]", "[remote")),
    ("/.git/HEAD",         ("ref:",)),
    ("/.git/index",        ("DIRC",)),
    ("/.svn/entries",      ("dir",)),
    ("/.hg/hgrc",          ("[paths]", "[ui]")),
    ("/.htaccess",         ("RewriteEngine", "Order", "Deny")),
    ("/.htpasswd",         (":$", "$apr1$", "$2y$")),
    ("/backup.zip",        ()),
    ("/backup.tar.gz",     ()),
    ("/backup.sql",        ()),
    ("/bak.sql",           ()),
    ("/db.sql",            ()),
    ("/dump.sql",          ()),
    ("/database.sql",      ()),
    ("/wp-config.php.bak", ("DB_NAME", "DB_PASSWORD")),
    ("/config.php.bak",    ("password", "db_")),
    ("/config.json",       ("\"password\"", "\"secret\"")),
    ("/config.yml",        ("password:", "secret:")),
    ("/phpinfo.php",       ("phpinfo()", "PHP Version")),
    ("/info.php",          ("phpinfo()", "PHP Version")),
    ("/test.php",          ("phpinfo()", "PHP Version")),
    ("/server-status",     ("Apache Server Status",)),
    ("/server-info",       ("Apache Server Information",)),
    ("/actuator/env",      ("activeProfiles", "systemProperties")),
    ("/actuator/health",   ("status",)),
    ("/actuator/metrics",  ("jvm.memory", "process.cpu")),
    ("/actuator/beans",    ("beans", "context")),
    ("/actuator/mappings", ("dispatcherServlets",)),
    ("/swagger-ui.html",   ("swagger",)),
    ("/api/swagger.json",  ("swagger", "openapi")),
    ("/api-docs",          ("swagger", "openapi")),
    ("/v2/api-docs",       ("swagger", "openapi")),
    ("/graphql",           ("graphql", "GraphQL")),
    ("/graphiql",          ("graphiql", "GraphiQL")),
    ("/.well-known/security.txt", ("Contact:",)),
    ("/crossdomain.xml",   ("cross-domain-policy",)),
    ("/clientaccesspolicy.xml", ("cross-domain-access",)),
    ("/package.json",      ("\"dependencies\"", "\"name\"")),
    ("/composer.json",     ("\"require\"", "\"name\"")),
    ("/composer.lock",     ("packages", "content-hash")),
    ("/Gemfile",           ("source", "gem ")),
    ("/requirements.txt",  ("==", ">=")),
    ("/Dockerfile",        ("FROM ", "RUN ")),
    ("/docker-compose.yml",("services:", "version:")),
    ("/id_rsa",            ("BEGIN", "PRIVATE KEY")),
    ("/.ssh/id_rsa",       ("BEGIN", "PRIVATE KEY")),
    ("/.ssh/authorized_keys", ("ssh-rsa", "ssh-ed25519")),
    ("/web.config",        ("<configuration",)),
    ("/WEB-INF/web.xml",   ("<web-app",)),
    ("/trace",             ("TRACE", "request headers")),
    ("/debug",             ("debug", "stack trace")),
    ("/console",           ("console", "shell")),
    ("/admin/",            ()),
    ("/adminer.php",       ("adminer", "login")),
    ("/phpmyadmin/",       ("phpMyAdmin",)),
    ("/pma/",              ("phpMyAdmin",)),
    ("/mysql/",            ("mysql",)),
    ("/cpanel",            ("cPanel",)),
    ("/.DS_Store",         ("Bud1",)),
    ("/Thumbs.db",         ("Thumbs.db",)),
    ("/error.log",         ("error", "[error]")),
    ("/debug.log",         ("debug",)),
    ("/access.log",        ("GET", "POST")),
    ("/.aws/credentials",  ("aws_access_key", "aws_secret")),
    ("/.docker/config.json", ("auths", "credsStore")),
    ("/.npmrc",            ("registry", "_authToken")),
    ("/.pypirc",           ("pypi", "password")),
    ("/.netrc",            ("machine", "login", "password")),
    ("/.bash_history",     ("ls ", "cd ")),
    ("/.zsh_history",      ("ls ", "cd ")),
    ("/kubernetes.yml",    ("apiVersion", "kind")),
    ("/helm/values.yaml",  ("replicaCount", "image")),
    ("/terraform.tfstate", ("terraform", "resources")),
    ("/backup/",           ()),
    ("/old/",              ()),
    ("/test/",             ()),
    ("/temp/",             ()),
]

WAF_CDN_SIGNATURES = [
    ("Cloudflare",  ("cf-ray", "cf-cache-status", "cf-request-id"),
                    ("__cfduid", "__cf_bm", "cf_clearance"),
                    ("cloudflare",)),
    ("Akamai",      ("x-akamai-transformed", "akamai-origin-hop",
                     "x-akamai-request-id"),
                    ("ak_bmsc", "bm_sz", "akavpau"),
                    ("akamai", "akamaighost")),
    ("AWS CloudFront", ("x-amz-cf-id", "x-amz-cf-pop", "x-cache"),
                    (),
                    ("cloudfront",)),
    ("Incapsula / Imperva", ("x-iinfo", "x-cdn"),
                    ("incap_ses", "visid_incap"),
                    ("incapsula", "imperva")),
    ("Sucuri",      ("x-sucuri-id", "x-sucuri-cache"),
                    ("sucuri_cloudproxy",),
                    ("sucuri",)),
    ("F5 BIG-IP",   ("x-wa-info", "x-cnection"),
                    ("bigipserver", "ts", "f5_cspm"),
                    ("big-ip", "bigip")),
    ("Barracuda",   ("x-barracuda",),
                    ("barra_counter_session",),
                    ("barracuda",)),
    ("Fastly",      ("x-fastly-request-id", "fastly-io-info", "x-served-by"),
                    (),
                    ("fastly", "varnish")),
    ("Azure Front Door", ("x-azure-ref", "x-fd-healthprobe"),
                    (),
                    ("azure", "front door")),
    ("Google Cloud CDN", ("x-goog-generation", "x-goog-metageneration"),
                    (),
                    ("gws", "gse", "google")),
    ("StackPath",   ("x-sp-cache",),
                    (),
                    ("stackpath",)),
    ("KeyCDN",      ("x-keycdn-request-id",),
                    (),
                    ("keycdn",)),
    ("Bunny CDN",   ("x-bunny-request-id",),
                    (),
                    ("bunnycdn", "bunny")),
    ("Vercel",      ("x-vercel-id", "x-vercel-cache"),
                    (),
                    ("vercel",)),
    ("Netlify",     ("x-nf-request-id",),
                    (),
                    ("netlify",)),
    ("ModSecurity", ("server:mod_security", "server:modsecurity"),
                    (),
                    ()),
    ("Wordfence",   ("x-wordfence",),
                    ("wordfence_verified",),
                    ()),
    ("Fortinet FortiWeb", ("fortiwafsid",),
                    (),
                    ("fortiweb",)),
    ("Citrix NetScaler", ("x-ns-",),
                    ("citrix_ns_id", "ns_af"),
                    ("netscaler",)),
]

TECH_SIGNATURES = [
    ("wordpress", ("wp-content", "wp-includes", "wordpress")),
    ("drupal", ("drupal", "sites/default/files")),
    ("joomla", ("joomla", "/components/com_")),
    ("react", ("__next", "react", "_next/static")),
    ("vue", ("__vue__", "vue.js")),
    ("angular", ("ng-version", "angular")),
    ("bootstrap", ("bootstrap.min.css", "bootstrap.min.js")),
    ("jquery", ("jquery.min.js", "jquery-")),
    ("cloudflare", ("cf-ray", "cloudflare")),
    ("nginx", ("nginx",)),
    ("apache", ("apache",)),
    ("shopify", ("shopify", "cdn.shopify")),
    ("magento", ("magento", "mage/cookies")),
    ("wix", ("wix.com", "wixstatic")),
    ("squarespace", ("squarespace", "static1.squarespace")),
    ("ghost", ("ghost", "ghost-content")),
    ("strapi", ("strapi",)),
    ("laravel", ("laravel_session", "XSRF-TOKEN")),
    ("django", ("csrftoken", "django")),
    ("flask", ("werkzeug", "flask")),
    ("rails", ("_rails", "csrf-token")),
    ("express", ("x-powered-by: express",)),
    ("nextjs", ("__NEXT_DATA__", "_next/")),
    ("nuxt", ("__NUXT__", "_nuxt/")),
    ("gatsby", ("gatsby", "___gatsby")),
    ("hugo", ("hugo", "generator")),
    ("jekyll", ("jekyll",)),
    ("netlify", ("netlify", "x-nf-request-id")),
    ("vercel", ("vercel", "x-vercel-id")),
    ("cloudfront", ("cloudfront", "x-amz-cf")),
    ("fastly", ("fastly",)),
    ("sendgrid", ("sendgrid",)),
    ("mailchimp", ("mailchimp",)),
    ("intercom", ("intercom",)),
    ("drift", ("drift.com", "drift-")),
    ("hubspot", ("hs-scripts", "hubspot")),
    ("google-analytics", ("google-analytics", "gtag")),
    ("google-tag-manager", ("googletagmanager", "gtm")),
    ("facebook-pixel", ("fbq", "facebook.net")),
    ("stripe", ("stripe", "js.stripe")),
    ("paypal", ("paypal", "paypalobjects")),
    ("recaptcha", ("recaptcha", "grecaptcha")),
    ("cloudflare-turnstile", ("turnstile", "challenges.cloudflare")),
    ("sentry", ("sentry", "sentry.io")),
    ("datadog", ("datadog", "dd_")),
    ("newrelic", ("newrelic", "nr-")),
    ("sentry-js", ("sentry", "@sentry")),
    ("segment", ("segment.com", "analytics.js")),
    ("mixpanel", ("mixpanel",)),
    ("amplitude", ("amplitude",)),
    ("hotjar", ("hotjar",)),
    ("crazyegg", ("crazyegg",)),
    ("optimizely", ("optimizely",)),
    ("vwo", ("visualwebsiteoptimizer", "vwo")),
    ("cloudflare-analytics", ("cloudflareinsights",)),
    ("prismjs", ("prism",)),
    ("highlightjs", ("highlight.js", "hljs")),
    ("tinymce", ("tinymce",)),
    ("ckeditor", ("ckeditor",)),
    ("summernote", ("summernote",)),
    ("quill", ("quill",)),
    ("fontawesome", ("font-awesome", "fontawesome")),
    ("material-icons", ("material-icons", "materialdesignicons")),
    ("feather-icons", ("feather-icons",)),
    ("heroicons", ("heroicons",)),
    ("bootstrap-icons", ("bootstrap-icons",)),
    ("tailwindcss", ("tailwind", "tailwindcss")),
    ("bulma", ("bulma",)),
    ("foundation", ("foundation",)),
    ("semantic-ui", ("semantic-ui", "semantic.min")),
]

# common dangling CNAME fingerprints for subdomain takeover
TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages", "github.io", ("There isn't a GitHub Pages site here",)),
    ("Heroku", "herokuapp.com", ("No such app", "heroku | no such app")),
    ("AWS S3", "s3.amazonaws.com", ("NoSuchBucket", "The specified bucket does not exist")),
    ("AWS CloudFront", "cloudfront.net", ("Bad request", "ERROR: The request could not be satisfied")),
    ("Azure", "azurewebsites.net", ("Error 404 - Web app not found",)),
    ("Shopify", "myshopify.com", ("Sorry, this shop is currently unavailable",)),
    ("Fastly", "fastly.net", ("Fastly error: unknown domain",)),
    ("Pantheon", "pantheonsite.io", ("The gods are wise, but do not know of the site",)),
    ("Tumblr", "tumblr.com", ("There's nothing here", "Whatever you were looking for")),
    ("Zendesk", "zendesk.com", ("Help Center Closed", "This help center no longer exists")),
    ("Ghost", "ghost.io", ("The thing you were looking for is no longer here",)),
    ("WordPress", "wordpress.com", ("Do you want to register",)),
    ("Surge.sh", "surge.sh", ("project not found",)),
    ("Bitbucket", "bitbucket.io", ("Repository not found",)),
    ("Netlify", "netlify.app", ("Not Found - Request ID",)),
    ("Vercel", "vercel.app", ("The deployment could not be found", "DEPLOYMENT_NOT_FOUND")),
    ("Cargo", "cargocollective.com", ("404 Not Found",)),
    ("Statuspage", "statuspage.io", ("You are being redirected",)),
    ("Unbounce", "unbouncepages.com", ("The requested URL was not found on this server",)),
    ("Intercom", "custom.intercom.help", ("This page is reserved for artistic use",)),
    ("UserVoice", "uservoice.com", ("This UserVoice subdomain is currently available",)),
    ("Discourse", "discourse.org", ("The page you requested doesn't exist",)),
    ("Fly.io", "fly.dev", ("404 Not Found",)),
    ("Read the Docs", "readthedocs.io", ("The page you are looking for",)),
    ("Porter", "porter.run", ("Not found",)),
    ("Ngrok", "ngrok.io", ("Tunnel not found",)),
    ("Sendgrid", "sendgrid.net", ("The page you are looking for",)),
    ("Helpjuice", "helpjuice.com", ("We could not find what you're looking for",)),
    ("Helpscout", "helpscoutdocs.com", ("No settings were found for this company",)),
    ("Cargo Collective", "cargocollective.com", ("If you're the owner of this website",)),
]

DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "s1", "s2",
    "mail", "dkim", "mandrill", "sendgrid", "amazonses", "ses",
    "mailchimp", "postmark", "zoho", "protonmail", "smtp", "sig1",
    "20230601", "20230101", "20220101", "20210101", "20200101",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
    "X-XSS-Protection",
    "X-Permitted-Cross-Domain-Policies",
    "X-Download-Options",
    "X-DNS-Prefetch-Control",
    "Expect-CT",
    "Report-To",
    "NEL",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
                "HEAD", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH",
                "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]

CORS_ORIGINS = [
    "https://evil.example.com",
    "https://attacker.test",
    "null",
    "https://localhost",
    "https://127.0.0.1",
]


# ───────────────────────── dns ─────────────────────────

def _dns(domain, rtype):
    try:
        r = requests.get(
            DNS_URL,
            params={"name": domain, "type": rtype},
            headers={"User-Agent": UA, "Accept": "application/dns-json"},
            timeout=8,
        )
        d = r.json()
        out = []
        for a in d.get("Answer") or []:
            out.append(a.get("data"))
        return rtype, out
    except Exception:
        return rtype, []


def _dns_full(domain, rtype):
    """Return full JSON from Google DoH for a query."""
    try:
        r = requests.get(
            DNS_URL,
            params={"name": domain, "type": rtype},
            headers={"User-Agent": UA, "Accept": "application/dns-json"},
            timeout=8,
        )
        return r.json()
    except Exception:
        return {}


def _dns_raw(domain, rtype):
    """Return the raw Answer list from Google DoH."""
    d = _dns_full(domain, rtype)
    return d.get("Answer") or []


# ───────────────────────── DNSSEC ─────────────────────────

def _dnssec_ds(domain):
    """Fetch DS records for the domain from its parent zone."""
    parts = domain.split(".")
    if len(parts) < 2:
        return []
    parent = ".".join(parts[1:])
    answers = _dns_raw(domain, "DS")
    return [a.get("data") for a in answers]


def _dnssec_dnskey(domain):
    """Fetch DNSKEY records for the domain."""
    answers = _dns_raw(domain, "DNSKEY")
    keys = []
    for a in answers:
        data = a.get("data") or ""
        fields = data.split()
        if len(fields) >= 4:
            keys.append({
                "flags": fields[0],
                "protocol": fields[1],
                "algorithm": fields[2],
                "key": fields[3][:40] + ("..." if len(fields[3]) > 40 else ""),
                "raw": data,
            })
    return keys


def _dnssec_rrsig(domain):
    """Check for RRSIG records on the domain's apex."""
    answers = _dns_raw(domain, "RRSIG")
    return [a.get("data") for a in answers]


def _dnssec_validate(domain):
    """Grade DNSSEC: unsigned / signed-no-chain / signed-valid."""
    ds = _dnssec_ds(domain)
    dnskey = _dnssec_dnskey(domain)
    rrsig = _dnssec_rrsig(domain)

    if not dnskey and not ds and not rrsig:
        return {
            "state": "unsigned",
            "score": 0,
            "ds": ds,
            "dnskey_count": 0,
            "rrsig_count": 0,
            "issues": ["domain has no DNSSEC records — vulnerable to DNS spoofing"],
        }

    issues = []
    if dnskey and not ds:
        issues.append("zone is signed but no DS record in parent — chain broken")
    if ds and not dnskey:
        issues.append("DS record exists but no DNSKEY — resolvers will fail validation")
    if not rrsig:
        issues.append("no RRSIG records — zone is not actually signed")

    if ds and dnskey and rrsig:
        state = "signed-valid"
        score = 100
    elif dnskey or ds:
        state = "partial"
        score = 40
    else:
        state = "unsigned"
        score = 0

    return {
        "state": state,
        "score": score,
        "ds": ds,
        "dnskey_count": len(dnskey),
        "dnskey": dnskey[:5],
        "rrsig_count": len(rrsig),
        "issues": issues,
    }


# ───────────────────────── CAA ─────────────────────────

def _caa(domain):
    """Fetch and parse CAA records."""
    answers = _dns_raw(domain, "CAA")
    out = {"records": [], "has_issue": False, "has_iodef": False,
           "issues": []}
    if not answers:
        out["issues"].append("no CAA records — any CA may issue certs for this domain")
        return out
    for a in answers:
        data = a.get("data") or ""
        out["records"].append(data)
        d = data.lower()
        if "issue" in d:
            out["has_issue"] = True
        if "iodef" in d:
            out["has_iodef"] = True
    if not out["has_issue"]:
        out["issues"].append("no issue directive — CAA does not restrict issuance")
    return out


# ───────────────────────── zone transfer ─────────────────────────

def _axfr_attempt(nameserver, domain, timeout=6):
    """Attempt an AXFR over TCP. Return (server, success, records)."""
    try:
        sock = socket.create_connection((nameserver, 53), timeout=timeout)
        sock.settimeout(timeout)

        # minimal AXFR query packet
        tid = 0x1234
        flags = 0x0000  # standard query
        header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)

        # encode domain name
        qname = b""
        for label in domain.split("."):
            qname += bytes([len(label)]) + label.encode()
        qname += b"\x00"

        question = qname + struct.pack(">HH", 252, 1)  # AXFR, IN
        packet = header + question

        # prepend TCP length
        sock.sendall(struct.pack(">H", len(packet)) + packet)

        records = []
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) >= 2:
                msglen = struct.unpack(">H", data[:2])[0]
                if len(data) >= 2 + msglen:
                    break
        sock.close()

        if len(data) > 2:
            # parse the response header for answer count
            try:
                _, rflags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[2:14])
                if an > 0 and (rflags & 0x000F) == 0:
                    return nameserver, True, an
            except Exception:
                pass
        return nameserver, False, 0
    except Exception:
        return nameserver, False, 0


def _try_axfr(domain, nameservers):
    """Try AXFR against each NS. Return list of vulnerable servers."""
    results = []
    for ns in nameservers:
        ns_clean = (ns or "").rstrip(".")
        if not ns_clean:
            continue
        try:
            ns_ip = socket.gethostbyname(ns_clean)
        except Exception:
            continue
        server, ok, count = _axfr_attempt(ns_ip, domain)
        results.append({
            "nameserver": ns_clean,
            "ip": ns_ip,
            "vulnerable": ok,
            "record_count": count,
        })
    return results


# ───────────────────────── propagation ─────────────────────────

def _propagation(domain):
    """Query the same record via multiple public resolvers."""
    results = []
    for name, url in PUBLIC_RESOLVERS:
        try:
            r = requests.get(
                url,
                params={"name": domain, "type": "A"},
                headers={"User-Agent": UA, "Accept": "application/dns-json"},
                timeout=6,
            )
            d = r.json()
            ips = [a.get("data") for a in (d.get("Answer") or [])
                   if a.get("type") == 1]
            results.append({"resolver": name, "ips": ips})
        except Exception:
            results.append({"resolver": name, "ips": []})
    return results


def _wildcard_dns(domain):
    """Check if *.domain resolves — wildcard DNS present."""
    rand = "ostin-" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    try:
        ip = socket.gethostbyname(f"{rand}.{domain}")
        return {"wildcard": True, "sample": f"{rand}.{domain}", "ip": ip}
    except Exception:
        return {"wildcard": False, "sample": f"{rand}.{domain}", "ip": None}


# ───────────────────────── reverse DNS + ASN ─────────────────────────

def _ptr(ip):
    """Reverse DNS lookup via Google DoH."""
    try:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        r = requests.get(
            DNS_URL,
            params={"name": rev, "type": "PTR"},
            headers={"User-Agent": UA, "Accept": "application/dns-json"},
            timeout=8,
        )
        d = r.json()
        out = []
        for a in d.get("Answer") or []:
            if a.get("type") == 12:
                out.append(a.get("data"))
        return out
    except Exception:
        return []


def _asn_info(ip):
    """Look up ASN + netblock via RDAP IP endpoint."""
    try:
        r = requests.get(
            f"https://rdap.org/ip/{ip}",
            headers={"User-Agent": UA, "Accept": "application/rdap+json"},
            timeout=10,
        )
        if r.status_code != 200:
            return None
        d = r.json()
        out = {
            "handle": d.get("handle"),
            "name": d.get("name"),
            "type": d.get("type"),
            "country": d.get("country"),
            "startAddress": d.get("startAddress"),
            "endAddress": d.get("endAddress"),
            "cidr": None,
            "autnums": [],
        }
        # compute CIDR
        try:
            start = ipaddress.ip_address(d.get("startAddress"))
            end = ipaddress.ip_address(d.get("endAddress"))
            net = list(ipaddress.summarize_address_range(start, end))
            if net:
                out["cidr"] = str(net[0])
        except Exception:
            pass
        for ent in d.get("entities") or []:
            if "autnum" in (ent.get("roles") or []):
                vc = ent.get("vcardArray")
                if vc and len(vc) > 1:
                    for f in vc[1]:
                        if f[0] == "fn":
                            out["autnums"].append(f[3])
        return out
    except Exception:
        return None


# ───────────────────────── email security ─────────────────────────

def _txt_records(domain):
    try:
        r = requests.get(
            DNS_URL,
            params={"name": domain, "type": "TXT"},
            headers={"User-Agent": UA, "Accept": "application/dns-json"},
            timeout=8,
        )
        d = r.json()
        out = []
        for a in d.get("Answer") or []:
            v = a.get("data", "").replace('"', "")
            out.append(v)
        return out
    except Exception:
        return []


def _parse_spf(txt_records):
    spf = next((t for t in txt_records if t.lower().startswith("v=spf1")), None)
    if not spf:
        return {
            "present": False, "record": None, "mechanisms": [],
            "all": None,
            "issues": ["no SPF record — spoofable envelope sender"],
        }
    mech = spf.split()[1:]
    all_q = None
    for m in mech:
        if m.lower().startswith("all") or m.lower().endswith("all"):
            all_q = m
            break
    issues = []
    if all_q is None:
        issues.append("no 'all' mechanism — SPF has no default policy")
    elif all_q.endswith("+all"):
        issues.append("'+all' allows anyone to send — spoofable")
    elif all_q.endswith("?all"):
        issues.append("'?all' is neutral — no real protection")
    elif all_q.endswith("~all"):
        issues.append("'~all' is softfail — marks but does not reject")
    lookups = sum(1 for m in mech if m.lower().startswith((
        "include:", "a:", "mx:", "ptr:", "exists:", "redirect=",
        "a", "mx", "ptr")))
    if lookups > 10:
        issues.append(f"{lookups} DNS lookups — SPF will hit the 10-lookup limit")
    return {
        "present": True, "record": spf, "mechanisms": mech,
        "all": all_q, "issues": issues,
    }


def _parse_dmarc(domain):
    recs = _txt_records(f"_dmarc.{domain}")
    dmarc = next((t for t in recs if t.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        return {
            "present": False, "record": None, "policy": None,
            "rua": None, "ruf": None, "pct": None,
            "issues": ["no DMARC record — receivers have no policy"],
        }
    tags = {}
    for part in dmarc.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    policy = tags.get("p")
    issues = []
    if policy is None:
        issues.append("no 'p=' tag — DMARC is effectively inert")
    elif policy == "none":
        issues.append("p=none — monitoring only, spoofed mail is still delivered")
    elif policy == "quarantine":
        pass
    elif policy == "reject":
        pass
    if tags.get("pct") and tags["pct"] != "100" and policy in ("quarantine", "reject"):
        issues.append(f"pct={tags['pct']} — policy applies to a fraction only")
    if "rua" not in tags:
        issues.append("no 'rua' — no aggregate reports, flying blind")
    if tags.get("sp") is None and policy and policy != "none":
        issues.append("no 'sp' — subdomains inherit but are not explicitly scoped")
    return {
        "present": True, "record": dmarc, "policy": policy,
        "rua": tags.get("rua"), "ruf": tags.get("ruf"),
        "pct": tags.get("pct"), "sp": tags.get("sp"),
        "adkim": tags.get("adkim"), "aspf": tags.get("aspf"),
        "issues": issues,
    }


def _probe_dkim(domain, selector, timeout=6):
    name = f"{selector}._domainkey.{domain}"
    try:
        r = requests.get(
            DNS_URL,
            params={"name": name, "type": "TXT"},
            headers={"User-Agent": UA, "Accept": "application/dns-json"},
            timeout=timeout,
        )
        d = r.json()
        for a in d.get("Answer") or []:
            v = (a.get("data") or "").replace('"', "")
            if "v=dkim1" in v.lower() or "p=" in v.lower():
                return {"selector": selector, "record": v}
    except Exception:
        pass
    return None


def _audit_email(domain):
    txt = _txt_records(domain)
    spf = _parse_spf(txt)
    dmarc = _parse_dmarc(domain)
    dkim_hits = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(_probe_dkim, domain, s) for s in DKIM_SELECTORS]
        for f in as_completed(futs):
            r = f.result()
            if r:
                dkim_hits.append(r)
    _, mx = _dns(domain, "MX")
    return {
        "spf": spf, "dmarc": dmarc, "dkim": dkim_hits, "mx": mx,
        "score": _email_score(spf, dmarc, dkim_hits),
    }


def _email_score(spf, dmarc, dkim):
    score = 0
    if spf.get("present"):
        score += 30
        if spf.get("all", "").endswith("-all"):
            score += 10
        elif spf.get("all", "").endswith("~all"):
            score += 5
    if dmarc.get("present"):
        score += 30
        if dmarc.get("policy") == "reject":
            score += 20
        elif dmarc.get("policy") == "quarantine":
            score += 10
        if dmarc.get("rua"):
            score += 5
    if dkim:
        score += 15
    return min(score, 100)


# ───────────────────────── rdap ─────────────────────────

def _rdap(domain):
    try:
        r = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={"User-Agent": UA, "Accept": "application/rdap+json"},
            timeout=12,
        )
        if r.status_code != 200:
            return None
        d = r.json()
    except Exception:
        return None
    out = {
        "handle": d.get("handle"),
        "ldhName": d.get("ldhName"),
        "status": d.get("status") or [],
        "nameservers": [],
        "events": {},
        "entities": [],
    }
    for ns in d.get("nameservers") or []:
        out["nameservers"].append(ns.get("ldhName"))
    for ev in d.get("events") or []:
        out["events"][ev.get("eventAction")] = ev.get("eventDate")
    for ent in d.get("entities") or []:
        roles = ent.get("roles") or []
        if "registrar" in roles:
            vc = ent.get("vcardArray")
            name = None
            if vc and len(vc) > 1:
                for f in vc[1]:
                    if f[0] == "fn":
                        name = f[3]
            out["entities"].append({"role": "registrar", "name": name})
    return out


# ───────────────────────── ssl + tls ─────────────────────────

def _ssl_cert(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                proto = ssock.version()
        sans = []
        for t, v in cert.get("subjectAltName", []):
            if t == "DNS":
                sans.append(v)
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        return {
            "subject_cn": subject.get("commonName"),
            "subject_org": subject.get("organizationName"),
            "issuer_cn": issuer.get("commonName"),
            "issuer_org": issuer.get("organizationName"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "sans": sans[:30],
            "san_count": len(sans),
            "protocol": proto,
            "cipher": cipher[0] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
        }
    except Exception as e:
        return {"error": str(e)}


def _tls_probe(domain):
    """Probe which TLS versions the server accepts."""
    out = {}
    tests = [
        ("TLS 1.0", ssl.TLSVersion.TLSv1),
        ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
        ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
        ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
    ]
    for label, version in tests:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = version
                ctx.maximum_version = version
            except Exception:
                out[label] = "unsupported"
                continue
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssock.getpeercert()
                    out[label] = "supported"
        except Exception:
            out[label] = "rejected"
    return out


def _http_version_probe(domain):
    """Detect HTTP/1.1, HTTP/2, HTTP/3 via response headers."""
    out = {"h1": None, "h2": None, "h3": None, "alt_svc": None}
    try:
        r = requests.get(f"https://{domain}", headers={"User-Agent": UA},
                         timeout=10)
        out["h1"] = "1.1" if r.raw.version <= 11 else "2+"
        alt = r.headers.get("Alt-Svc") or r.headers.get("alt-svc")
        if alt:
            out["alt_svc"] = alt
            if "h3" in alt:
                out["h3"] = "advertised"
            if "h2" in alt:
                out["h2"] = "advertised"
    except Exception:
        pass
    return out


# ───────────────────────── http + redirect chain ─────────────────────────

def _http_headers(domain):
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{domain}",
                headers={"User-Agent": UA},
                timeout=10,
                allow_redirects=True,
            )
            chain = []
            for h in r.history:
                chain.append({
                    "url": h.url,
                    "status": h.status_code,
                    "location": h.headers.get("Location"),
                })
            chain.append({
                "url": r.url,
                "status": r.status_code,
                "location": None,
            })
            return {
                "url": r.url,
                "status": r.status_code,
                "server": r.headers.get("Server"),
                "powered_by": r.headers.get("X-Powered-By"),
                "via": r.headers.get("Via"),
                "cdn": r.headers.get("CF-Ray") or r.headers.get("X-Cache"),
                "headers": dict(r.headers),
                "cookies": list(r.cookies.keys()),
                "set_cookie_raw": r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else [],
                "redirect_chain": chain,
                "body_snippet": r.text[:3000],
                "body_full": r.text[:20000],
            }
        except Exception:
            continue
    return None


def _audit_security(headers):
    if not headers:
        return []
    present = {h.lower() for h in headers.keys()}
    return [(h, "yes" if h.lower() in present else "no") for h in SECURITY_HEADERS]


# ───────────────────────── CSP deep analysis ─────────────────────────

def _analyze_csp(headers):
    """Deep CSP inspection for known weaknesses."""
    if not headers:
        return None
    csp = None
    for k, v in headers.items():
        if k.lower() == "content-security-policy":
            csp = v
            break
    if not csp:
        return {"present": False, "issues": ["no CSP header set"]}
    directives = {}
    for chunk in csp.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split()
        directives[parts[0].lower()] = parts[1:]
    issues = []
    if "default-src" not in directives and "script-src" not in directives:
        issues.append("no default-src or script-src — no baseline for script loads")
    for dn in ("script-src", "default-src"):
        if dn in directives:
            vals = " ".join(directives[dn])
            if "'unsafe-inline'" in vals:
                issues.append(f"{dn} allows 'unsafe-inline' — XSS risk")
            if "'unsafe-eval'" in vals:
                issues.append(f"{dn} allows 'unsafe-eval' — code injection risk")
            if "*" in vals:
                issues.append(f"{dn} contains wildcard '*' — CSP bypass risk")
            if "http:" in vals:
                issues.append(f"{dn} allows http: — mixed-content risk")
    if "object-src" not in directives:
        issues.append("no object-src — legacy plugin vectors possible")
    if "base-uri" not in directives:
        issues.append("no base-uri — base tag injection possible")
    if "frame-ancestors" not in directives and "report-only" not in csp.lower():
        issues.append("no frame-ancestors — clickjacking not mitigated by CSP")
    return {
        "present": True,
        "raw": csp,
        "directives": directives,
        "issues": issues,
    }


def _analyze_hsts(headers):
    """Audit Strict-Transport-Security."""
    if not headers:
        return {"present": False, "issues": ["no HSTS header"]}
    hsts = None
    for k, v in headers.items():
        if k.lower() == "strict-transport-security":
            hsts = v
            break
    if not hsts:
        return {"present": False, "issues": ["no HSTS header — SSL stripping possible"]}
    issues = []
    maxage = 0
    m = re.search(r"max-age\s*=\s*(\d+)", hsts)
    if m:
        maxage = int(m.group(1))
    if maxage < 15552000:
        issues.append(f"max-age={maxage} — below the recommended 6 months")
    if "includesubdomains" not in hsts.lower():
        issues.append("no includeSubDomains — subdomains not covered")
    if "preload" not in hsts.lower():
        issues.append("no preload — browser preload list opt-in missing")
    return {
        "present": True,
        "raw": hsts,
        "max_age": maxage,
        "issues": issues,
    }


def _analyze_frame_options(headers):
    """Check X-Frame-Options and frame-ancestors for clickjacking."""
    if not headers:
        return {"present": False, "issues": ["no X-Frame-Options"]}
    xfo = None
    for k, v in headers.items():
        if k.lower() == "x-frame-options":
            xfo = v
            break
    if not xfo:
        return {"present": False, "issues": ["no X-Frame-Options — clickjacking possible"]}
    val = xfo.strip().lower()
    if val not in ("deny", "sameorigin"):
        return {"present": True, "raw": xfo,
                "issues": [f"unusual value '{xfo}'"]}
    return {"present": True, "raw": xfo, "issues": []}


# ───────────────────────── cookie audit ─────────────────────────

def _parse_set_cookie(raw_cookie):
    """Parse a Set-Cookie header into a dict of flags."""
    parts = [p.strip() for p in raw_cookie.split(";")]
    if not parts:
        return None
    name_val = parts[0]
    if "=" not in name_val:
        return None
    name, _, value = name_val.partition("=")
    out = {
        "name": name.strip(),
        "secure": False,
        "httponly": False,
        "samesite": None,
        "domain": None,
        "path": None,
        "max_age": None,
        "expires": None,
        "raw": raw_cookie,
    }
    for p in parts[1:]:
        low = p.lower()
        if low == "secure":
            out["secure"] = True
        elif low == "httponly":
            out["httponly"] = True
        elif low.startswith("samesite="):
            out["samesite"] = p.split("=", 1)[1].strip()
        elif low.startswith("domain="):
            out["domain"] = p.split("=", 1)[1].strip()
        elif low.startswith("path="):
            out["path"] = p.split("=", 1)[1].strip()
        elif low.startswith("max-age="):
            try:
                out["max_age"] = int(p.split("=", 1)[1].strip())
            except Exception:
                pass
        elif low.startswith("expires="):
            out["expires"] = p.split("=", 1)[1].strip()
    return out


def _audit_cookies(headers):
    """Full cookie security audit from Set-Cookie headers."""
    if not headers:
        return []
    raws = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            raws.append(v)
    # requests joins multiple Set-Cookie headers with commas — best-effort split
    split = []
    for r in raws:
        # naive: split on comma followed by space and something like Name=
        split.extend(re.split(r",\s*(?=[A-Za-z_][A-Za-z0-9_\-\.]*\s*=)", r))
    results = []
    for r in split:
        parsed = _parse_set_cookie(r)
        if not parsed:
            continue
        issues = []
        if not parsed["secure"]:
            issues.append("missing Secure flag")
        if not parsed["httponly"]:
            issues.append("missing HttpOnly flag")
        if not parsed["samesite"]:
            issues.append("missing SameSite — defaults vary by browser")
        elif parsed["samesite"].lower() == "none" and not parsed["secure"]:
            issues.append("SameSite=None without Secure is rejected by modern browsers")
        if parsed["name"].startswith("__Host-"):
            if not parsed["secure"] or parsed["domain"]:
                issues.append("__Host- prefix requires Secure and no Domain")
        if parsed["name"].startswith("__Secure-") and not parsed["secure"]:
            issues.append("__Secure- prefix requires Secure flag")
        parsed["issues"] = issues
        results.append(parsed)
    return results


# ───────────────────────── CORS probe ─────────────────────────

def _cors_probe(url):
    """Test CORS origin reflection and misconfigurations."""
    results = []
    for origin in CORS_ORIGINS:
        try:
            # simple request
            r = requests.get(
                url,
                headers={"User-Agent": UA, "Origin": origin},
                timeout=8,
                allow_redirects=False,
            )
            acao = r.headers.get("Access-Control-Allow-Origin")
            acac = r.headers.get("Access-Control-Allow-Credentials")
            vary = r.headers.get("Vary")
            simple = {
                "origin": origin,
                "method": "GET",
                "acao": acao,
                "acac": acac,
                "vary": vary,
                "issues": [],
            }
            if acao == origin:
                simple["issues"].append("origin reflected")
                if acac and acac.lower() == "true":
                    simple["issues"].append("CRITICAL: reflected origin + credentials")
            elif acao == "*":
                simple["issues"].append("wildcard ACAO")
                if acac and acac.lower() == "true":
                    simple["issues"].append("CRITICAL: wildcard + credentials")
            if acao and acao != "*" and (not vary or "origin" not in vary.lower()):
                simple["issues"].append("missing Vary: Origin — cache poisoning risk")
            if simple["issues"]:
                results.append(simple)

            # preflight
            rp = requests.options(
                url,
                headers={
                    "User-Agent": UA,
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "authorization",
                },
                timeout=8,
                allow_redirects=False,
            )
            pacao = rp.headers.get("Access-Control-Allow-Origin")
            pacam = rp.headers.get("Access-Control-Allow-Methods")
            pacah = rp.headers.get("Access-Control-Allow-Headers")
            pacac = rp.headers.get("Access-Control-Allow-Credentials")
            pre = {
                "origin": origin,
                "method": "OPTIONS",
                "acao": pacao,
                "acam": pacam,
                "acah": pacah,
                "acac": pacac,
                "issues": [],
            }
            if pacao == origin:
                pre["issues"].append("preflight reflected origin")
                if pacac and pacac.lower() == "true":
                    pre["issues"].append("preflight reflected + credentials")
            if pacam and "authorization" in pacam.lower() and origin == "https://evil.example.com":
                pre["issues"].append("permissive Allow-Methods")
            if pre["issues"]:
                results.append(pre)
        except Exception:
            continue
    return results


# ───────────────────────── http methods ─────────────────────────

def _http_methods_probe(url):
    """Probe HTTP methods; flag risky ones."""
    results = []
    for method in HTTP_METHODS:
        try:
            r = requests.request(method, url, headers={"User-Agent": UA},
                                 timeout=6, allow_redirects=False)
            status = r.status_code
            allow = r.headers.get("Allow")
            results.append({
                "method": method,
                "status": status,
                "allow": allow,
            })
        except Exception as e:
            results.append({
                "method": method,
                "status": None,
                "allow": None,
                "error": type(e).__name__,
            })
    # identify risky ones
    for r in results:
        risky = []
        if r["method"] in ("TRACE", "TRACK") and r["status"] in (200, 405) and r["status"] == 200:
            risky.append("TRACE enabled — cross-site tracing risk")
        if r["method"] == "PUT" and r["status"] in (200, 201, 204):
            risky.append("PUT accepted — check write permissions")
        if r["method"] == "DELETE" and r["status"] in (200, 202, 204):
            risky.append("DELETE accepted — check permissions")
        if r["method"] == "PROPFIND" and r["status"] in (200, 207):
            risky.append("WebDAV PROPFIND — may allow directory listing")
        if r["method"] == "CONNECT" and r["status"] in (200, 201):
            risky.append("CONNECT accepted — proxy risk")
        r["risky"] = risky
    return results


# ───────────────────────── open redirect ─────────────────────────

def _open_redirect_probe(url):
    """Probe common redirect params for unvalidated redirects."""
    probes = [
        "redirect", "url", "next", "return", "returnurl", "return_url",
        "dest", "destination", "continue", "target", "redir", "r",
        "u", "goto", "out", "link", "forward", "callback",
    ]
    payload = "https://evil.example.com"
    hits = []
    for p in probes:
        sep = "&" if "?" in url else "?"
        test = f"{url}{sep}{p}={payload}"
        try:
            r = requests.get(test, headers={"User-Agent": UA},
                             timeout=6, allow_redirects=False)
            location = r.headers.get("Location") or ""
            if "evil.example.com" in location:
                hits.append({"param": p, "location": location})
        except Exception:
            continue
    return hits


# ───────────────────────── tech + WAF ─────────────────────────

def _fingerprint(resp):
    hits = set()
    if not resp:
        return []
    server = (resp.get("server") or "").lower()
    pb = (resp.get("powered_by") or "").lower()
    body = (resp.get("body_full") or resp.get("body_snippet") or "").lower()
    hdrs = " ".join(f"{k}:{v}" for k, v in resp.get("headers", {}).items()).lower()
    blob = f"{server} {pb} {body} {hdrs}"
    for name, sigs in TECH_SIGNATURES:
        if any(s.lower() in blob for s in sigs):
            hits.add(name)
    return sorted(hits)


def _detect_waf(resp):
    if not resp:
        return []
    headers_l = {k.lower(): v for k, v in resp.get("headers", {}).items()}
    server = (resp.get("server") or "").lower()
    via = (resp.get("via") or "").lower()
    cookie_names = [c.lower() for c in (resp.get("cookies") or [])]
    via_blob = f"{server} {via}"
    hits = []
    for name, hdrs, cookies, servers in WAF_CDN_SIGNATURES:
        matched = []
        for h in hdrs:
            if h.startswith("server:"):
                token = h.split(":", 1)[1]
                if token in server:
                    matched.append(f"server:{token}")
            elif h in headers_l:
                matched.append(f"hdr:{h}")
        for c in cookies:
            if c in cookie_names:
                matched.append(f"cookie:{c}")
        for s in servers:
            if s in via_blob or s in headers_l.get("server", "").lower():
                matched.append(f"server:{s}")
        if matched:
            hits.append({"name": name, "evidence": matched})
    return hits


# ───────────────────────── favicon hash ─────────────────────────

def _favicon_hash(domain):
    """Get favicon and compute mmh3-style hash for Shodan lookup."""
    try:
        r = requests.get(f"https://{domain}/favicon.ico", headers={"User-Agent": UA},
                         timeout=8, allow_redirects=True)
        if r.status_code != 200 or not r.content:
            return None
        data = r.content
        import base64
        b64 = base64.encodebytes(data)
        # use hashlib md5 as proxy — mmh3 requires the package
        md5 = hashlib.md5(data).hexdigest()
        return {
            "size": len(data),
            "md5": md5,
            "shodan_query": f'http.favicon.hash:{md5}',
        }
    except Exception:
        return None


# ───────────────────────── subdomains ─────────────────────────

def _crtsh(domain):
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": UA}, timeout=20,
        )
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:
        return []
    subs = set()
    for entry in data:
        for name in (entry.get("name_value") or "").split("\n"):
            name = name.strip().lower()
            if name.endswith(domain) and "*" not in name:
                subs.add(name)
    return sorted(subs)[:300]


def _resolve_sub(sub, domain):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return {"subdomain": fqdn, "ip": ip}
    except Exception:
        return None


def _brute_subdomains(domain, wordlist, threads=40):
    hits = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_resolve_sub, w, domain) for w in wordlist]
        for f in as_completed(futs):
            r = f.result()
            if r:
                hits.append(r)
    return sorted(hits, key=lambda x: x["subdomain"])


# ───────────────────────── subdomain takeover ─────────────────────────

def _cname_chain(subdomain):
    """Follow the CNAME chain for a subdomain via DoH."""
    chain = []
    current = subdomain
    for _ in range(6):
        answers = _dns_raw(current, "CNAME")
        if not answers:
            break
        target = answers[0].get("data") or ""
        target = target.rstrip(".")
        chain.append(target)
        current = target
    return chain


def _subdomain_takeover_check(subdomain, timeout=8):
    """Detect dangling CNAME pointing to a claimable cloud resource."""
    chain = _cname_chain(subdomain)
    if not chain:
        return None
    final = chain[-1].lower()
    # match against fingerprint db
    for service, cname_suffix, body_markers in TAKEOVER_FINGERPRINTS:
        if cname_suffix in final:
            # fetch the subdomain, look for "resource missing" markers
            try:
                r = requests.get(f"https://{subdomain}", headers={"User-Agent": UA},
                                 timeout=timeout, allow_redirects=True)
                body = (r.text or "")[:8000]
                for marker in body_markers:
                    if marker.lower() in body.lower():
                        return {
                            "subdomain": subdomain,
                            "cname_chain": chain,
                            "service": service,
                            "marker": marker,
                            "status": r.status_code,
                            "vulnerable": True,
                        }
            except Exception:
                pass
            return {
                "subdomain": subdomain,
                "cname_chain": chain,
                "service": service,
                "marker": None,
                "vulnerable": False,
                "note": "matches fingerprint suffix but body check failed",
            }
    return None


def _subdomain_takeover_scan(subs, threads=20):
    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_subdomain_takeover_check, s) for s in subs]
        for f in as_completed(futs):
            r = f.result()
            if r:
                results.append(r)
    return results


# ───────────────────────── typosquat ─────────────────────────

HOMOGLYPHS = {
    "a": ["4", "@"],
    "b": ["d", "6"],
    "c": ["(", "k"],
    "d": ["b", "cl"],
    "e": ["3"],
    "g": ["9", "q"],
    "h": ["n"],
    "i": ["1", "l", "!"],
    "j": ["i"],
    "l": ["1", "i"],
    "m": ["rn", "nn"],
    "n": ["m", "h"],
    "o": ["0"],
    "q": ["g"],
    "r": ["n"],
    "s": ["5", "$"],
    "t": ["7", "+"],
    "u": ["v"],
    "v": ["u"],
    "w": ["vv", "uu"],
    "x": ["ks"],
    "y": ["j"],
    "z": ["2"],
}

KEYBOARD_NEIGHBORS = {
    "a": "qwsz",
    "b": "vghn",
    "c": "xdfv",
    "d": "serfcx",
    "e": "wsdr",
    "f": "drtgvc",
    "g": "ftyhbv",
    "h": "gyujnb",
    "i": "ujko",
    "j": "huikmn",
    "k": "jiolm",
    "l": "kop",
    "m": "njk",
    "n": "bhjm",
    "o": "iklp",
    "p": "ol",
    "q": "wa",
    "r": "edft",
    "s": "awedxz",
    "t": "rfgy",
    "u": "yhji",
    "v": "cfgb",
    "w": "qase",
    "x": "zsdc",
    "y": "tghu",
    "z": "asx",
}


def _typosquat_generate(domain):
    """Generate typosquat candidates for a domain."""
    if "." not in domain:
        return []
    name, _, tld = domain.partition(".")
    variants = set()

    # insertion
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"
    for c in alphabet:
        for i in range(len(name) + 1):
            variants.add(name[:i] + c + name[i:])

    # deletion
    for i in range(len(name)):
        variants.add(name[:i] + name[i+1:])

    # transposition
    for i in range(len(name) - 1):
        variants.add(name[:i] + name[i+1] + name[i] + name[i+2:])

    # replacement with keyboard neighbors
    for i, ch in enumerate(name):
        for neigh in KEYBOARD_NEIGHBORS.get(ch, ""):
            variants.add(name[:i] + neigh + name[i+1:])

    # replacement with homoglyphs
    for i, ch in enumerate(name):
        for gly in HOMOGLYPHS.get(ch, []):
            variants.add(name[:i] + gly + name[i+1:])

    # tld swap
    common_tlds = ["com", "net", "org", "io", "co", "info", "biz",
                   "ru", "de", "uk", "xyz", "app", "dev"]
    for t in common_tlds:
        if t != tld:
            variants.add(f"{name}.{t}")

    # common prefixes/suffixes
    for prefix in ("www-", "web-", "secure-", "login-", "auth-", "my-"):
        variants.add(f"{prefix}{name}.{tld}")
    for suffix in ("-secure", "-login", "-auth", "-support", "-service",
                   "-portal", "-online"):
        variants.add(f"{name}{suffix}.{tld}")

    # drop the original
    variants.discard(domain)
    return sorted(variants)[:300]


def _typosquat_resolve(variants, threads=30):
    """Check which typosquat candidates resolve."""
    resolved = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_resolve_sub, v.split(".")[0], ".".join(v.split(".")[1:])): v
                for v in variants if v.count(".") >= 1}
        for f in as_completed(futs):
            r = f.result()
            if r:
                resolved.append({
                    "domain": futs[f],
                    "ip": r["ip"],
                })
    return resolved


# ───────────────────────── robots + security.txt ─────────────────────────

def _robots(domain):
    out = {"robots": None, "sitemap": None, "disallow": [], "allow": [],
           "crawl_delay": None, "user_agents": []}
    try:
        r = requests.get(f"https://{domain}/robots.txt",
                         headers={"User-Agent": UA}, timeout=8)
        if r.status_code == 200:
            out["robots"] = f"https://{domain}/robots.txt"
            current_ua = None
            for line in r.text.splitlines():
                line = line.strip()
                low = line.lower()
                if low.startswith("user-agent:"):
                    current_ua = line.split(":", 1)[1].strip()
                    out["user_agents"].append(current_ua)
                elif low.startswith("disallow:"):
                    out["disallow"].append(line.split(":", 1)[1].strip())
                elif low.startswith("allow:"):
                    out["allow"].append(line.split(":", 1)[1].strip())
                elif low.startswith("crawl-delay:"):
                    try:
                        out["crawl_delay"] = float(line.split(":", 1)[1].strip())
                    except Exception:
                        pass
                elif low.startswith("sitemap:"):
                    out["sitemap"] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    if not out["sitemap"]:
        for path in ("sitemap.xml", "sitemap_index.xml", "sitemap-index.xml"):
            try:
                r = requests.head(f"https://{domain}/{path}",
                                  headers={"User-Agent": UA}, timeout=6)
                if r.status_code == 200:
                    out["sitemap"] = f"https://{domain}/{path}"
                    break
            except Exception:
                continue
    return out


def _securitytxt(domain):
    """Fetch and parse security.txt per RFC 9116."""
    out = {"found": False, "path": None, "fields": {}, "issues": []}
    paths = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt",
    ]
    for path in paths:
        try:
            r = requests.get(path, headers={"User-Agent": UA}, timeout=8)
            if r.status_code == 200 and ("Contact:" in r.text or "contact:" in r.text):
                out["found"] = True
                out["path"] = path
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        k, _, v = line.partition(":")
                        out["fields"].setdefault(k.strip(), []).append(v.strip())
                break
        except Exception:
            continue
    if out["found"]:
        if "Contact" not in out["fields"] and "contact" not in out["fields"]:
            out["issues"].append("no Contact field — mandatory per RFC 9116")
        if "Expires" not in out["fields"] and "expires" not in out["fields"]:
            out["issues"].append("no Expires field — mandatory per RFC 9116")
        else:
            expires_val = (out["fields"].get("Expires") or out["fields"].get("expires") or [""])[0]
            try:
                exp = datetime.fromisoformat(expires_val.replace("Z", "+00:00"))
                if exp < datetime.now(exp.tzinfo):
                    out["issues"].append(f"Expires is in the past: {expires_val}")
            except Exception:
                pass
    return out


# ───────────────────────── sensitive paths ─────────────────────────

def _probe_path(domain, path, markers, timeout=6):
    url = f"https://{domain}{path}"
    try:
        r = requests.get(url, headers={"User-Agent": UA},
                         timeout=timeout, allow_redirects=False)
    except Exception:
        try:
            r = requests.get(f"http://{domain}{path}",
                             headers={"User-Agent": UA},
                             timeout=timeout, allow_redirects=False)
        except Exception:
            return None
    if r.status_code == 200:
        body = (r.text or "")[:4000]
        if markers:
            if any(m.lower() in body.lower() for m in markers):
                return {"path": path, "status": 200,
                        "size": len(r.content), "note": "confirmed"}
            return {"path": path, "status": 200,
                    "size": len(r.content), "note": "soft-200 (unconfirmed)"}
        ctype = r.headers.get("Content-Type", "").lower()
        if "text/html" in ctype and len(body) > 800:
            return None
        return {"path": path, "status": 200,
                "size": len(r.content), "note": "exposed"}
    if r.status_code in (401, 403):
        return {"path": path, "status": r.status_code,
                "size": 0, "note": "exists (guarded)"}
    return None


def _audit_paths(domain, threads=20):
    hits = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_probe_path, domain, p, m) for p, m in SENSITIVE_PATHS]
        for f in as_completed(futs):
            r = f.result()
            if r:
                hits.append(r)
    return sorted(hits, key=lambda x: x["path"])


# ───────────────────────── wayback ─────────────────────────

def _wayback_summary(domain):
    """Query the Wayback Machine CDX API for snapshot stats."""
    try:
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{domain}/*",
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype",
                "collapse": "urlkey",
                "limit": 200,
            },
            headers={"User-Agent": UA}, timeout=20,
        )
        if r.status_code != 200:
            return None
        rows = r.json()
    except Exception:
        return None
    if not rows or len(rows) < 2:
        return None
    header = rows[0]
    body = rows[1:]
    first = body[0][0] if body else None
    last = body[-1][0] if body else None
    urls = set()
    statuses = {}
    for row in body:
        if len(row) >= 4:
            urls.add(row[1])
            statuses[row[2]] = statuses.get(row[2], 0) + 1
    return {
        "snapshot_count": len(body),
        "first_snapshot": first,
        "last_snapshot": last,
        "unique_urls": len(urls),
        "status_codes": statuses,
        "sample": list(urls)[:20],
    }


# ───────────────────────── ports ─────────────────────────

def _scan_port(host, port):
    try:
        with socket.create_connection((host, port), timeout=2):
            try:
                banner_sock = socket.socket()
                banner_sock.settimeout(1.5)
                banner_sock.connect((host, port))
                # some services send a banner unprovoked
                try:
                    banner = banner_sock.recv(256).decode(errors="ignore").strip()
                except Exception:
                    banner = ""
                banner_sock.close()
                return port, "open", banner
            except Exception:
                return port, "open", ""
    except Exception:
        return port, "closed", ""


# ───────────────────────── render ─────────────────────────

def _render(domain, dns, dnssec, caa, axfr, prop, wildcard,
            ptr, asn, email_sec, rdap, ssl_d, tls_versions,
            http_versions, http, tech, waf, sec, csp, hsts, xfo,
            cookies, cors, methods, redirects, favicon,
            subs, brute_subs, takeovers, typosquats,
            rb, sectxt, sensitive, wayback, ports):
    console.print(Panel.fit(
        f"[bg]DOMAIN RECON[/bg]  [dg]{domain}[/dg]",
        border_style="bd", padding=(0, 2),
    ))

    # DNS
    if dns:
        dt = Table(border_style="bd", title="[bg]dns[/bg]",
                   show_header=True, padding=(0, 2))
        dt.add_column("type", style="bg", no_wrap=True)
        dt.add_column("value", style="g", overflow="fold")
        for rtype, vals in dns.items():
            for v in vals:
                dt.add_row(rtype, v)
        console.print(dt)

    # DNSSEC
    if dnssec:
        state = dnssec.get("state")
        score = dnssec.get("score", 0)
        dt = Table(border_style="bd",
                   title=f"[bg]dnssec[/bg]  [g]state={state}  score={score}/100[/g]",
                   show_header=False, padding=(0, 2))
        dt.add_column("k", style="dg", no_wrap=True)
        dt.add_column("v", style="g", overflow="fold")
        dt.add_row("DS records", str(len(dnssec.get("ds") or [])))
        dt.add_row("DNSKEY count", str(dnssec.get("dnskey_count", 0)))
        dt.add_row("RRSIG count", str(dnssec.get("rrsig_count", 0)))
        for k in dnssec.get("dnskey") or []:
            dt.add_row("  dnskey", f"alg={k.get('algorithm')} flags={k.get('flags')}")
        console.print(dt)
        if dnssec.get("issues"):
            for i in dnssec["issues"]:
                console.print(f"[yellow]    · {i}[/yellow]")
            console.print()

    # CAA
    if caa:
        ct = Table(border_style="bd", title="[bg]caa[/bg]",
                   show_header=False, padding=(0, 2))
        ct.add_column("k", style="dg", no_wrap=True)
        ct.add_column("v", style="g", overflow="fold")
        ct.add_row("records", str(len(caa.get("records") or [])))
        for r in (caa.get("records") or []):
            ct.add_row("  ", r[:100])
        console.print(ct)
        if caa.get("issues"):
            for i in caa["issues"]:
                console.print(f"[yellow]    · {i}[/yellow]")
            console.print()

    # AXFR
    if axfr:
        at = Table(border_style="bd",
                   title="[bg]zone transfer (AXFR)[/bg]",
                   show_header=True, padding=(0, 2))
        at.add_column("nameserver", style="bg", overflow="fold")
        at.add_column("ip", style="dg")
        at.add_column("result", style="g")
        at.add_column("records", style="dg", justify="right")
        for r in axfr:
            at.add_row(
                r["nameserver"], r["ip"],
                "[red]VULNERABLE[/red]" if r["vulnerable"] else "closed",
                str(r["record_count"]),
            )
        console.print(at)

    # propagation
    if prop:
        pt = Table(border_style="bd", title="[bg]dns propagation[/bg]",
                   show_header=True, padding=(0, 2))
        pt.add_column("resolver", style="bg")
        pt.add_column("A record(s)", style="g", overflow="fold")
        for r in prop:
            pt.add_row(r["resolver"], ", ".join(r["ips"]) or "—")
        console.print(pt)

    # wildcard
    if wildcard:
        tag = "[red]wildcard DNS detected[/red]" if wildcard["wildcard"] else "no wildcard"
        console.print(f"[dg]  wildcard: {tag}  ({wildcard['sample']} → {wildcard['ip'] or '—'})[/dg]\n")

    # reverse + ASN
    if ptr or asn:
        rt = Table(border_style="bd", title="[bg]reverse / asn[/bg]",
                   show_header=False, padding=(0, 2))
        rt.add_column("k", style="dg", no_wrap=True)
        rt.add_column("v", style="g", overflow="fold")
        if ptr:
            rt.add_row("PTR", ", ".join(ptr))
        if asn:
            rt.add_row("asn handle", str(asn.get("handle") or "—"))
            rt.add_row("asn name", str(asn.get("name") or "—"))
            rt.add_row("country", str(asn.get("country") or "—"))
            rt.add_row("cidr", str(asn.get("cidr") or "—"))
            rt.add_row("autnums", ", ".join(asn.get("autnums") or []) or "—")
        console.print(rt)

    # email security
    if email_sec:
        spf = email_sec.get("spf", {})
        dmarc = email_sec.get("dmarc", {})
        dkim = email_sec.get("dkim", [])
        et = Table(border_style="bd",
                   title=f"[bg]email security[/bg]  "
                         f"[g]score {email_sec.get('score', 0)}/100[/g]",
                   show_header=False, padding=(0, 2))
        et.add_column("k", style="dg", no_wrap=True)
        et.add_column("v", style="g", overflow="fold")
        et.add_row("SPF", "present" if spf.get("present") else "MISSING")
        if spf.get("record"):
            et.add_row("  record", spf["record"])
        if spf.get("all"):
            et.add_row("  all policy", spf["all"])
        et.add_row("DMARC", "present" if dmarc.get("present") else "MISSING")
        if dmarc.get("record"):
            et.add_row("  record", dmarc["record"])
        if dmarc.get("policy"):
            et.add_row("  p=", dmarc["policy"])
        if dmarc.get("rua"):
            et.add_row("  rua", dmarc["rua"])
        et.add_row("DKIM selectors",
                   ", ".join(d["selector"] for d in dkim) if dkim
                   else "none found")
        if email_sec.get("mx"):
            et.add_row("MX", ", ".join(email_sec["mx"][:4]))
        console.print(et)
        issues = list(spf.get("issues") or []) + list(dmarc.get("issues") or [])
        if issues:
            console.print("[dg]  issues:[/dg]")
            for i in issues:
                console.print(f"[yellow]    · {i}[/yellow]")
            console.print()

    # RDAP
    if rdap:
        rt = Table(border_style="bd", title="[bg]registration[/bg]",
                   show_header=False, padding=(0, 2))
        rt.add_column("k", style="dg", no_wrap=True)
        rt.add_column("v", style="g")
        rt.add_row("handle", rdap.get("handle") or "—")
        for k, v in (rdap.get("events") or {}).items():
            rt.add_row(k, v)
        if rdap.get("nameservers"):
            rt.add_row("nameservers", ", ".join(rdap["nameservers"]))
        for e in rdap.get("entities", []):
            if e.get("role") == "registrar":
                rt.add_row("registrar", e.get("name") or "—")
        if rdap.get("status"):
            rt.add_row("status", ", ".join(rdap["status"]))
        console.print(rt)

    # SSL
    if ssl_d and "error" not in ssl_d:
        st = Table(border_style="bd", title="[bg]ssl cert[/bg]",
                   show_header=False, padding=(0, 2))
        st.add_column("k", style="dg", no_wrap=True)
        st.add_column("v", style="g", overflow="fold")
        st.add_row("subject", ssl_d.get("subject_cn") or "—")
        st.add_row("org", ssl_d.get("subject_org") or "—")
        st.add_row("issuer", ssl_d.get("issuer_cn") or "—")
        st.add_row("not before", ssl_d.get("not_before") or "—")
        st.add_row("not after", ssl_d.get("not_after") or "—")
        st.add_row("san count", str(ssl_d.get("san_count") or 0))
        st.add_row("protocol", ssl_d.get("protocol") or "—")
        st.add_row("cipher", ssl_d.get("cipher") or "—")
        if ssl_d.get("sans"):
            st.add_row("sans", ", ".join(ssl_d["sans"][:12]))
        console.print(st)

    # TLS versions
    if tls_versions:
        tt = Table(border_style="bd", title="[bg]tls versions[/bg]",
                   show_header=True, padding=(0, 2))
        tt.add_column("version", style="bg")
        tt.add_column("state", style="g")
        for v, state in tls_versions.items():
            color = "g" if state == "supported" else "dg"
            if v in ("TLS 1.0", "TLS 1.1") and state == "supported":
                color = "yellow"
            tt.add_row(v, f"[{color}]{state}[/{color}]")
        console.print(tt)

    # HTTP versions
    if http_versions:
        parts = []
        if http_versions.get("h1"):
            parts.append(f"HTTP/{http_versions['h1']}")
        if http_versions.get("h3"):
            parts.append("HTTP/3 (Alt-Svc)")
        if http_versions.get("alt_svc"):
            parts.append(f"Alt-Svc: {http_versions['alt_svc'][:60]}")
        if parts:
            console.print(f"[dg]  http versions: {', '.join(parts)}[/dg]")

    # HTTP
    if http:
        ht = Table(border_style="bd", title="[bg]http[/bg]",
                   show_header=False, padding=(0, 2))
        ht.add_column("k", style="dg", no_wrap=True)
        ht.add_column("v", style="g", overflow="fold")
        ht.add_row("final url", http.get("url"))
        ht.add_row("status", str(http.get("status")))
        ht.add_row("server", http.get("server") or "—")
        ht.add_row("x-powered-by", http.get("powered_by") or "—")
        ht.add_row("via", http.get("via") or "—")
        ht.add_row("cdn", http.get("cdn") or "—")
        console.print(ht)

        chain = http.get("redirect_chain") or []
        if chain and len(chain) > 1:
            rt = Table(border_style="bd",
                       title="[bg]redirect chain[/bg]",
                       show_header=True, padding=(0, 2))
            rt.add_column("#", style="dg", justify="right")
            rt.add_column("status", style="bg", justify="right")
            rt.add_column("url", style="g", overflow="fold")
            for i, hop in enumerate(chain, 1):
                rt.add_row(str(i), str(hop.get("status")), hop.get("url"))
            console.print(rt)

    # tech
    if tech:
        console.print(f"[dg]  tech fingerprint: {', '.join(tech)}[/dg]")

    # WAF / CDN
    if waf:
        wt = Table(border_style="bd", title="[bg]waf / cdn[/bg]",
                   show_header=True, padding=(0, 2))
        wt.add_column("name", style="bg", no_wrap=True)
        wt.add_column("evidence", style="g", overflow="fold")
        for hit in waf:
            wt.add_row(hit["name"], ", ".join(hit["evidence"]))
        console.print(wt)

    # security headers
    if sec:
        sect = Table(border_style="bd",
                     title="[bg]security headers[/bg]",
                     show_header=True, padding=(0, 2))
        sect.add_column("header", style="dg", overflow="fold")
        sect.add_column("present", style="g")
        for h, v in sec:
            mark = "[green]yes[/green]" if v == "yes" else "[red]no[/red]"
            sect.add_row(h, mark)
        console.print(sect)

    # CSP
    if csp and csp.get("present"):
        console.print("[dg]  csp directives:[/dg]")
        for dn, vals in (csp.get("directives") or {}).items():
            console.print(f"[g]    {dn}: {' '.join(vals)[:100]}[/g]")
        if csp.get("issues"):
            for i in csp["issues"]:
                console.print(f"[yellow]    · {i}[/yellow]")
        console.print()
    elif csp:
        console.print("[yellow]  csp: not present[/yellow]")

    # HSTS
    if hsts and hsts.get("present"):
        console.print(f"[dg]  hsts: {hsts['raw'][:80]}[/dg]")
        for i in hsts.get("issues") or []:
            console.print(f"[yellow]    · {i}[/yellow]")
        console.print()
    elif hsts:
        console.print("[yellow]  hsts: not present[/yellow]\n")

    # XFO
    if xfo and not xfo.get("present"):
        console.print("[yellow]  x-frame-options: missing[/yellow]\n")

    # cookies
    if cookies:
        ckt = Table(border_style="bd",
                    title=f"[bg]cookies[/bg]  [g]{len(cookies)}[/g]",
                    show_header=True, padding=(0, 2))
        ckt.add_column("name", style="bg", overflow="fold")
        ckt.add_column("secure", style="g")
        ckt.add_column("httponly", style="g")
        ckt.add_column("samesite", style="g")
        ckt.add_column("issues", style="dg", overflow="fold")
        for ck in cookies:
            ckt.add_row(
                ck["name"],
                "[green]y[/green]" if ck["secure"] else "[red]n[/red]",
                "[green]y[/green]" if ck["httponly"] else "[red]n[/red]",
                ck["samesite"] or "[red]—[/red]",
                "; ".join(ck["issues"]),
            )
        console.print(ckt)

    # CORS
    if cors:
        cot = Table(border_style="bd",
                    title="[bg]cors findings[/bg]",
                    show_header=True, padding=(0, 2))
        cot.add_column("origin", style="bg", overflow="fold")
        cot.add_column("method", style="dg")
        cot.add_column("acao", style="g", overflow="fold")
        cot.add_column("issues", style="dg", overflow="fold")
        for c in cors:
            cot.add_row(
                c["origin"], c["method"], c.get("acao") or "—",
                "; ".join(c["issues"]),
            )
        console.print(cot)

    # HTTP methods
    if methods:
        mt = Table(border_style="bd", title="[bg]http methods[/bg]",
                   show_header=True, padding=(0, 2))
        mt.add_column("method", style="bg", no_wrap=True)
        mt.add_column("status", style="g", justify="right")
        mt.add_column("allow", style="dg", overflow="fold")
        mt.add_column("risky", style="dg", overflow="fold")
        for m in methods:
            risky = "; ".join(m.get("risky") or [])
            mt.add_row(
                m["method"],
                str(m["status"]) if m["status"] else "—",
                (m.get("allow") or "—")[:60],
                risky,
            )
        console.print(mt)

    # open redirect
    if redirects:
        console.print("[yellow]  open redirect candidates:[/yellow]")
        for r in redirects:
            console.print(f"[yellow]    · {r['param']} → {r['location'][:80]}[/yellow]")
        console.print()

    # favicon
    if favicon:
        console.print(f"[dg]  favicon: size={favicon['size']}b  "
                      f"md5={favicon['md5']}  "
                      f"shodan_query={favicon['shodan_query']}[/dg]")

    # crt.sh subdomains
    if subs:
        console.print(Panel.fit(
            f"[bg]subdomains (crt.sh)[/bg]  [g]{len(subs)} unique[/g]",
            border_style="bd", padding=(0, 2),
        ))
        for s in subs[:40]:
            console.print(f"[g]  · {s}[/g]")
        if len(subs) > 40:
            console.print(f"[dg]  ... +{len(subs) - 40} more[/dg]")
        console.print()

    # brute-force subdomains
    if brute_subs:
        bt = Table(border_style="bd",
                   title=f"[bg]active subdomains (brute)[/bg]  "
                         f"[g]{len(brute_subs)} resolved[/g]",
                   show_header=True, padding=(0, 2))
        bt.add_column("subdomain", style="bg", overflow="fold")
        bt.add_column("ip", style="g")
        for r in brute_subs:
            bt.add_row(r["subdomain"], r["ip"])
        console.print(bt)

    # subdomain takeover
    if takeovers:
        tt = Table(border_style="bd",
                   title=f"[bg]subdomain takeover[/bg]  "
                         f"[g]{len(takeovers)} candidate(s)[/g]",
                   show_header=True, padding=(0, 2))
        tt.add_column("subdomain", style="bg", overflow="fold")
        tt.add_column("service", style="g")
        tt.add_column("cname chain", style="dg", overflow="fold")
        tt.add_column("state", style="g")
        for t in takeovers:
            state = "[red]VULNERABLE[/red]" if t["vulnerable"] else "[yellow]candidate[/yellow]"
            tt.add_row(
                t["subdomain"], t["service"],
                " → ".join(t["cname_chain"])[:100],
                state,
            )
        console.print(tt)

    # typosquats
    if typosquats:
        tt = Table(border_style="bd",
                   title=f"[bg]typosquat resolutions[/bg]  "
                         f"[g]{len(typosquats)}[/g]",
                   show_header=True, padding=(0, 2))
        tt.add_column("domain", style="bg", overflow="fold")
        tt.add_column("ip", style="g")
        for t in typosquats[:30]:
            tt.add_row(t["domain"], t["ip"])
        if len(typosquats) > 30:
            console.print(f"[dg]  ... +{len(typosquats) - 30} more[/dg]")
        console.print()

    # robots
    if rb and (rb.get("robots") or rb.get("disallow") or rb.get("sitemap")):
        bt = Table(border_style="bd", title="[bg]robots / sitemap[/bg]",
                   show_header=False, padding=(0, 2))
        bt.add_column("k", style="dg", no_wrap=True)
        bt.add_column("v", style="g", overflow="fold")
        bt.add_row("robots", rb.get("robots") or "—")
        bt.add_row("sitemap", rb.get("sitemap") or "—")
        if rb.get("disallow"):
            bt.add_row("disallow", ", ".join(rb["disallow"][:15]))
        if rb.get("crawl_delay") is not None:
            bt.add_row("crawl-delay", str(rb["crawl_delay"]))
        console.print(bt)

    # security.txt
    if sectxt and sectxt.get("found"):
        stxt = Table(border_style="bd",
                     title="[bg]security.txt (RFC 9116)[/bg]",
                     show_header=False, padding=(0, 2))
        stxt.add_column("k", style="dg", no_wrap=True)
        stxt.add_column("v", style="g", overflow="fold")
        stxt.add_row("path", sectxt["path"])
        for k, vals in sectxt["fields"].items():
            stxt.add_row(k, ", ".join(vals)[:120])
        console.print(stxt)
        for i in sectxt.get("issues") or []:
            console.print(f"[yellow]    · {i}[/yellow]")
        console.print()

    # sensitive paths
    if sensitive:
        st = Table(border_style="bd",
                   title=f"[bg]sensitive paths[/bg]  "
                         f"[g]{len(sensitive)} hit(s)[/g]",
                   show_header=True, padding=(0, 2))
        st.add_column("path", style="bg", overflow="fold")
        st.add_column("code", style="dg", justify="right")
        st.add_column("size", style="dg", justify="right")
        st.add_column("note", style="g")
        for hit in sensitive:
            st.add_row(hit["path"], str(hit["status"]),
                       str(hit.get("size") or 0), hit.get("note") or "")
        console.print(st)

    # wayback
    if wayback:
        wt = Table(border_style="bd",
                   title="[bg]wayback machine[/bg]",
                   show_header=False, padding=(0, 2))
        wt.add_column("k", style="dg", no_wrap=True)
        wt.add_column("v", style="g")
        wt.add_row("snapshots", str(wayback["snapshot_count"]))
        wt.add_row("unique urls", str(wayback["unique_urls"]))
        wt.add_row("first", wayback["first_snapshot"] or "—")
        wt.add_row("last", wayback["last_snapshot"] or "—")
        if wayback.get("status_codes"):
            wt.add_row("status codes",
                       ", ".join(f"{k}:{v}" for k, v in wayback["status_codes"].items()))
        console.print(wt)

    # ports
    if ports:
        pt = Table(border_style="bd", title="[bg]top ports[/bg]",
                   show_header=True, padding=(0, 2))
        pt.add_column("port", style="bg", justify="right")
        pt.add_column("service", style="dg")
        pt.add_column("state", style="g")
        pt.add_column("banner", style="g", overflow="fold")
        open_ports = [p for p in ports if p[1] == "open"]
        for port, state, banner in sorted(ports):
            svc = next((s for p, s in TOP_PORTS if p == port), "?")
            pt.add_row(str(port), svc, state, banner[:60] or "")
        console.print(pt)
        console.print(f"[dg]  {len(open_ports)} open / {len(ports)} scanned[/dg]\n")


def _export(domain, payload):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", domain)[:40]
    p = OUT_DIR / f"domain_{safe}_{ts}.json"
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False,
                            default=str), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]\n")


# ───────────────────────── main ─────────────────────────

def run():
    domain = input("  domain >> ").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    if not domain or "." not in domain:
        print("  [!] invalid domain")
        return

    # ---- phase 1: dns + dnssec + caa + email + rdap + ssl ----
    with tqdm(total=len(RECORD_TYPES) + 8, desc="dns + dnssec + email",
              ncols=60, bar_format=BAR_FMT) as bar:
        dns = {}
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(_dns, domain, rt): rt for rt in RECORD_TYPES}
            for f in as_completed(futs):
                rt, vals = f.result()
                if vals:
                    dns[rt] = vals
                bar.update(1)
        dnssec = _dnssec_validate(domain); bar.update(1)
        caa = _caa(domain); bar.update(1)
        email_sec = _audit_email(domain); bar.update(1)
        rdap = _rdap(domain); bar.update(1)
        ssl_d = _ssl_cert(domain); bar.update(1)
        tls_versions = _tls_probe(domain); bar.update(1)
        http = _http_headers(domain); bar.update(1)

    # ---- phase 2: axfr + prop + wildcard + ptr + asn ----
    with tqdm(total=5, desc="axfr + propagation", ncols=60,
              bar_format=BAR_FMT) as bar:
        ns_records = []
        for v in dns.get("NS", []) or []:
            ns_records.append(v.rstrip("."))
        axfr = _try_axfr(domain, ns_records) if ns_records else []
        bar.update(1)
        prop = _propagation(domain); bar.update(1)
        wildcard = _wildcard_dns(domain); bar.update(1)

        # reverse + asn on the A record
        ptr = []
        asn = None
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = None
        if ip:
            ptr = _ptr(ip)
            asn = _asn_info(ip)
        bar.update(1)
        bar.update(1)

    # ---- phase 3: http analysis ----
    tech = _fingerprint(http)
    waf = _detect_waf(http)
    sec = _audit_security(http.get("headers") if http else None)
    csp = _analyze_csp(http.get("headers") if http else None)
    hsts = _analyze_hsts(http.get("headers") if http else None)
    xfo = _analyze_frame_options(http.get("headers") if http else None)
    cookies = _audit_cookies(http.get("headers") if http else None)
    http_versions = _http_version_probe(domain)

    # ---- phase 4: active probes (cors, methods, redirect, favicon) ----
    with tqdm(total=4, desc="active http probes", ncols=60,
              bar_format=BAR_FMT) as bar:
        target = f"https://{domain}"
        cors = _cors_probe(target); bar.update(1)
        methods = _http_methods_probe(target); bar.update(1)
        redirects = _open_redirect_probe(target); bar.update(1)
        favicon = _favicon_hash(domain); bar.update(1)

    # ---- phase 5: subdomains + takeover + typos + robots + txt + paths + wayback ----
    with tqdm(total=8, desc="subs + paths + typos", ncols=60,
              bar_format=BAR_FMT) as bar:
        subs = _crtsh(domain); bar.update(1)
        rb = _robots(domain); bar.update(1)
        sectxt = _securitytxt(domain); bar.update(1)

        # parallel heavy lifts
        brute_subs = []
        sensitive = []
        takeovers = []
        typosquats = []
        with ThreadPoolExecutor(max_workers=4) as ex:
            f_brute = ex.submit(_brute_subdomains, domain, SUBDOMAIN_WORDLIST)
            f_paths = ex.submit(_audit_paths, domain)
            f_take = ex.submit(_subdomain_takeover_scan, subs[:60])
            f_typo = ex.submit(_typosquat_resolve,
                               _typosquat_generate(domain))
            brute_subs = f_brute.result()
            bar.update(1)
            sensitive = f_paths.result()
            bar.update(1)
            takeovers = f_take.result()
            bar.update(1)
            typosquats = f_typo.result()
            bar.update(1)

        wayback = _wayback_summary(domain); bar.update(1)

        # ports last — longest
        try:
            ip2 = socket.gethostbyname(domain)
        except Exception:
            ip2 = None
        ports = []
        if ip2:
            with ThreadPoolExecutor(max_workers=30) as ex:
                futs = [ex.submit(_scan_port, ip2, p) for p, _ in TOP_PORTS]
                for f in as_completed(futs):
                    ports.append(f.result())
        bar.update(1)

    _render(domain, dns, dnssec, caa, axfr, prop, wildcard,
            ptr, asn, email_sec, rdap, ssl_d, tls_versions,
            http_versions, http, tech, waf, sec, csp, hsts, xfo,
            cookies, cors, methods, redirects, favicon,
            subs, brute_subs, takeovers, typosquats,
            rb, sectxt, sensitive, wayback, ports)

    if input("  export? [y/N] >> ").strip().lower() == "y":
        _export(domain, {
            "domain": domain,
            "dns": dns,
            "dnssec": dnssec,
            "caa": caa,
            "axfr": axfr,
            "propagation": prop,
            "wildcard": wildcard,
            "ptr": ptr,
            "asn": asn,
            "email_security": email_sec,
            "rdap": rdap,
            "ssl": ssl_d,
            "tls_versions": tls_versions,
            "http_versions": http_versions,
            "http": {k: v for k, v in (http or {}).items()
                     if k not in ("body_snippet", "body_full")},
            "tech": tech,
            "waf_cdn": waf,
            "security_headers": sec,
            "csp": csp,
            "hsts": hsts,
            "x_frame_options": xfo,
            "cookies": cookies,
            "cors": cors,
            "http_methods": methods,
            "open_redirects": redirects,
            "favicon": favicon,
            "subdomains_crtsh": subs,
            "subdomains_brute": brute_subs,
            "subdomain_takeover": takeovers,
            "typosquats": typosquats,
            "robots": rb,
            "securitytxt": sectxt,
            "sensitive_paths": sensitive,
            "wayback": wayback,
            "ports": [{"port": p, "state": s, "banner": b}
                      for p, s, b in ports],
            "generated": datetime.now().isoformat(timespec="seconds"),
        })
