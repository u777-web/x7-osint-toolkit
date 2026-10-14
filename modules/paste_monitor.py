"""
paste_monitor.py — Pastebin & leak-site keyword monitor.

Searches:
  · psbdmp.ws (mirror/index of pastebin dumps)
  · pastebin.com/api_scraping.php (public recent feed)
  · ghostbin / rentry public feeds (best effort)

Modes:
  · one-shot search for a keyword
  · continuous monitor loop with configurable interval
"""

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

console = Console(theme=Theme({
    "g": "grey70", "dg": "grey50", "bg": "grey93", "bd": "grey37",
}))

BAR_FMT = "\033[38;5;245m  {desc} |{bar}| {percentage:3.0f}%\033[0m"
OUT_DIR = Path.home() / ".osinttoolkit" / "exports"
OUT_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = OUT_DIR / "paste_monitor_seen.json"

UA = "Mozilla/5.0 (compatible; doxtoolkit/2.0)"


# ───────────────────────── sources ─────────────────────────

def psbdmp_search(query):
    """psbdmp.ws — indexed pastebin dump search."""
    try:
        r = requests.get(
            f"https://psbdmp.ws/api/v3/search/{query}",
            headers={"User-Agent": UA}, timeout=20,
        )
        if r.status_code != 200:
            return []
        d = r.json()
        if isinstance(d, dict) and d.get("status") == "success":
            items = d.get("data") or []
        elif isinstance(d, list):
            items = d
        else:
            return []
        out = []
        for it in items:
            if not isinstance(it, dict):
                continue
            pid = it.get("id") or it.get("paste_id")
            if not pid:
                continue
            out.append({
                "id": pid,
                "source": "psbdmp",
                "url": f"https://pastebin.com/{pid}",
                "time": it.get("time"),
                "tags": it.get("tags") or [],
                "preview": (it.get("text") or it.get("text_preview") or "")[:200],
            })
        return out
    except Exception:
        return []


def pastebin_recent(limit=100):
    """pastebin public scraping endpoint — best effort."""
    try:
        r = requests.get(
            "https://pastebin.com/api_scraping.php",
            params={"limit": limit},
            headers={"User-Agent": UA}, timeout=20,
        )
        if r.status_code != 200:
            return []
        d = r.json()
        if not isinstance(d, list):
            return []
        out = []
        for it in d:
            url = it.get("scrape_url") or ""
            if not url:
                continue
            out.append({
                "id": it.get("key"),
                "source": "pastebin-feed",
                "url": url,
                "time": it.get("scrape_date"),
                "title": it.get("title") or "",
                "syntax": it.get("syntax") or "",
            })
        return out
    except Exception:
        return []


def fetch_paste(url):
    try:
        raw = url
        if "pastebin.com/" in raw and not raw.endswith("/raw"):
            pid = raw.rsplit("/", 1)[-1]
            raw = f"https://pastebin.com/raw/{pid}"
        r = requests.get(raw, headers={"User-Agent": UA}, timeout=15)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None


# ───────────────────────── state ─────────────────────────

def load_seen():
    if STATE_FILE.exists():
        try:
            return set(json.loads(STATE_FILE.read_text(encoding="utf-8")))
        except Exception:
            return set()
    return set()


def save_seen(seen):
    try:
        STATE_FILE.write_text(
            json.dumps(sorted(seen), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


# ───────────────────────── filter ─────────────────────────

def matches_keyword(text, keyword):
    if not text:
        return False
    return keyword.lower() in text.lower()


def build_context(text, keyword, width=120):
    if not text:
        return ""
    idx = text.lower().find(keyword.lower())
    if idx < 0:
        return text[:width]
    start = max(0, idx - width // 2)
    end = min(len(text), idx + len(keyword) + width // 2)
    snippet = text[start:end].replace("\n", " ")
    return f"…{snippet}…"


# ───────────────────────── render ─────────────────────────

def _render(hits, keyword, scanned):
    console.print(Panel.fit(
        f"[bg]PASTE MONITOR[/bg]  [dg]\"{keyword}\"[/dg]  ·  "
        f"[g]{len(hits)} hit(s) / {scanned} scanned[/g]",
        border_style="bd", padding=(0, 2),
    ))

    if not hits:
        console.print("[dg]  no matches[/dg]\n")
        return

    t = Table(border_style="bd", show_header=True, padding=(0, 2))
    t.add_column("#", style="dg", justify="right")
    t.add_column("source", style="bg")
    t.add_column("time", style="dg")
    t.add_column("url", style="g", overflow="fold")
    t.add_column("context", style="g", overflow="fold")

    for i, h in enumerate(hits, 1):
        t.add_row(str(i), h.get("source", "?"),
                  str(h.get("time") or "-"),
                  h.get("url", "?"),
                  h.get("context", "")[:100])
    console.print(t)
    console.print()


def _export(keyword, hits, scanned):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", keyword)[:32] or "kw"
    p = OUT_DIR / f"paste_{safe}_{ts}.json"
    p.write_text(json.dumps({
        "keyword": keyword, "scanned": scanned, "hits": hits,
        "generated": datetime.now().isoformat(timespec="seconds"),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]\n")


# ───────────────────────── passes ─────────────────────────

def run_pass(keyword, seen, psbdmp_only=False):
    hits = []

    with tqdm(total=3, desc="querying sources",
              ncols=60, bar_format=BAR_FMT) as bar:
        dump_results = psbdmp_search(keyword); bar.update(1)

        feed_results = []
        if not psbdmp_only:
            feed = pastebin_recent(limit=60)
            for p in feed:
                uid = f"{p['source']}:{p['id']}"
                if uid in seen:
                    continue
                body = fetch_paste(p["url"])
                time.sleep(0.3)
                if body and matches_keyword(body, keyword):
                    feed_results.append({
                        "id": uid, "source": p["source"], "url": p["url"],
                        "time": p.get("time"),
                        "context": build_context(body, keyword),
                    })
        bar.update(1)

        for d in dump_results:
            uid = f"{d['source']}:{d['id']}"
            if uid in seen:
                continue
            preview = d.get("preview") or ""
            context = build_context(preview, keyword) if preview else ""
            if not context:
                body = fetch_paste(d["url"])
                if body:
                    context = build_context(body, keyword)
            hits.append({
                "id": uid, "source": d["source"], "url": d["url"],
                "time": d.get("time"), "context": context,
            })
            seen.add(uid)
        bar.update(1)

    hits.extend(feed_results)
    for h in feed_results:
        seen.add(h["id"])

    return hits, len(dump_results) + len(feed_results)


# ───────────────────────── entry ─────────────────────────

def run():
    keyword = input("  keyword / email / domain >> ").strip()
    if not keyword:
        print("  [!] empty keyword")
        return

    mode = input("  mode: [1] one-shot  [2] monitor loop >> ").strip() or "1"

    if mode == "2":
        try:
            interval = int(input("  interval seconds [300] >> ").strip() or "300")
        except ValueError:
            interval = 300
        seen = load_seen()
        console.print(f"[dg]  monitoring \"{keyword}\" every {interval}s  "
                      f"(ctrl-c to stop)[/dg]\n")
        try:
            while True:
                hits, scanned = run_pass(keyword, seen)
                save_seen(seen)
                _render(hits, keyword, scanned)
                if hits and input("  export this batch? [y/N] >> "
                                  ).strip().lower() == "y":
                    _export(keyword, hits, scanned)
                time.sleep(interval)
        except KeyboardInterrupt:
            console.print("\n[dim]  monitor stopped[/dim]\n")
        return

    seen = load_seen()
    hits, scanned = run_pass(keyword, seen)
    save_seen(seen)
    _render(hits, keyword, scanned)

    if hits and input("  export? [y/N] >> ").strip().lower() == "y":
        _export(keyword, hits, scanned)
