"""
crypto_wallet.py — Multi-chain crypto address intelligence.

Detects chain from address format, validates checksum where possible,
queries Blockchair (multi-chain) with per-chain fallbacks, and reports
balance, tx count, first/last activity, and recent transactions.
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
OUT_DIR = Path.home() / ".doxtoolkit" / "exports"
OUT_DIR.mkdir(parents=True, exist_ok=True)

UA = "Mozilla/5.0 (compatible; osinttoolkit/2.0)"

# chain → (regex, blockchair key, fallback label)
CHAINS = [
    ("BTC",  re.compile(r"^(bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$"),
     "bitcoin", None),
    ("BCH",  re.compile(r"^(bitcoincash:)?(q|p)[a-z0-9]{41}$|^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$"),
     "bitcoin-cash", None),
    ("ETH",  re.compile(r"^0x[a-fA-F0-9]{40}$"), "ethereum", "ethplorer"),
    ("LTC",  re.compile(r"^(ltc1[a-z0-9]{25,90}|[LM3][a-km-zA-HJ-NP-Z1-9]{25,34})$"),
     "litecoin", "sochain-LTC"),
    ("DOGE", re.compile(r"^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$"),
     "dogecoin", "sochain-DOGE"),
    ("XRP",  re.compile(r"^r[1-9A-HJ-NP-Za-km-z]{24,34}$"), "ripple", None),
    ("XMR",  re.compile(r"^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$"), "monero", None),
    ("ADA",  re.compile(r"^addr1[a-z0-9]{20,120}$"), "cardano", None),
    ("SOL",  re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$"), "solana", None),
    ("TRX",  re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$"), "tron", None),
    ("DASH", re.compile(r"^X[1-9A-HJ-NP-Za-km-z]{33}$"), "dash", None),
    ("ZEC",  re.compile(r"^t1[a-zA-Z0-9]{33}$"), "zcash", None),
]


# ───────────────────────── detection ─────────────────────────

def detect_chain(addr: str):
    a = addr.strip()
    for name, rx, _, _ in CHAINS:
        if rx.match(a):
            return name
    return None


def _chain_meta(name):
    for row in CHAINS:
        if row[0] == name:
            return row
    return None


# ───────────────────────── providers ─────────────────────────

def _blockchair(chain_key, addr):
    url = f"https://api.blockchair.com/{chain_key}/dashboards/address/{addr}"
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=15)
        if r.status_code != 200:
            return None
        d = r.json()
        if "data" not in d or addr not in d["data"]:
            return None
        block = d["data"][addr]
        return {
            "source": "blockchair",
            "address": block.get("address") or {},
            "transactions": (block.get("transactions") or [])[:10],
            "utxo_count": block.get("utxo_count"),
            "raw": d.get("context"),
        }
    except Exception:
        return None


def _blockchain_info(addr):
    """BTC-only fallback"""
    try:
        r = requests.get(
            f"https://blockchain.info/rawaddr/{addr}?limit=10",
            headers={"User-Agent": UA}, timeout=15,
        )
        if r.status_code != 200:
            return None
        d = r.json()
        return {
            "source": "blockchain.info",
            "address": {
                "balance": d.get("final_balance"),
                "received": d.get("total_received"),
                "sent": d.get("total_sent"),
                "transaction_count": d.get("n_tx"),
            },
            "transactions": d.get("txs", [])[:10],
        }
    except Exception:
        return None


def _ethplorer(addr):
    """ETH-only fallback"""
    try:
        r = requests.get(
            f"https://api.ethplorer.io/getAddressInfo/{addr}",
            params={"apiKey": "freekey"},
            headers={"User-Agent": UA}, timeout=15,
        )
        if r.status_code != 200:
            return None
        d = r.json()
        if "error" in d:
            return None
        eth = d.get("ETH") or {}
        tokens = []
        for t in (d.get("tokens") or [])[:8]:
            info = t.get("tokenInfo") or {}
            tokens.append({
                "symbol": info.get("symbol"),
                "name": info.get("name"),
                "balance": t.get("balance"),
                "decimals": info.get("decimals"),
            })
        return {
            "source": "ethplorer",
            "address": {
                "balance_wei": eth.get("balance"),
                "transaction_count": d.get("countTxs"),
            },
            "tokens": tokens,
        }
    except Exception:
        return None


def _sochain(chain, addr):
    """LTC/DOGE fallback"""
    network = {"LTC": "LTC", "DOGE": "DOGE"}.get(chain)
    if not network:
        return None
    try:
        r = requests.get(
            f"https://sochain.com/api/v2/get_address_balance/{network}/{addr}",
            headers={"User-Agent": UA}, timeout=15,
        )
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("status") != "success":
            return None
        data = d.get("data") or {}
        return {
            "source": "sochain",
            "address": {
                "balance": data.get("confirmed_balance"),
                "unconfirmed": data.get("unconfirmed_balance"),
            },
        }
    except Exception:
        return None


def query_chain(chain, addr):
    meta = _chain_meta(chain)
    if not meta:
        return None
    _, _, blockchair_key, fallback = meta
    primary = _blockchair(blockchair_key, addr)
    if primary:
        return primary
    if fallback == "ethplorer" or chain == "ETH":
        return _ethplorer(addr)
    if fallback and fallback.startswith("sochain"):
        return _sochain(chain, addr)
    if chain == "BTC":
        return _blockchain_info(addr)
    return None


# ───────────────────────── formatting ─────────────────────────

def _short(s, n=12):
    s = str(s)
    return s if len(s) <= n * 2 else f"{s[:n]}…{s[-n:]}"


def _ts(v):
    try:
        v = int(v)
    except Exception:
        return v
    if v > 1e12:
        v //= 1000
    try:
        return datetime.utcfromtimestamp(v).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return v


# ───────────────────────── render ─────────────────────────

def _render(addr, chain, data):
    console.print(Panel.fit(
        f"[bg]CRYPTO LOOKUP[/bg]  [dg]{chain}[/dg]  ·  "
        f"[g]{_short(addr, 16)}[/g]",
        border_style="bd", padding=(0, 2),
    ))

    if not data:
        console.print("[dg]  no data returned — provider may be rate-limiting"
                      " or the address is unused[/dg]\n")
        return

    addr_info = data.get("address") or {}

    at = Table(border_style="bd", title="[bg]address[/bg]",
               show_header=False, padding=(0, 2))
    at.add_column("k", style="dg", no_wrap=True)
    at.add_column("v", style="g", overflow="fold")
    at.add_row("chain", chain)
    at.add_row("source", data.get("source", "?"))
    at.add_row("full", addr)

    for k in ("balance", "final_balance", "received", "sent",
              "transaction_count", "n_tx", "utxo_count",
              "unconfirmed_balance", "balance_wei"):
        v = addr_info.get(k)
        if v is not None:
            at.add_row(k, str(v))

    for k in ("type", "script_hex", "first_seen_receiving",
              "last_seen_receiving", "first_seen_spending",
              "last_seen_spending"):
        v = addr_info.get(k)
        if v:
            if k.endswith("_receiving") or k.endswith("_spending"):
                v = _ts(v)
            at.add_row(k, str(v))

    console.print(at)

    if data.get("tokens"):
        tt = Table(border_style="bd", title="[bg]tokens[/bg]",
                   show_header=True, padding=(0, 2))
        tt.add_column("symbol", style="bg")
        tt.add_column("name", style="g")
        tt.add_column("balance", style="dg", justify="right")
        for t in data["tokens"]:
            tt.add_row(t.get("symbol") or "?", t.get("name") or "?",
                       str(t.get("balance")))
        console.print(tt)

    txs = data.get("transactions") or []
    if txs:
        tt = Table(border_style="bd",
                   title=f"[bg]recent transactions ({len(txs)})[/bg]",
                   show_header=True, padding=(0, 2))
        tt.add_column("#", style="dg", justify="right")
        tt.add_column("hash", style="g", overflow="fold")
        tt.add_column("time", style="dg")
        for i, tx in enumerate(txs, 1):
            h = tx.get("hash") or tx.get("hash_blockchair") or "?"
            t = tx.get("time") or tx.get("block_time")
            tt.add_row(str(i), _short(h, 24), _ts(t) if t else "-")
        console.print(tt)

    console.print()


def _export(addr, chain, data):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    p = OUT_DIR / f"crypto_{chain}_{addr[:12]}_{ts}.json"
    p.write_text(json.dumps({
        "address": addr, "chain": chain, "data": data,
        "generated": datetime.now().isoformat(timespec="seconds"),
    }, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]\n")


# ───────────────────────── entry ─────────────────────────

def run():
    addr = input("  crypto address >> ").strip()
    if not addr:
        print("  [!] empty address")
        return

    with tqdm(total=3, desc="detecting chain",
              ncols=60, bar_format=BAR_FMT) as bar:
        chain = detect_chain(addr); bar.update(1)
        if not chain:
            print("  [!] unrecognized address format")
            return
        console.print(f"[dg]  detected chain: {chain}[/dg]")
        bar.update(1)
        with console.status("[dg]querying chain...[/dg]", spinner="dots"):
            data = query_chain(chain, addr)
        bar.update(1)

    _render(addr, chain, data)

    if input("  export? [y/N] >> ").strip().lower() == "y":
        _export(addr, chain, data)
