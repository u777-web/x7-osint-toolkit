"""
reverse_image.py — Reverse image search and hash forensics.

Given a file or URL:
  · computes md5 / sha1 / sha256
  · computes perceptual hashes (aHash, dHash, pHash) if imagehash installed
  · extracts a short EXIF summary (camera, software, GPS presence)
  · generates reverse-search URLs for 14 engines
  · optionally uploads to a temporary public host (0x0.st) for engines
    that need a public URL
  · exports everything to json
"""

import hashlib
import json
import mimetypes
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

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

UA = "Mozilla/5.0 (compatible; doxtoolkit/2.0)"

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import imagehash
    HAS_PHASH = True
except ImportError:
    HAS_PHASH = False


# ───────────────────────── hashing ─────────────────────────

def hash_file(path: Path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            size += len(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size_bytes": size,
    }


def perceptual_hashes(path: Path):
    if not HAS_PHASH:
        return None
    try:
        img = Image.open(path).convert("RGB")
        return {
            "ahash": str(imagehash.average_hash(img)),
            "dhash": str(imagehash.dhash(img)),
            "phash": str(imagehash.phash(img)),
            "whash": str(imagehash.whash(img)),
        }
    except Exception:
        return None


# ───────────────────────── exif summary ─────────────────────────

def exif_summary(path: Path):
    if not HAS_PIL:
        return None
    try:
        img = Image.open(path)
        exif = img.getexif() or {}
        out = {}
        for tid, val in exif.items():
            name = TAGS.get(tid, tid)
            if name in ("Make", "Model", "Software", "DateTime",
                        "DateTimeOriginal", "Orientation", "LensModel"):
                out[name] = str(val)
        has_gps = any(TAGS.get(k, k) == "GPSInfo" for k in exif.keys())
        out["has_gps"] = has_gps
        return out
    except Exception:
        return None


# ───────────────────────── search engines ─────────────────────────

def build_search_urls(public_url: str):
    q = quote(public_url, safe="")
    return [
        ("Google Lens",
         f"https://lens.google.com/uploadbyurl?url={q}"),
        ("Google Images",
         f"https://www.google.com/searchbyimage?image_url={q}"),
        ("Yandex",
         f"https://yandex.com/images/search?rpt=imageview&url={q}"),
        ("Bing Visual",
         f"https://www.bing.com/images/search?view=detailv2"
         f"&iss=sbi&form=SBIVSP&sbisrc=UrlPaste&q=imgurl:{q}"),
        ("TinEye",
         f"https://tineye.com/search?url={q}"),
        ("SauceNAO",
         f"https://saucenao.com/search.php?url={q}"),
        ("IQDB (anime)",
         f"https://iqdb.org/?url={q}"),
        ("ASCII2D",
         f"https://ascii2d.net/search/url/{q}"),
        ("Karma Decay (reddit)",
         f"http://karmadecay.com/search/?q={q}"),
        ("Baidu Image",
         f"https://graph.baidu.com/upload?image={q}"),
        ("Search by image (misc)",
         f"https://searchbyimage.appspot.com/search?url={q}"),
        ("PimEyes (face)",
         f"https://pimeyes.com/en/search?image_url={q}"),
        ("FaceCheck.id",
         f"https://facecheck.id/search?image_url={q}"),
        ("Lenso.ai",
         f"https://lenso.ai/search?image_url={q}"),
    ]


def _upload_temp(path: Path):
    """upload to 0x0.st — returns public URL or None"""
    try:
        with path.open("rb") as fh:
            r = requests.post(
                "https://0x0.st",
                files={"file": (path.name, fh,
                                mimetypes.guess_type(path.name)[0]
                                or "application/octet-stream")},
                headers={"User-Agent": UA},
                timeout=30,
            )
        if r.status_code == 200 and r.text.strip().startswith("http"):
            return r.text.strip()
    except Exception:
        pass
    return None


# ───────────────────────── render ─────────────────────────

def _render(source, hashes, phashes, exif, urls, uploaded):
    console.print(Panel.fit(
        f"[bg]REVERSE IMAGE[/bg]  [dg]{source[:64]}[/dg]",
        border_style="bd", padding=(0, 2),
    ))

    ht = Table(border_style="bd", title="[bg]hashes[/bg]",
               show_header=False, padding=(0, 2))
    ht.add_column("k", style="dg", no_wrap=True)
    ht.add_column("v", style="g", overflow="fold")
    for k, v in hashes.items():
        ht.add_row(k, str(v))
    console.print(ht)

    if phashes:
        pt = Table(border_style="bd",
                   title="[bg]perceptual hashes[/bg]",
                   show_header=False, padding=(0, 2))
        pt.add_column("k", style="dg", no_wrap=True)
        pt.add_column("v", style="g")
        for k, v in phashes.items():
            pt.add_row(k, v)
        console.print(pt)

    if exif:
        et = Table(border_style="bd", title="[bg]exif summary[/bg]",
                   show_header=False, padding=(0, 2))
        et.add_column("k", style="dg", no_wrap=True)
        et.add_column("v", style="g", overflow="fold")
        for k, v in exif.items():
            et.add_row(k, str(v))
        console.print(et)

    if uploaded:
        console.print(f"[dg]  temp public url:[/dg] [g]{uploaded}[/g]")

    if urls:
        st = Table(border_style="bd",
                   title="[bg]reverse-search engines[/bg]",
                   show_header=True, padding=(0, 2))
        st.add_column("engine", style="bg")
        st.add_column("url", style="g", overflow="fold")
        for name, url in urls:
            st.add_row(name, url)
        console.print(st)
    else:
        console.print("[dg]  no search URLs — provide a public URL or "
                      "allow temp upload[/dg]")

    console.print()


def _export(source, hashes, phashes, exif, urls, uploaded):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(source).name)[:40] or "img"
    p = OUT_DIR / f"img_{safe}_{ts}.json"
    p.write_text(json.dumps({
        "source": source,
        "hashes": hashes,
        "perceptual": phashes,
        "exif": exif,
        "temp_url": uploaded,
        "search_urls": [{"engine": n, "url": u} for n, u in urls],
        "generated": datetime.now().isoformat(timespec="seconds"),
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]\n")


# ───────────────────────── entry ─────────────────────────

def run():
    raw = input("  image path or public url >> ").strip().strip('"')
    if not raw:
        print("  [!] empty input")
        return

    is_url = raw.lower().startswith(("http://", "https://"))
    hashes = {}
    phashes = None
    exif = None
    public_url = None

    if is_url:
        public_url = raw
        with tqdm(total=3, desc="hashing url", ncols=60,
                  bar_format=BAR_FMT) as bar:
            try:
                r = requests.get(raw, headers={"User-Agent": UA},
                                 timeout=20, stream=True)
                md5 = hashlib.md5()
                sha1 = hashlib.sha1()
                sha256 = hashlib.sha256()
                size = 0
                for chunk in r.iter_content(1 << 20):
                    md5.update(chunk); sha1.update(chunk)
                    sha256.update(chunk); size += len(chunk)
                hashes = {"md5": md5.hexdigest(),
                          "sha1": sha1.hexdigest(),
                          "sha256": sha256.hexdigest(),
                          "size_bytes": size}
            except Exception as e:
                print(f"  [!] fetch failed: {e}")
                return
            bar.update(1)
            bar.update(2)
        source = raw
    else:
        path = Path(raw).expanduser()
        if not path.exists() or not path.is_file():
            print("  [!] file not found")
            return
        with tqdm(total=4, desc="hashing file", ncols=60,
                  bar_format=BAR_FMT) as bar:
            hashes = hash_file(path); bar.update(1)
            phashes = perceptual_hashes(path); bar.update(1)
            exif = exif_summary(path); bar.update(1)
            bar.update(1)
        source = str(path)

        if input("  upload to temp host (0x0.st) for search URLs? "
                 "[y/N] >> ").strip().lower() == "y":
            with console.status("[dg]uploading...[/dg]", spinner="dots"):
                public_url = _upload_temp(path)

    urls = build_search_urls(public_url) if public_url else []

    _render(source, hashes, phashes, exif, urls, public_url)

    if input("  export? [y/N] >> ").strip().lower() == "y":
        _export(source, hashes, phashes, exif, urls, public_url)
