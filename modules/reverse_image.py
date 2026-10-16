"""
reverse_image.py — Reverse image search and hash forensics.

Given a file or URL:
  · computes md5 / sha1 / sha256
  · computes perceptual hashes (aHash, dHash, pHash) if imagehash installed
  · extracts a broad EXIF summary (camera, software, GPS with lat/lon)
  · generates reverse-search URLs for 22 engines
  · optionally uploads to a temp public host (multi-host fallback chain)
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
OUT_DIR = Path.home() / ".doxtoolkit" / "exports"
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
        wanted = {
            "Make", "Model", "Software", "DateTime", "DateTimeOriginal",
            "DateTimeDigitized", "Orientation", "LensModel",
            "LensMake", "LensSerialNumber",
            "Artist", "Copyright", "ImageDescription", "HostComputer",
            "XPTitle", "XPComment", "XPAuthor", "XPKeywords", "XPSubject",
            "BodySerialNumber", "CameraOwnerName",
            "ExposureTime", "FNumber", "ISOSpeedRatings",
            "FocalLength", "FocalLengthIn35mmFilm",
            "Flash", "WhiteBalance", "ExposureProgram", "MeteringMode",
            "ExifVersion", "UserComment",
        }
        out = {}
        for tid, val in exif.items():
            name = TAGS.get(tid, tid)
            if name in wanted:
                out[name] = str(val)

        # nested IFD blocks: Exif, GPS, Interop
        try:
            for ifd_name in ("Exif", "GPS", "Interop"):
                ifd = exif.get_ifd(ifd_name) or {}
                for tid, val in ifd.items():
                    name = TAGS.get(tid, tid)
                    if name in wanted:
                        out[name] = str(val)
        except Exception:
            pass

        # GPS presence + signed lat/lon + maps link
        gps = {}
        try:
            gps = exif.get_ifd("GPS") or {}
        except Exception:
            gps = {}
        out["has_gps"] = bool(gps)
        if gps:
            def _rat(v):
                try:
                    return float(v)
                except Exception:
                    try:
                        return v[0] / v[1]
                    except Exception:
                        return None

            lat = gps.get(2)
            lon = gps.get(4)
            lat_ref = gps.get(1, "N")
            lon_ref = gps.get(3, "E")
            if lat and lon:
                lat_d = _rat(lat[0]) if isinstance(lat, tuple) else _rat(lat)
                lat_m = _rat(lat[1]) if isinstance(lat, tuple) and len(lat) > 1 else 0
                lat_s = _rat(lat[2]) if isinstance(lat, tuple) and len(lat) > 2 else 0
                lon_d = _rat(lon[0]) if isinstance(lon, tuple) else _rat(lon)
                lon_m = _rat(lon[1]) if isinstance(lon, tuple) and len(lon) > 1 else 0
                lon_s = _rat(lon[2]) if isinstance(lon, tuple) and len(lon) > 2 else 0
                if None not in (lat_d, lon_d):
                    lat_f = lat_d + (lat_m or 0) / 60 + (lat_s or 0) / 3600
                    lon_f = lon_d + (lon_m or 0) / 60 + (lon_s or 0) / 3600
                    if str(lat_ref).upper().startswith("S"):
                        lat_f = -lat_f
                    if str(lon_ref).upper().startswith("W"):
                        lon_f = -lon_f
                    out["gps_lat"] = f"{lat_f:.6f}"
                    out["gps_lon"] = f"{lon_f:.6f}"
                    out["gps_maps"] = (
                        f"https://www.google.com/maps?q={lat_f:.6f},{lon_f:.6f}"
                    )
        return out
    except Exception:
        return None


# ───────────────────────── search engines ─────────────────────────

def build_search_urls(public_url: str):
    q = quote(public_url, safe="")
    return [
        ("Google Lens",
         f"https://lens.google.com/uploadbyurl?url={q}"),
        ("Google Lens Mobile",
         f"https://lens.google.com/v3/upload?stcs=&url={q}"),
        ("Google Images",
         f"https://www.google.com/searchbyimage?image_url={q}"),
        ("Yandex",
         f"https://yandex.com/images/search?rpt=imageview&url={q}"),
        ("Yandex Collections",
         f"https://yandex.com/images/search?rpt=imageview&url={q}"
         f"&source=collections"),
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
        ("Pinterest Visual Search",
         f"https://www.pinterest.com/search/visual/?imageUrl={q}"),
        ("Shutterstock Image Search",
         f"https://www.shutterstock.com/search?image_url={q}"),
        ("Alibaba Image Search",
         f"https://s.taobao.com/search?imgfile=&js=1&stats_click=1"
         f"&search_type=image&imgtype=all&av=all&wb=all&q="
         f"&image_url={q}"),
        ("Getty Images Search",
         f"https://www.gettyimages.com/search/2/image"
         f"?phrase=visual-search&asset-url={q}"),
        ("Getty Images Visual",
         f"https://www.gettyimages.com/search/photographer"
         f"?family=editorial&asseturl={q}"),
        ("Social Catfish",
         f"https://socialcatfish.com/reverse-image-search/?image_url={q}"),
    ]


# ───────────────────────── uploaders ─────────────────────────

def _upload_0x0(path: Path):
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
        t = r.text.strip()
        if r.status_code == 200 and t.startswith("http"):
            return t
    except Exception:
        pass
    return None


def _upload_catbox(path: Path):
    try:
        with path.open("rb") as fh:
            r = requests.post(
                "https://catbox.moe/user/api.php",
                data={"reqtype": "fileupload"},
                files={"fileToUpload": (path.name, fh,
                                        "application/octet-stream")},
                headers={"User-Agent": UA},
                timeout=45,
            )
        t = r.text.strip()
        if r.status_code == 200 and t.startswith("http"):
            return t
    except Exception:
        pass
    return None


def _upload_litterbox(path: Path, hours: int = 72):
    try:
        with path.open("rb") as fh:
            r = requests.post(
                "https://litterbox.catbox.moe/resources/internals/api.php",
                data={"reqtype": "fileupload", "time": f"{hours}h"},
                files={"fileToUpload": (path.name, fh,
                                        "application/octet-stream")},
                headers={"User-Agent": UA},
                timeout=45,
            )
        t = r.text.strip()
        if r.status_code == 200 and t.startswith("http"):
            return t
    except Exception:
        pass
    return None


def _upload_uguu(path: Path):
    try:
        with path.open("rb") as fh:
            r = requests.post(
                "https://uguu.se/upload.php",
                files={"files[]": (path.name, fh,
                                   "application/octet-stream")},
                headers={"User-Agent": UA},
                timeout=45,
            )
        j = r.json()
        if r.status_code == 200 and j.get("success") and j.get("files"):
            return j["files"][0].get("url")
    except Exception:
        pass
    return None


def _upload_tmpfiles(path: Path):
    try:
        with path.open("rb") as fh:
            r = requests.post(
                "https://tmpfiles.org/api/v1/upload",
                files={"file": (path.name, fh,
                                "application/octet-stream")},
                headers={"User-Agent": UA},
                timeout=45,
            )
        j = r.json()
        u = (j.get("data") or {}).get("url")
        if u and "tmpfiles.org/" in u:
            return u.replace("tmpfiles.org/", "tmpfiles.org/dl/")
    except Exception:
        pass
    return None


UPLOADERS = (
    ("0x0.st", _upload_0x0),
    ("catbox.moe", _upload_catbox),
    ("litterbox.catbox.moe", _upload_litterbox),
    ("uguu.se", _upload_uguu),
    ("tmpfiles.org", _upload_tmpfiles),
)


def _upload_temp(path: Path):
    """Try uploaders in order. First live URL wins. Returns (host, url) or (None, None)."""
    for name, fn in UPLOADERS:
        with console.status(f"[dg]uploading via {name}...[/dg]",
                            spinner="dots"):
            url = fn(path)
        if url:
            return name, url
    return None, None


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

        if input("  upload to temp host for search URLs? "
                 "[y/N] >> ").strip().lower() == "y":
            host, public_url = _upload_temp(path)
            if public_url:
                console.print(f"[dg]  host:[/dg] [g]{host}[/g]")
            else:
                console.print("[dg]  all hosts failed[/dg]")

    urls = build_search_urls(public_url) if public_url else []

    _render(source, hashes, phashes, exif, urls, public_url)

    if input("  export? [y/N] >> ").strip().lower() == "y":
        _export(source, hashes, phashes, exif, urls, public_url)
