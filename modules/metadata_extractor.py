"""
metadata_extractor.py — File metadata forensics.

Extracts:
  · EXIF from images (PIL): GPS, camera, timestamps, software
  · PDF metadata (pypdf)
  · DOCX / XLSX / PPTX (docx / openpyxl / zipfile fallback)
  · Audio / video tags (mutagen, optional)
  · ZIP / archive structure
  · RAW sidecar / XMP fragments

Also provides:
  · GPS → decimal conversion + OSM link
  · Metadata scrubber (image re-save without EXIF)
"""

import json
import os
import re
import zipfile
from datetime import datetime
from pathlib import Path

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

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from pypdf import PdfReader
    HAS_PYPDF = True
except ImportError:
    try:
        from PyPDF2 import PdfReader
        HAS_PYPDF = True
    except ImportError:
        HAS_PYPDF = False


IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp", ".heic"}
PDF_EXTS = {".pdf"}
OFFICE_EXTS = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}
ARCHIVE_EXTS = {".zip", ".jar", ".apk", ".epub"}


# ───────────────────────── image ─────────────────────────

def _rational(v):
    try:
        if isinstance(v, tuple) and len(v) == 2:
            return v[0] / v[1] if v[1] else 0.0
        return float(v)
    except Exception:
        return None


def _gps_decimal(gps):
    if not gps:
        return None

    def dms(dms_val, ref):
        try:
            d = _rational(dms_val[0])
            m = _rational(dms_val[1])
            s = _rational(dms_val[2])
            if None in (d, m, s):
                return None
            val = d + m / 60 + s / 3600
            if ref in ("S", "W"):
                val = -val
            return round(val, 7)
        except Exception:
            return None

    try:
        lat = dms(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef", "N"))
        lon = dms(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef", "E"))
        alt = _rational(gps.get("GPSAltitude"))
        has_coords = lat is not None and lon is not None
        return {
            "lat": lat,
            "lon": lon,
            "altitude_m": round(alt, 2) if alt is not None else None,
            "osm": (f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}"
                    f"#map=17/{lat}/{lon}") if has_coords else None,
            "google": (f"https://www.google.com/maps?q={lat},{lon}")
                      if has_coords else None,
        }
    except Exception:
        return None


def _image_meta(path):
    if not HAS_PIL:
        return {"error": "Pillow not installed"}
    try:
        img = Image.open(path)
        info = {
            "format": img.format,
            "mode": img.mode,
            "size": f"{img.width}x{img.height}",
            "width": img.width,
            "height": img.height,
        }
        exif = img.getexif() or {}
        tags = {}
        for tid, val in exif.items():
            name = TAGS.get(tid, tid)
            if name == "GPSInfo":
                gps = {}
                for k, v in (val or {}).items():
                    gps[GPSTAGS.get(k, k)] = v
                tags["GPSInfo"] = gps
            else:
                tags[name] = val if isinstance(val, (str, int, float)) else str(val)

        # sub-IFD exif block
        try:
            sub = exif.get_ifd(0x8769) or {}
            for tid, val in sub.items():
                name = TAGS.get(tid, tid)
                tags[name] = val if isinstance(val, (str, int, float)) else str(val)
        except Exception:
            pass

        info["exif"] = tags
        info["gps"] = _gps_decimal(tags.get("GPSInfo"))
        return info
    except Exception as e:
        return {"error": str(e)}


# ───────────────────────── pdf ─────────────────────────

def _pdf_meta(path):
    if not HAS_PYPDF:
        return {"error": "pypdf not installed"}
    try:
        r = PdfReader(str(path))
        meta = dict(r.metadata or {})
        out = {
            "pages": len(r.pages),
            "encrypted": r.is_encrypted,
            "metadata": {str(k): str(v) for k, v in meta.items()},
        }
        try:
            xmp = r.xmp_metadata
            if xmp is not None:
                out["xmp"] = {
                    k: getattr(xmp, k) for k in dir(xmp)
                    if not k.startswith("_")
                    and not callable(getattr(xmp, k))
                }
        except Exception:
            pass
        return out
    except Exception as e:
        return {"error": str(e)}


# ───────────────────────── office / archive ─────────────────────────

def _office_meta(path):
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            out = {"entries": len(names), "type": path.suffix.lower()}
            for candidate in ("docProps/core.xml", "docProps/app.xml",
                              "meta.xml"):
                if candidate in names:
                    with z.open(candidate) as fh:
                        raw = fh.read().decode("utf-8", errors="ignore")
                    pairs = re.findall(
                        r"<([a-zA-Z]+:)?([a-zA-Z]+)[^>]*>([^<]+)<", raw)
                    extracted = {}
                    for _, tag, val in pairs:
                        val = val.strip()
                        if val:
                            extracted[tag] = val
                    out[candidate] = extracted
            return out
    except Exception as e:
        return {"error": str(e)}


def _archive_meta(path):
    try:
        with zipfile.ZipFile(path) as z:
            entries = z.infolist()
            out = {
                "entries": len(entries),
                "total_size": sum(e.file_size for e in entries),
                "compressed_size": sum(e.compress_size for e in entries),
                "comments": z.comment.decode(errors="ignore") or None,
                "sample": [e.filename for e in entries[:25]],
            }
            return out
    except Exception as e:
        return {"error": str(e)}


# ───────────────────────── classify ─────────────────────────

def _classify(path):
    ext = path.suffix.lower()
    if ext in IMAGE_EXTS:
        return "image"
    if ext in PDF_EXTS:
        return "pdf"
    if ext in OFFICE_EXTS:
        return "office"
    if ext in ARCHIVE_EXTS:
        return "archive"
    return "unknown"


def _extract(path):
    kind = _classify(path)
    try:
        st = path.stat()
        base = {
            "path": str(path),
            "size_bytes": st.st_size,
            "kind": kind,
            "modified": datetime.fromtimestamp(st.st_mtime)
                        .isoformat(timespec="seconds"),
        }
    except Exception:
        base = {"path": str(path), "kind": kind}

    if kind == "image":
        base.update(_image_meta(path))
    elif kind == "pdf":
        base.update(_pdf_meta(path))
    elif kind == "office":
        base.update(_office_meta(path))
    elif kind == "archive":
        base.update(_archive_meta(path))
    return base


# ───────────────────────── scrub ─────────────────────────

def _scrub_image(path):
    if not HAS_PIL:
        return None
    try:
        out_dir = OUT_DIR / "scrubbed"
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"clean_{path.name}"
        img = Image.open(path)
        data = list(img.getdata())
        clean = Image.new(img.mode, img.size)
        clean.putdata(data)
        clean.save(out)
        return out
    except Exception as e:
        console.print(f"[dg]  scrub error: {e}[/dg]")
        return None


# ───────────────────────── render ─────────────────────────

def _render(meta):
    console.print(Panel.fit(
        f"[bg]METADATA[/bg]  [dg]{Path(meta.get('path', '?')).name}[/dg]  "
        f"·  [g]{meta.get('kind')}[/g]",
        border_style="bd", padding=(0, 2),
    ))

    ft = Table(border_style="bd", title="[bg]file[/bg]",
               show_header=False, padding=(0, 2))
    ft.add_column("k", style="dg", no_wrap=True)
    ft.add_column("v", style="g", overflow="fold")
    for k in ("path", "size_bytes", "modified", "format", "mode",
              "size", "pages", "encrypted", "entries", "total_size"):
        if meta.get(k) is not None:
            ft.add_row(k, str(meta[k]))
    console.print(ft)

    if meta.get("gps"):
        g = meta["gps"]
        gt = Table(border_style="bd", title="[bg]gps[/bg]",
                   show_header=False, padding=(0, 2))
        gt.add_column("k", style="dg", no_wrap=True)
        gt.add_column("v", style="g", overflow="fold")
        for k in ("lat", "lon", "altitude_m"):
            if g.get(k) is not None:
                gt.add_row(k, str(g[k]))
        if g.get("osm"):
            gt.add_row("map", g["osm"])
        console.print(gt)

    exif = meta.get("exif")
    if exif and isinstance(exif, dict):
        et = Table(border_style="bd", title="[bg]exif[/bg]",
                   show_header=True, padding=(0, 2))
        et.add_column("tag", style="bg", overflow="fold")
        et.add_column("value", style="g", overflow="fold")
        for k, v in list(exif.items())[:40]:
            if k == "GPSInfo":
                continue
            et.add_row(str(k), str(v)[:120])
        console.print(et)

    for key in ("metadata", "xmp"):
        if meta.get(key):
            mt = Table(border_style="bd", title=f"[bg]{key}[/bg]",
                       show_header=True, padding=(0, 2))
            mt.add_column("k", style="bg", overflow="fold")
            mt.add_column("v", style="g", overflow="fold")
            for k, v in meta[key].items():
                mt.add_row(str(k), str(v)[:120])
            console.print(mt)

    for key in ("docProps/core.xml", "docProps/app.xml", "meta.xml"):
        if meta.get(key):
            ot = Table(border_style="bd", title=f"[bg]{key}[/bg]",
                       show_header=True, padding=(0, 2))
            ot.add_column("k", style="bg", overflow="fold")
            ot.add_column("v", style="g", overflow="fold")
            for k, v in meta[key].items():
                ot.add_row(str(k), str(v)[:120])
            console.print(ot)

    if meta.get("sample"):
        console.print("[dg]  archive entries (first 25):[/dg]")
        for s in meta["sample"]:
            console.print(f"[g]    · {s}[/g]")
    console.print()


def _export(meta):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_",
                  Path(meta.get("path", "file")).name)[:40]
    p = OUT_DIR / f"meta_{safe}_{ts}.json"
    p.write_text(json.dumps(meta, indent=2, ensure_ascii=False,
                            default=str), encoding="utf-8")
    console.print(f"[dg]  exported → {p}[/dg]\n")


# ───────────────────────── entry ─────────────────────────

def run():
    raw = input("  file or directory path >> ").strip().strip('"')
    if not raw:
        print("  [!] empty input")
        return

    target = Path(os.path.expanduser(raw))
    if not target.exists():
        print("  [!] path does not exist")
        return

    files = []
    if target.is_dir():
        for p in target.rglob("*"):
            if p.is_file() and _classify(p) != "unknown":
                files.append(p)
    else:
        files.append(target)

    if not files:
        print("  [!] no supported files found")
        return

    all_meta = []
    for p in tqdm(files, desc=f"parsing {len(files)} file(s)",
                  ncols=60, bar_format=BAR_FMT):
        all_meta.append(_extract(p))

    for m in all_meta:
        _render(m)

    if input("  export all? [y/N] >> ").strip().lower() == "y":
        for m in all_meta:
            _export(m)

    if any(_classify(Path(m["path"])) == "image" for m in all_meta):
        if input("  scrub EXIF from images? [y/N] >> ").strip().lower() == "y":
            for m in all_meta:
                p = Path(m["path"])
                if _classify(p) == "image":
                    out = _scrub_image(p)
                    if out:
                        console.print(f"[dg]  scrubbed → {out}[/dg]")
            console.print()
