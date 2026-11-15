# -*- coding: utf-8 -*-
"""ماژولِ دقیق‌کاوی (Forensics) برای چشمِ EXIF — تامبنیل مخفی، اثرِ انگشتِ JPEG، MakerNotes، دیتایِ بعدِ EOI"""
import io, os, json, subprocess, base64, tempfile
from PIL import Image

# ---------- اثرِ انگشتِ جدولِ کوانتیزاسیون ----------
# دیتابیسِ الگوهایِ معروف (luma quant table سازنده‌هایِ شاخص — خلاصه‌شده)
QT_SIGNATURES = [
    {"name": "Apple iPhone / iPad", "sig": [8,6,5,8,12,20,26,31], "note": "فشرده‌سازیِ استانداردِ iOS"},
    {"name": "Samsung Galaxy", "sig": [8,8,8,9,12,14,18,24], "note": "پردازشگرِ تصویرِ سامسونگ"},
    {"name": "Google Pixel", "sig": [8,6,6,8,10,12,16,20], "note": "پردازشگرِ تصویرِ گوگل"},
    {"name": "Adobe Photoshop (save q~80)", "sig": [8,6,5,8,12,20,26,35], "note": "بعد از ذخیره در فتوشاپ"},
    {"name": "Telegram / WhatsApp re-encode", "sig": [2,1,1,2,2,4,6,7], "note": "فشرده‌سازیِ مجازیِ پیام‌رسان‌ها"},
    {"name": "JPEG standard (quality 50)", "sig": [16,11,10,16,24,40,51,61], "note": "کیفیتِ پایینِ ۵۰٪"},
    {"name": "Xiaomi / MIUI", "sig": [3,2,2,3,5,8,10,12], "note": "پردازشگرِ شیائومی"},
]

def jpeg_quant_fingerprint(data: bytes):
    """استخراجِ جدولِ کوانتیزاسیون از سگمنتِ DQT"""
    i = 2  # skip SOI
    tables = []
    while i < len(data) - 9:
        if data[i] != 0xFF: break
        marker = data[i+1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2; continue
        if marker == 0xD9: break
        length = int.from_bytes(data[i+2:i+4], "big")
        if marker == 0xDB:  # DQT
            p = i + 4
            while p < i + 2 + length:
                pq = data[p] >> 4
                tq = data[p] & 0x0F
                p += 1
                n = 64 * (2 if pq else 1)
                vals = list(data[p:p+n]) if pq == 0 else [int.from_bytes(data[p+k*2:p+k*2+2],"big") for k in range(64)]
                p += n
                tables.append({"id": tq, "first8": vals[:8], "full": vals})
        if marker == 0xDA: break  # SOS — داده‌ی تصویر شروع شد
        i += 2 + length
    # تطبیق با دیتابیس
    matches = []
    for t in tables:
        for s in QT_SIGNATURES:
            if t["first8"] == s["sig"]:
                matches.append(s["name"] + " — " + s["note"])
    return {"tables": [{"id": t["id"], "first8": t["first8"]} for t in tables],
            "matches": matches,
            "gen_hint": f"تعدادِ جدول‌ها: {len(tables)} — هر ذخیرهٔ مجدد معمولاً جدولِ تازه‌ای می‌نویسد"}

# ---------- دیتایِ پنهانِ بعد از EOI ----------
def after_eoi(data: bytes):
    idx = data.find(b"\xff\xd9")
    hidden = None
    if idx != -1 and idx + 2 < len(data):
        extra = data[idx+2:]
        preview = extra[:3000]
        # آیا تصویر است؟
        kind = "دادهٔ نامشخص"
        if extra[:8] == b"\x89PNG\r\n\x1a\n": kind = "تصویرِ PNG جاسازی‌شده"
        elif extra[:3] == b"\xff\xd8\xff": kind = "تصویرِ JPEG جاسازی‌شده (احتمالاً ویدیوی motion-photo)"
        elif extra[:4] in (b"ftyp",) or extra[4:8] == b"ftyp": kind = "ویدیو/فایلِ MP4 جاسازی‌شده"
        elif all(32 <= b < 127 or b in (9,10,13) for b in preview[:200]): kind = "متنِ پنهان"
        hidden = {"size": len(extra), "kind": kind,
                  "hex_head": extra[:64].hex(),
                  "ascii_head": "".join(chr(b) if 32 <= b < 127 else "·" for b in preview[:120])}
    return {"trailing_bytes": hidden}

# ---------- تامبنیلِ مخفی ----------
def hidden_thumbnail(data: bytes):
    try:
        import exifread
        tags = exifread.process_file(io.BytesIO(data), details=True)
        th = tags.get("JPEGThumbnail")
        if th:
            raw = bytes(th)
            try:
                img = Image.open(io.BytesIO(raw))
                return {"found": True, "size": len(raw), "dims": f"{img.width}×{img.height}",
                        "b64": base64.b64encode(raw).decode(), "note": "این کپی معمولاً نسخهٔ قبلِ ویرایشِ عکس است!"}
            except Exception:
                return {"found": True, "size": len(raw), "dims": None, "b64": None,
                        "note": "تامبنیل هست ولی بازگشایی نشد"}
        return {"found": False}
    except Exception as e:
        return {"found": False, "error": str(e)}

# ---------- MakerNotes و همهٔ تگ‌ها با exiftool ----------
MAKER_FA = {
    "SensorSerialNumber":"سریالِ سنسور (خیلی حساس!)","SerialNumber":"سریالِ دستگاه (خیلی حساس!)",
    "InternalSerialNumber":"سریالِ داخلی (خیلی حساس!)","ShutterCount":"تعدادِ شاتتر (خطرناک!)",
    "LensSerialNumber":"سریالِ لنز","CameraTemperature":"دمایِ سنسور","FirmwareVersion":"نسخهٔ فریم‌ور",
    "ImageUniqueID":"شناسهٔ یکتایِ تصویر","AutoBrightness":"روشناییِ خودکار","FaceDetected":"تشخیصِ چهرهٔ دوربین",
    "FacesDetected":"تعدادِ چهره‌هایِ شناسایی‌شده","ShotNumberSincePowerUp":"شمارهٔ عکس از روشن‌شدن",
    "BatteryLevel":"وضعیتِ باتری","DriveMode":"حالتِ عکاسی","FocusMode":"حالتِ فوکوس",
}
SENSITIVE_KEYS = ("Serial","Shutter","UniqueID","InternalSerial","OwnerName","ArtistName","BatteryLevel")

def full_exiftool(data: bytes, filename="photo.jpg"):
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
        f.write(data); tmp = f.name
    try:
        r = subprocess.run(["exiftool","-j","-a","-u","-G1","-ee","tmp"], capture_output=True, text=True, timeout=30) if False else \
            subprocess.run(["exiftool","-j","-a","-u","-G1","-ee",tmp], capture_output=True, text=True, timeout=30)
        d = json.loads(r.stdout)[0]
        groups = {}
        for k, v in d.items():
            if k.startswith(("System:","SourceFile","ExifTool:ExifTool")): continue
            g, key = k.split(":", 1)
            if key in ("FileName","Directory","FileSize","FileModifyDate","FileAccessDate","FileInodeChangeDate","FilePermissions"): continue
            val = v if isinstance(v, (int, float)) else str(v)
            if isinstance(val, str) and len(val) > 200: val = val[:200] + "…"
            fa = MAKER_FA.get(key, key)
            sens = any(s.lower() in key.lower() for s in SENSITIVE_KEYS)
            groups.setdefault(g, []).append({"key": key, "fa": fa, "value": val, "sensitive": sens})
        return groups
    finally:
        os.unlink(tmp)

def forensics_report(data: bytes):
    return {
        "thumbnail": hidden_thumbnail(data),
        "fingerprint": jpeg_quant_fingerprint(data),
        "hidden_data": after_eoi(data),
        "maker_groups": full_exiftool(data),
    }
