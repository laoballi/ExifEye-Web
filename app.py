# -*- coding: utf-8 -*-
"""چشمِ EXIF — اپِ وبِ فارسیِ تحلیل و پاک‌سازیِ متادیتا (FastAPI، کاملاً محلی)"""
import io, os, json, hashlib
from datetime import datetime
from pathlib import Path
from typing import List
import exifread
from PIL import Image, ImageStat, ImageFilter
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
import uvicorn

app = FastAPI(title="چشمِ EXIF")
UPLOAD = Path("/tmp/exifweb_uploads"); UPLOAD.mkdir(exist_ok=True)
FA_DIGITS = str.maketrans("0123456789.", "۰۱۲۳۴۵۶۷۸۹٫")
fa = lambda s: str(s).translate(FA_DIGITS)

TAGS_FA = {
    "Image Make":"سازنده دوربین","Image Model":"مدل دوربین","Image DateTime":"تاریخ و ساعت عکس",
    "EXIF DateTimeOriginal":"زمانِ اصلیِ عکس","EXIF ExifVersion":"نسخهٔ EXIF","EXIF ISOSpeedRatings":"ISO",
    "EXIF FNumber":"عدد f (دیافراگم)","EXIF ExposureTime":"زمانِ نوردهی","EXIF FocalLength":"فاصلهٔ کانونی",
    "EXIF LensModel":"لنز","EXIF Flash":"فلاش","EXIF WhiteBalance":"وایت‌بالانس","EXIF Software":"نرم‌افزار",
    "EXIF UserComment":"یادداشت کاربر","GPS GPSLatitude":"عرضِ جغرافیایی (GPS!)","GPS GPSLongitude":"طولِ جغرافیایی (GPS!)",
    "GPS GPSAltitude":"ارتفاع از دریا","Image XResolution":"رزولوشن X","Image YResolution":"رزولوشن Y",
    "EXIF DateTimeDigitized":"زمانِ دیجیتال‌سازی","Image Orientation":"جهتِ تصویر","EXIF PixelXDimension":"عرضِ پیکسلی",
    "EXIF PixelYDimension":"ارتفاعِ پیکسلی","EXIF SerialNumber":"سریالِ دوربین (حساس!)","EXIF BodySerialNumber":"سریالِ بدنه (حساس!)",
    "Image Artist":"هنرمند/سازنده","Image Copyright":"کپی‌رایت","Image ImageDescription":"توضیحِ تصویر",
}

def reverse_geocode(lat, lon):
    try:
        import requests
        r = requests.get(f"https://api.bigdatacloud.net/data/reverse-geocode-client?latitude={lat}&longitude={lon}&localityLanguage=fa", timeout=8)
        d = r.json(); return ", ".join(filter(None,[d.get("locality"), d.get("principalSubdivision"), d.get("countryName")])) or None
    except Exception:
        return None

def dms_to_deg(dms, ref):
    try:
        if hasattr(dms, "values"): dms = list(dms.values)
        d = float(dms[0]) + float(dms[1])/60 + float(dms[2])/3600
        if str(ref) in ("S","W"): d = -d
        return round(d, 6)
    except Exception: return None

def quality(img: Image.Image):
    g = img.convert("L")
    st = ImageStat.Stat(g)
    edges = g.filter(ImageFilter.FIND_EDGES)
    es = ImageStat.Stat(edges)
    sharp = round(min(es.stddev[0]*4, 100), 1)
    bright = round(st.mean[0], 1)
    contrast = round(st.stddev[0], 1)
    score = round(sharp*0.4 + min(bright/2.55*1.3,100)*0.3 + min(contrast*2.2,100)*0.3, 1)
    return {"score": score, "sharpness": sharp, "brightness": bright, "contrast": contrast,
            "blur": "تیز ✓" if sharp > 35 else "بلور ⚠"}

def analyze_bytes(data: bytes, name: str, geocode=True):
    out = {"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()[:16]}
    try:
        img = Image.open(io.BytesIO(data))
        out["format"] = img.format; out["dimensions"] = f"{img.width}×{img.height}"; out["mode"] = img.mode
        out["quality"] = quality(img)
        # پالت رنگ
        small = img.convert("RGB").resize((80,80))
        colors = sorted(small.getcolors(6400) or [], reverse=True)[:5]
        total = sum(c[0] for c in colors) or 1
        out["colors"] = [{"hex": "#%02x%02x%02x" % c[1], "pct": round(c[0]*100/total,1)} for c in colors]
    except Exception as e:
        out["image_error"] = str(e)
    tags = exifread.process_file(io.BytesIO(data), details=False)
    meta = []
    for tag, val in tags.items():
        if tag in ("JPEGThumbnail","TIFFThumbnail","EXIF MakerNote"): continue
        v = str(val)
        meta.append({"tag": tag, "fa": TAGS_FA.get(tag, tag), "value": v[:120]})
    out["metadata"] = meta
    # GPS
    lat = dms_to_deg(tags.get("GPS GPSLatitude", ()), tags.get("GPS GPSLatitudeRef","N"))
    lon = dms_to_deg(tags.get("GPS GPSLongitude", ()), tags.get("GPS GPSLongitudeRef","E"))
    if lat is not None and lon is not None:
        out["gps"] = {"lat": lat, "lon": lon, "place": reverse_geocode(lat, lon) if geocode else None}
    # ریسک حریم خصوصی
    risks = []
    if "gps" in out: risks.append("📍 موقعیتِ GPS در فایل ثبت شده — لو دادنِ مکان!")
    sens = [m for m in meta if "سریال" in m["fa"] or "یادداشت" in m["fa"] or "نرم‌افزار" in m["fa"]]
    if sens: risks.append("🆔 اطلاعاتِ حساسِ دستگاه/سریال موجود: " + "، ".join(m["fa"] for m in sens))
    if any("تاریخ" in m["fa"] for m in meta): risks.append("🕒 زمانِ اصلیِ عکس ثبت شده")
    if any("سازنده دوربین" in m["fa"] or "مدل" in m["fa"] for m in meta): risks.append("📷 مشخصاتِ دوربین ثبت شده")
    # متادیتای پنهان بعد از EOI / اندازه غیرعادی
    if out.get("format") == "JPEG" and data.find(b"\xff\xd9") != -1 and data.find(b"\xff\xd9")+2 < len(data):
        risks.append("🕳 دیتایِ پنهانِ بعد از پایانِ تصویر (احتمالِ واترمارک/فایلِ چسبیده)")
    score = min(len(risks)*25, 100)
    out["privacy"] = {"score": score, "level": ["کم","متوسط","بالا","بحرانی"][min(len(risks)-1,3)] if risks else "پاکیزه",
                      "risks": risks}
    return out

def strip_bytes(data: bytes):
    """پاک‌سازی کامل — بازنویسیِ تمیز با Pillow"""
    img = Image.open(io.BytesIO(data))
    buf = io.BytesIO()
    fmt = img.format or "JPEG"
    if fmt in ("JPEG","WEBP"):
        img.save(buf, fmt, quality=95)
    else:
        img.save(buf, fmt)
    return buf.getvalue(), img.format

HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>چشمِ EXIF 👁️</title>
<style>
@font-face{font-family:Vazirmatn;src:url('https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face/css/fonts/webfonts/Vazirmatn-Regular.woff2') format('woff2');font-weight:400}
@font-face{font-family:Vazirmatn;src:url('https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face/css/fonts/webfonts/Vazirmatn-Bold.woff2') format('woff2');font-weight:700}
:root{--bg:#0d1117;--card:#161b27;--acc:#ef394e;--ok:#3fb950;--warn:#d29922;--bad:#f85149;--tx:#e6edf3;--sub:#8b949e}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:Vazirmatn,system-ui;padding:24px;max-width:900px;margin:auto}
h1{font-size:1.7rem;display:flex;align-items:center;gap:10px}h1 b{color:var(--acc)}
.sub{color:var(--sub);font-size:.85rem;margin:6px 0 20px}
.drop{border:2px dashed #30363d;border-radius:16px;padding:40px;text-align:center;cursor:pointer;transition:.2s;background:var(--card)}
.drop:hover,.drop.on{border-color:var(--acc);background:#1c2233}
.drop p{color:var(--sub);margin-top:8px;font-size:.85rem}
.drop .big{font-size:2.2rem}
#files{display:none}
.bar{display:none;height:6px;background:#21262d;border-radius:99px;margin:16px 0;overflow:hidden}
.bar i{display:block;height:100%;width:0;background:var(--acc);border-radius:99px;transition:.3s}
.card{background:var(--card);border:1px solid #30363d;border-radius:14px;padding:18px;margin-top:16px}
.fname{font-weight:700;margin-bottom:4px}
.row{display:flex;gap:12px;flex-wrap:wrap;margin-top:10px}
.chip{background:#21262d;border-radius:10px;padding:8px 14px;font-size:.85rem}
.chip b{display:block;font-size:1.05rem}
table{width:100%;border-collapse:collapse;margin-top:10px;font-size:.85rem}
td{padding:7px 10px;border-bottom:1px solid #21262d}
td:first-child{color:var(--sub)}td:last-child{direction:ltr;text-align:left;word-break:break-all}
.badge{display:inline-block;padding:4px 12px;border-radius:99px;font-size:.8rem;font-weight:700}
.lv-پاکیزه{background:#1a3a1f;color:var(--ok)}.lv-کم{background:#3d2e00;color:var(--warn)}
.lv-متوسط,.lv-بالا,.lv-بحرانی{background:#3d1416;color:var(--bad)}
.risks li{margin:6px 24px 0 0;color:#ffb0ae;font-size:.85rem;list-style:none}
.gps{background:#3d1416;border:1px solid var(--bad);border-radius:10px;padding:12px;margin-top:10px;font-size:.9rem}
.gps a{color:#ff7b72}
.qrow{display:flex;gap:10px;margin-top:10px}
.q{flex:1;background:#21262d;border-radius:10px;padding:10px;text-align:center}
.q b{font-size:1.3rem;display:block}
.sw{display:inline-block;width:22px;height:22px;border-radius:6px;vertical-align:middle;margin-inline-start:8px}
.pal{display:flex;gap:8px;margin-top:8px}
.pal div{flex:1;height:34px;border-radius:8px;position:relative}
.pal span{position:absolute;bottom:-20px;left:0;font-size:.7rem;color:var(--sub);direction:ltr}
.act{display:flex;gap:10px;margin-top:14px}
button{flex:1;padding:12px;border:0;border-radius:10px;font-family:inherit;font-weight:700;font-size:.95rem;cursor:pointer;background:#21262d;color:var(--tx)}
button.go{background:var(--acc);color:#fff}
button:disabled{opacity:.4;cursor:not-allowed}
.thumb{max-width:100%;max-height:260px;border-radius:10px;margin-top:10px;display:block}
.foot{text-align:center;color:var(--sub);font-size:.75rem;margin-top:30px}
</style></head><body>
<h1>👁️ چشمِ <b>EXIF</b></h1>
<div class="sub">تحلیلِ کاملِ متادیتا، کیفیت، حریمِ خصوصی و پاک‌سازی — تماماً رویِ همین دستگاه، بدونِ آپلود به هیچ سروری</div>
<div class="drop" id="drop"><div class="big">🖼️</div>عکس‌ها را اینجا بکِش یا کلیک کن<p>JPEG · PNG · WebP · TIFF — چندتایی هم می‌شه</p></div>
<input type="file" id="files" accept="image/*" multiple>
<div class="bar" id="bar"><i></i></div>
<div id="out"></div>
<div class="foot">چشمِ EXIF — نسخهٔ ۱٫۰ · همه‌چیز محلی است · ساخته‌شده با FastAPI + Pillow</div>
<script>
const drop=document.getElementById('drop'),files=document.getElementById('files'),out=document.getElementById('out'),bar=document.getElementById('bar'),fill=bar.querySelector('i');
drop.onclick=()=>files.click();
drop.ondragover=e=>{e.preventDefault();drop.classList.add('on')};
drop.ondragleave=()=>drop.classList.remove('on');
drop.ondrop=e=>{e.preventDefault();drop.classList.remove('on');run(e.dataTransfer.files)};
files.onchange=()=>run(files.files);
const fd2=n=>String(n).replace(/[0-9.]/g,d=>'۰۱۲۳۴۵۶۷۸۹٫'[d]);
async function run(list){
  out.innerHTML='';bar.style.display='block';fill.style.width='10%';
  for(let i=0;i<list.length;i++){
    const f=list[i],body=new FormData();body.append('file',f);
    fill.style.width=Math.round(10+80*i/list.length)+'%';
    const r=await fetch('/analyze',{method:'POST',body});const d=await r.json();
    out.insertAdjacentHTML('beforeend',render(d,f));
    fill.style.width=Math.round(10+80*(i+1)/list.length)+'%';
  }
  fill.style.width='100%';setTimeout(()=>bar.style.display='none',600);
}
function render(d,f){
  let h=`<div class="card"><div class="fname">📄 ${d.name}</div>
  <div class="row"><div class="chip">ابعاد<b>${fd2(d.dimensions||'—')}</b></div>
  <div class="chip">حجم<b>${fd2((d.size/1024).toFixed(1))} کیلوبایت</b></div>
  <div class="chip">فرمت<b>${d.format||'—'}</b></div></div>`;
  if(d.thumbnail)h+=`<img class="thumb" src="data:image/jpeg;base64,${d.thumbnail}">`;
  if(d.quality)h+=`<div class="row" style="margin-top:12px">
   <div class="q">نمرهٔ کیفیت<b style="color:${d.quality.score>60?'#3fb950':d.quality.score>35?'#d29922':'#f85149'}">${fd2(d.quality.score)}</b>از ۱۰۰</div>
   <div class="q">تیزی<b>${fd2(d.quality.sharpness)}</b></div><div class="q">روشنایی<b>${fd2(d.quality.brightness)}</b></div>
   <div class="q">کنتراست<b>${fd2(d.quality.contrast)}</b></div><div class="q">وضعیت<b>${d.quality.blur}</b></div></div>`;
  if(d.colors)h+=`<div style="margin-top:16px;font-size:.85rem;color:var(--sub)">🎨 پالتِ رنگِ غالب</div><div class="pal">`+
    d.colors.map(c=>`<div style="background:${c.hex}"><span>${c.hex} · ${fd2(c.pct)}٪</span></div>`).join('')+`</div>`;
  const p=d.privacy;h+=`<div style="margin-top:18px">🔒 حریمِ خصوصی: <span class="badge lv-${p.level}">${p.level} · ${fd2(p.score)}/۱۰۰</span></div>`;
  if(p.risks.length)h+=`<ul class="risks">`+p.risks.map(r=>`<li>${r}</li>`).join('')+`</ul>`;
  if(d.gps)h+=`<div class="gps">📍 <b>موقعیتِ GPS:</b> ${d.gps.lat}, ${d.gps.lon}`+
    (d.gps.place?` — ${d.gps.place}`:'')+`<br><a target="_blank" href="https://www.google.com/maps?q=${d.gps.lat},${d.gps.lon}">نمایش روی نقشه ↗</a></div>`;
  if(d.metadata.length)h+=`<div style="margin-top:16px;font-size:.85rem;color:var(--sub)">📋 متادیتا (${fd2(d.metadata.length)} تگ)</div>
    <table>`+d.metadata.map(m=>`<tr><td>${m.fa}</td><td>${esc(m.value)}</td></tr>`).join('')+`</table>`;
  h+=`<div class="act"><button onclick='clean("${d.name}",${d.size})'>🧹 پاک‌سازی و دانلودِ نسخهٔ تمیز</button>
  <button onclick='forensics("${d.name}",${d.size},this)'>🔬 دقیق‌کاوی</button></div></div>`;
  return h;
}
async function forensics(name,size,btn){
  const f=[...document.getElementById('files').files].find(x=>x.name===name&&x.size===size);
  if(!f)return alert('فایل پیدا نشد');
  btn.textContent='… در حالِ کاوش';btn.disabled=true;
  const body=new FormData();body.append('file',f);
  const r=await fetch('/forensics',{method:'POST',body});const d=await r.json();
  btn.textContent='🔬 دقیق‌کاوی';btn.disabled=false;
  let h=`<div class="card" id="fx"><div class="fname" style="color:#ff7b72">🔬 گزارشِ دقیق‌کاوی — ${esc(name)}</div>`;
  // تامبنیل مخفی
  const t=d.thumbnail;
  h+=`<div style="margin-top:12px">🖼️ <b>تامبنیلِ مخفیِ EXIF:</b> `;
  if(t.found){h+=`<span class="badge lv-بحرانی">پیدا شد! ${fd2(t.size)} بایت ${t.dims?'· '+fd2(t.dims):''}</span>
  <div style="color:#ffb0ae;font-size:.85rem;margin-top:6px">${t.note}</div>`;
   if(t.b64)h+=`<img class="thumb" src="data:image/jpeg;base64,${t.b64}">`;}
  else h+=`<span class="badge lv-پاکیزه">تامبنیلی قایم نشده</span>`;
  h+=`</div>`;
  // اثر انگشت
  const fp=d.fingerprint;
  h+=`<div style="margin-top:14px">🧬 <b>اثرِ انگشتِ فشرده‌سازیِ JPEG:</b> ${esc(fp.gen_hint)}</div>`;
  if(fp.matches.length)h+=`<div class="gps" style="background:#1a2a1f;border-color:var(--ok)">✅ تطبیق: `+fp.matches.map(m=>esc(m)).join(' · ')+`</div>`;
  h+=`<table>`+fp.tables.map(t=>`<tr><td>جدول ${fd2(t.id)}</td><td>${t.first8.join(' · ')}</td></tr>`).join('')+`</table>`;
  // دیتای بعد EOI
  const hd=d.hidden_data.trailing_bytes;
  h+=`<div style="margin-top:14px">🕳 <b>دیتایِ پنهانِ بعد از پایانِ تصویر:</b> `;
  if(hd)h+=`<span class="badge lv-بحرانی">${fd2(hd.size)} بایتِ پنهان — ${esc(hd.kind)}</span>
  <table><tr><td>شروعِ هگز</td><td style="direction:ltr">${hd.hex_head}</td></tr>
  <tr><td>متنیِ قابلِ خواندن</td><td style="direction:ltr">${esc(hd.ascii_head)}</td></tr></table>`;
  else h+=`<span class="badge lv-پاکیزه">دیتایِ پنهانی نیست — فایلِ پاکیزه</span>`;
  h+=`</div>`;
  // MakerNotes
  const mg=d.maker_groups||{};
  const gc=Object.keys(mg).filter(g=>mg[g].length).length;
  h+=`<div style="margin-top:14px">🏭 <b>MakerNotes و تگ‌هایِ عمیق (exiftool):</b> ${fd2(Object.values(mg).reduce((a,b)=>a+b.length,0))} تگ در ${fd2(gc)} گروه</div>`;
  for(const[g,arr]of Object.entries(mg)){
    if(!arr.length)continue;
    h+=`<details style="margin-top:8px"><summary style="cursor:pointer;color:var(--sub);font-size:.85rem">📁 ${esc(g)} (${fd2(arr.length)})</summary><table>`+
      arr.map(m=>`<tr><td>${m.sensitive?'🚨 ':''}${esc(m.fa)}</td><td>${esc(String(m.value))}</td></tr>`).join('')+`</table></details>`;
  }
  h+=`</div>`;
  const card=document.getElementById('fx')||document.createElement('div');
  out.insertAdjacentHTML('beforeend',h);
  document.getElementById('fx').scrollIntoView({behavior:'smooth'});
}
function esc(s){const t=document.createElement('i');t.textContent=s;return t.innerHTML}
async function clean(name,size){
  const f=[...document.getElementById('files').files].find(x=>x.name===name&&x.size===size);
  if(!f)return alert('فایل پیدا نشد');
  const body=new FormData();body.append('file',f);
  const r=await fetch('/strip',{method:'POST',body});const b=await r.blob();
  const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='cleaned_'+name;a.click();
}
</script></body></html>"""

from fastapi.staticfiles import StaticFiles
app.mount("/static", StaticFiles(directory="/home/agentuser/exifeye-web/static"), name="static")

@app.post("/forensics")
async def forensics_ep(file: UploadFile = File(...)):
    data = await file.read()
    from forensics import forensics_report
    return JSONResponse(forensics_report(data))

@app.get("/", response_class=HTMLResponse)
def home(): return HTML

@app.post("/analyze")
async def analyze_ep(file: UploadFile = File(...)):
    data = await file.read()
    r = analyze_bytes(data, file.filename)
    if r.get("format") == "JPEG":
        try:
            img = Image.open(io.BytesIO(data)); img.thumbnail((400,400))
            tb = io.BytesIO(); img.convert("RGB").save(tb, "JPEG", quality=80)
            r["thumbnail"] = tb.getvalue().hex() and __import__("base64").b64encode(tb.getvalue()).decode()
        except Exception: pass
    return JSONResponse(r)

@app.post("/strip")
async def strip_ep(file: UploadFile = File(...)):
    data = await file.read()
    cleaned, fmt = strip_bytes(data)
    from fastapi import Response
    return Response(content=cleaned, media_type=f"image/{fmt.lower()}",
                    headers={"Content-Disposition": f'attachment; filename="cleaned_{file.filename}"'})

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8097)
