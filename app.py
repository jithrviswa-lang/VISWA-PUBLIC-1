# app.py
import json, asyncio, random, hmac, hashlib
import gzip, zlib, uuid, base64
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import aiohttp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ================== CONSTANTS ==================
RELEASE_VERSION = "OB55"
CLIENT_ID       = 100067
CLIENT_SECRET   = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
AES_KEY         = b'Yg&tc%DEuh6%Zc^8'
AES_IV          = b'6oyZDr22E3ychjM%'
TIMEOUT         = 25

OAUTH_URLS = [
    "https://ffmconnect.live.gop.garenanow.com/api/v2/oauth/guest/token:grant",
    "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant",
]
LOGIN_URLS = [
    "https://loginbp.ppmainecoonghj.com/MajorLogin",
    "https://loginbp.ggwhitehawk.com/MajorLogin",
    "https://loginbp.ggblueshark.com/MajorLogin",
]

# ================== PROTOBUF ==================
def _vi(n):
    o=[]
    while True:
        b=n&0x7F; n>>=7
        o.append(b|(0x80 if n else 0))
        if not n: break
    return bytes(o)

def _fv(f,v): return _vi((f<<3)|0)+_vi(v)
def _fb(f,v):
    b=v.encode() if isinstance(v,str) else bytes(v)
    return _vi((f<<3)|2)+_vi(len(b))+b

def encode_proto(fields):
    out=bytearray()
    for f in sorted(fields):
        v=fields[f]
        if isinstance(v,dict): out+=_fb(f,encode_proto(v))
        elif isinstance(v,int): out+=_fv(f,v)
        elif isinstance(v,(str,bytes)): out+=_fb(f,v)
    return bytes(out)

def _rvi(buf,pos):
    r=s=0
    while pos<len(buf):
        b=buf[pos]; r|=(b&0x7F)<<s; pos+=1
        if not (b&0x80): break
        s+=7
    return r,pos

def decode_proto(data):
    res,pos={},0
    while pos<len(data):
        try: tag,pos=_rvi(data,pos)
        except: break
        f,wt=tag>>3,tag&7; v=None
        try:
            if wt==0: v,pos=_rvi(data,pos)
            elif wt==1: v,pos=int.from_bytes(data[pos:pos+8],'little'),pos+8
            elif wt==2:
                ln,pos=_rvi(data,pos); v,pos=data[pos:pos+ln],pos+ln
            elif wt==5: v,pos=int.from_bytes(data[pos:pos+4],'little'),pos+4
            else: break
        except: break
        if v is not None:
            if f in res: res[f]=res[f]+[v] if isinstance(res[f],list) else [res[f],v]
            else: res[f]=v
    return res

# ================== UTIL ==================
def encrypt(d): return AES.new(AES_KEY,AES.MODE_CBC,AES_IV).encrypt(pad(d,16))

def decompress(d):
    if not d: return b''
    if d.startswith(b'\x1f\x8b'):
        try: return gzip.decompress(d)
        except: pass
    for w in (zlib.MAX_WBITS,-zlib.MAX_WBITS):
        try: return zlib.decompress(d,w)
        except: pass
    return d

def _first(v,d=None):
    return v[0] if isinstance(v,list) and v else (d if v is None else v)

def jwt_payload(tok):
    try:
        p=tok.split('.')[1]; p+='='*(-len(p)%4)
        return json.loads(base64.urlsafe_b64decode(p))
    except: return {}

# ================== DEVICE ==================
_DEVICES = [("Samsung","SM-G998B","Adreno 660","Android OS 12 / API-31"),
            ("Xiaomi","2201122G","Adreno 730","Android OS 13 / API-33"),
            ("Realme","RMX3700","Mali-G710","Android OS 14 / API-34")]

def make_device():
    _,_,gpu,osv = random.choice(_DEVICES)
    return {"unique_device_id": f"Google|{uuid.uuid4()}",
            "system_software": osv,
            "screen_width":  random.choice([1080,1440,720,1280]),
            "screen_height": random.choice([2400,3200,1600]),
            "screen_dpi":    str(random.randint(300,420)),
            "memory":        random.randint(2800,6500),
            "processor_details": f"ARM64 FP ASIMD AES VMH | {random.randint(2200,3200)} | {random.randint(6,12)}",
            "gpu_renderer":  gpu}

# ================== CORE ==================
async def fetch_account(uid, password):
    async with aiohttp.ClientSession() as session:
        # --- OAuth ---
        oauth = None
        for url in OAUTH_URLS:
            try:
                body = json.dumps({
                    "uid": int(uid) if str(uid).isdigit() else uid,
                    "password": password,
                    "response_type": "token",
                    "client_type": 2,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                }, separators=(',',':'))
                sig = hmac.new(bytes.fromhex(CLIENT_SECRET), body.encode(), hashlib.sha256).hexdigest()
                async with session.post(url, headers={
                    "User-Agent":"Dalvik/2.1.0 (Linux; U; Android 14; Pixel 7 Build/UQ1A.240205.06151050)",
                    "Authorization": f"Signature {sig}",
                    "Content-Type":"application/json; charset=utf-8",
                    "Accept":"application/json",
                }, data=body, timeout=TIMEOUT) as r:
                    if r.status != 200: continue
                    d = await r.json()
                    if d.get("code") == 0 and d.get("data",{}).get("access_token"):
                        oauth = d["data"]; break
            except Exception:
                continue
        if not oauth:
            raise Exception("OAuth failed on all endpoints")

        # --- MajorLogin ---
        dev = make_device()
        payload = {
            3: str(datetime.now())[:-7], 4:"free fire", 5:2, 7:"1.132.3",
            8: dev["system_software"], 9:"Handheld", 10:"Verizon", 11:"WIFI",
            12: dev["screen_width"], 13: dev["screen_height"], 14: dev["screen_dpi"],
            15: dev["processor_details"], 16: dev["memory"], 17: dev["gpu_renderer"],
            18:"OpenGL ES 3.2 V@1.50", 19: dev["unique_device_id"], 21:"en",
            22: oauth["open_id"], 23:"4", 24:"Handheld", 25:{6:55,8:81},
            29: oauth["access_token"], 30:2, 41:"Verizon", 42:"WIFI",
            57:"7428b253defc164018c604a1ebbfebdf",
            60:128512, 61:random.randint(38000,52000), 62:110731,
            63:random.randint(18000,32000), 64:random.randint(18000,25000),
            65:26628, 66:random.randint(25000,60000), 67:119234,
            73:3, 74:"/data/app/~~random/base.apk",
            76:1, 77:"hash|base.apk", 78:3, 79:2, 81:"64",
            83:"2019121229", 86:"OpenGLES3", 87:16383, 88:4,
            89:b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg==",
            92:random.randint(9000,18000), 93:"android",
            97:1, 98:0, 99:"4", 100:"4",
        }
        headers = {
            "Content-Type":"application/octet-stream",
            "X-Unity-Version":"2018.4.12f1",
            "X-GA":"v1 1", "X-GA-SV":"1789544569",
            "ReleaseVersion": RELEASE_VERSION,
            "Accept-Encoding":"deflate, gzip",
            "User-Agent":"UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        }
        content = None
        for url in LOGIN_URLS:
            try:
                async with session.post(url, headers=headers,
                                        data=encrypt(encode_proto(payload)),
                                        timeout=TIMEOUT) as r:
                    if r.status == 200:
                        content = await r.read()
                        if content: break
            except Exception:
                continue
        if not content:
            raise Exception("MajorLogin failed on all endpoints")

        # --- Decode ---
        parsed = {}
        for off in (0,4,5,8,64):
            if len(content) > off:
                try:
                    p = decode_proto(decompress(content[off:]))
                    if p and 8 in p:
                        parsed = p; break
                except: pass
        if not parsed or 8 not in parsed:
            raise Exception("Protobuf decode failed")

        jwt = _first(parsed.get(8))
        if isinstance(jwt, bytes): jwt = jwt.decode('utf-8','ignore')
        jd = jwt_payload(jwt)

        # ================== ONLY 5 FIELDS ==================
        return {
            "success": True,
            "uid": str(uid),
            "account_id": jd.get("account_id"),
            "jwt_token": jwt,
            "access_token": oauth.get("access_token"),
            "region": jd.get("lock_region"),
        }

# ==================================================================
#              VERCEL HANDLER
# ==================================================================
class handler(BaseHTTPRequestHandler):
    def _send_json(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin","*")
        self.end_headers()
        self.wfile.write(json.dumps(body, indent=2).encode('utf-8'))

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.rstrip('/') not in ('', '/token', '/api/token'):
            self._send_json(404, {"success": False, "error": "Use /token"})
            return

        q = parse_qs(parsed.query)
        uid = (q.get("uid") or [None])[0]
        pwd = (q.get("password") or q.get("pass") or [None])[0]

        if not uid or not pwd:
            self._send_json(400, {
                "success": False,
                "error": "Missing 'uid' or 'pass'",
                "example": "/token?uid=123&pass=abc"
            })
            return

        try:
            result = asyncio.run(fetch_account(uid, pwd))
            self._send_json(200, result)
        except Exception as e:
            self._send_json(500, {"success": False, "uid": uid, "error": str(e)})

    def log_message(self, *args):
        pass

# ==================================================================
#              LOCAL RUNNER
# ==================================================================
if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8000), handler)
    print("🚀 Server running on http://0.0.0.0:8000")
    print("📱 Test: http://127.0.0.1:8000/token?uid=YOUR_UID&pass=YOUR_PASS")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Stopped")
