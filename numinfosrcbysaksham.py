# numtoinfo.py
"""
Real-style API (single developer field):
  - Endpoint: GET /fetch?key=<API_KEY>&num=<10-digit-number>
  - Returns valid JSON only (Content-Type: application/json; charset=utf-8)
  - API key validation (edit API_KEY constant to change key)
  - Adds "source_developer" only as a top-level field (not inside each result)
  - Adds header X-Source-Developer: Saksham
  - Compact JSON (no pretty spacing)
  - Proper HTTP status codes and error messages

Upstream request now emulates the provided curl: form field "message", many headers
(including sec-ch-ua*), Accept-Encoding with zstd, Origin/Referer, Cookie support,
and includes ?i=1 on the upstream URL.
"""
from flask import Flask, request, Response
import requests, re, html, binascii, json, logging
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# === CONFIG ===
API_KEY = "paidkey"        # change this when you want a new key
# <-- Updated to the curl target from your example. Keep/change as needed.
TARGET_URL = "https://hostzo.ct.ws/uploads/32288f2ab34dde64a97e0c2fbf8d8b7d/web_746f.php?i=1"
SOURCE_NAME = "Saksham"        # developer name shown only once (top-level)
REQUEST_TIMEOUT = 30
# ==============

# Base headers (will be merged/overridden to emulate curl more closely)
BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
    "Accept-Language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,hi;q=0.6",
    # Note: Accept-Encoding will be set to include zstd to match the curl example
    "Accept-Encoding": "gzip, deflate, br, zstd",
    # The following sec-ch-* and fetch metadata are included to mirror the curl
    "sec-ch-ua-platform": '"Android"',
    'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
    "sec-ch-ua-mobile": "?1",
    "Origin": "https://hostzo.ct.ws",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    # Keep Connection header (requests default is HTTP/1.1)
    "Connection": "keep-alive",
}

# emoji removal regex
EMOJI_RE = re.compile(r"[\U0001F000-\U0010FFFF]+", flags=re.UNICODE)

def clean_text(t):
    if not t:
        return ""
    t = html.unescape(t)
    t = EMOJI_RE.sub("", t)
    t = re.sub(r"[\uFE00-\uFE0F\u200D]", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t

def parse_reply_html(reply_html):
    """Parse the HTML 'reply' block returned by upstream and return dict of fields.
       NOTE: This function does NOT add source_developer to each result."""
    soup = BeautifulSoup(reply_html, "html.parser")
    rows = soup.find_all("div", class_="row")
    data = {}
    for r in rows:
        lbl_el = r.find("div", class_="label")
        val_el = r.find("div", class_="value")
        label = clean_text(lbl_el.get_text(" ", strip=True)) if lbl_el else ""
        value = clean_text(val_el.get_text(" ", strip=True)) if val_el else ""
        key = re.sub(r"[^\w\s]", "", label).strip().lower().replace(" ", "_").replace(":", "")
        if key:
            data[key] = value
    return data

def attempt_js_cookie(page_html):
    """Attempt to decrypt __test cookie from JS challenge by pulling hex arrays used by client's JS."""
    hexvals = re.findall(r'toNumbers\(\s*"([0-9a-fA-F]+)"\s*\)', page_html)
    if len(hexvals) < 3:
        return None
    a, b, c = hexvals[-3], hexvals[-2], hexvals[-1]
    try:
        key_bytes = binascii.unhexlify(a)
        iv_bytes = binascii.unhexlify(b)
        cipher_bytes = binascii.unhexlify(c)
        dec = AES.new(key_bytes, AES.MODE_CBC, iv_bytes).decrypt(cipher_bytes)
        try:
            plain = unpad(dec, AES.block_size)
        except Exception:
            plain = dec.rstrip(b"\x00").rstrip()
        return binascii.hexlify(plain).decode()
    except Exception:
        return None

def make_json_response(payload_dict, status=200):
    """Return Response object with compact JSON and proper content-type + source header."""
    compact = json.dumps(payload_dict, separators=(",", ":"))
    headers = {"X-Source-Developer": SOURCE_NAME}
    return Response(compact, status=status, mimetype="application/json; charset=utf-8", headers=headers)

def upstream_post_number(num, cookie_value=None):
    """
    Perform the upstream POST exactly as the curl:
      - form field 'message' with the phone number
      - includes many headers (sec-ch-*, Origin, Referer, Accept-Encoding with zstd)
      - includes Cookie header if cookie_value provided
    Returns the requests.Response object or raises.
    """
    headers = dict(BASE_HEADERS)
    # Add Referer matching curl example
    headers["Referer"] = "https://hostzo.ct.ws/uploads/32288f2ab34dde64a97e0c2fbf8d8b7d/web_746f.php?i=1"
    # If cookie_value passed in, set Cookie header to include __test (and optional user_id if known)
    if cookie_value:
        headers["Cookie"] = cookie_value
    # The curl used --http1.1; requests uses HTTP/1.1 by default.
    # The body is multipart/form-data with field 'message'
    files = {"message": (None, num)}
    # Use POST
    resp = requests.post(TARGET_URL, headers=headers, files=files, timeout=REQUEST_TIMEOUT)
    return resp

@app.route("/fetch", methods=["GET"])
def fetch():
    provided_key = request.args.get("key", "").strip()
    num = request.args.get("num", "").strip()

    # Validate API key
    if not provided_key or provided_key != API_KEY:
        return make_json_response({"ok": False, "error": "Invalid or missing API key."}, status=401)

    # Validate phone number
    if not re.fullmatch(r"\d{10}", num):
        return make_json_response({"ok": False, "error": "Provide a valid 10-digit phone number in ?num= parameter."}, status=400)

    # Call upstream (first try without cookie header; if JS challenge appears, try to solve and retry with cookie)
    try:
        resp = upstream_post_number(num)
    except Exception as e:
        logging.exception("Upstream request failed (initial)")
        return make_json_response({"ok": False, "error": f"Upstream request failed: {str(e)}"}, status=502)

    # Try parse upstream JSON; if there's a JS challenge, attempt cookie solution and retry once
    try:
        upstream_json = resp.json()
    except ValueError:
        # Attempt to extract/decrypt __test cookie from the returned page and retry
        cookie = attempt_js_cookie(resp.text)
        if not cookie:
            logging.warning("JS challenge present and not solvable (no cookie extracted)")
            return make_json_response({"ok": False, "error": "JS challenge not solvable."}, status=502)
        # Build cookie header same format as curl example (if you also have user_id you can include it)
        cookie_header_value = f"__test={cookie}"
        try:
            resp = upstream_post_number(num, cookie_value=cookie_header_value)
            upstream_json = resp.json()
        except Exception as e:
            logging.exception("Upstream failed after solving cookie")
            return make_json_response({"ok": False, "error": f"Upstream request failed after cookie: {str(e)}"}, status=502)

    # Extract results
    results = []
    if isinstance(upstream_json, dict) and "reply" in upstream_json:
        results.append(parse_reply_html(upstream_json["reply"]))
    elif isinstance(upstream_json, dict) and "replies" in upstream_json:
        for rhtml in upstream_json["replies"]:
            results.append(parse_reply_html(rhtml))
    else:
        logging.warning("Upstream returned unexpected structure")
        return make_json_response({"ok": False, "error": "Upstream did not return expected data."}, status=502)

    # Top-level payload: include source_developer only once (top-level)
    payload = {
        "ok": True,
        "results": results,
        "source_developer": SOURCE_NAME
    }
    return make_json_response(payload, status=200)

if __name__ == "__main__":
    # In production, run with gunicorn / uwsgi behind nginx. This debug run is for testing.
    app.run(host="0.0.0.0", port=5000, debug=False)
