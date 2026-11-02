"""Build the encrypted BBP Portfolio page.

Usage: python3 tools/build.py <plaintext_app.html> <codes.json> [out=index.html]

codes.json (kept private, never committed): {"codes": ["MONTHLYCODE", "ownercode"]}
The plaintext app is encrypted with a random page key (AES-256-GCM); the page key is
wrapped once per access code (PBKDF2-SHA256, 250k iterations). Only ciphertext is written.
"""
import base64, json, os, sys, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 250_000
b64 = lambda b: base64.b64encode(b).decode()

def main():
    app_path, codes_path = sys.argv[1], sys.argv[2]
    out = sys.argv[3] if len(sys.argv) > 3 else os.path.join(os.path.dirname(__file__), '..', 'index.html')
    html = open(app_path, encoding='utf-8').read()
    # The gate replaces the app's own login: hide it once decrypted.
    html = html.replace("const login = document.getElementById('login');",
                        "const login = document.getElementById('login'); login.hidden = true;", 1)
    html = html.replace("document.getElementById('pw').value = ''; login.hidden = false; });",
                        "try { Object.keys(sessionStorage).filter(k => k.startsWith('bbp-k-')).forEach(k => sessionStorage.removeItem(k)); } catch (er) {} location.reload(); });", 1)
    # Inline Chart.js so the decrypted page has no external script (document.write blocks cross-site scripts on slow connections).
    tag = '<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>'
    vendor = open(os.path.join(os.path.dirname(__file__), 'vendor', 'chart.umd.4.4.1.js'), encoding='utf-8').read()
    assert '</script' not in vendor.lower()
    if tag in html:
        html = html.replace(tag, '<script>' + vendor + '</script>', 1)
    codes = json.load(open(codes_path))['codes']
    key = AESGCM.generate_key(256); iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, html.encode('utf-8'), None)
    wraps = []
    for code in codes:
        salt = os.urandom(16); wiv = os.urandom(12)
        kek = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(code.encode())
        wraps.append({'salt': b64(salt), 'iv': b64(wiv), 'ct': b64(AESGCM(kek).encrypt(wiv, key, None))})
    payload = {'v': hashlib.sha256(ct).hexdigest()[:12], 'iter': ITER, 'iv': b64(iv), 'ct': b64(ct), 'wraps': wraps}
    tpl = open(os.path.join(os.path.dirname(__file__), 'gate_template.html'), encoding='utf-8').read()
    open(out, 'w', encoding='utf-8').write(tpl.replace('__PAYLOAD__', json.dumps(payload)))
    print('wrote', out, len(ct), 'bytes encrypted,', len(wraps), 'codes')

if __name__ == '__main__':
    main()
