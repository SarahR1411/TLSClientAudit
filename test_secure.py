#!/usr/bin/env python3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
import ssl
import time
import subprocess
import signal

class SecureAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers('ECDHE+AESGCM:!aNULL:!MD5:!RC4')
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

print("[*] Démarrage mitmproxy...")
mitm = subprocess.Popen(["mitmdump", "-q", "-s", "client_audit.py"])
time.sleep(3)

print("\n=== CLIENT SÉCURISÉ (devrait avoir Grade A) ===\n")
session = requests.Session()
session.mount('https://', SecureAdapter())
session.proxies = {'https': 'http://127.0.0.1:8080'}
session.verify = False

for i in range(1, 5):
    print(f"Connexion {i}/4...")
    try:
        r = session.get('https://www.google.com', timeout=10)
        print(f"  ✓ OK (HTTP {r.status_code})")
    except Exception as e:
        print(f"  ✗ Échec attendu: {type(e).__name__}")
    time.sleep(2)

mitm.send_signal(signal.SIGTERM)
mitm.wait()
print("\n[✓] Terminé!")
