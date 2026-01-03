#!/usr/bin/env python3
import requests
import urllib.parse
import random
import time
import sys
import os

print("------------------------------------------")
print(" SQL Injection Detection Framework (Valid Only + Save Results)")
print("------------------------------------------")
print(" Gunakan hanya untuk pengujian legal / lab")
print("------------------------------------------")

target_url = input("[?] Masukkan URL target: ").strip()
params = input("[?] Masukkan parameter yang ingin diuji (pisahkan dengan koma): ").strip().split(",")
payload_input = input("[?] Masukkan payload (pisahkan dengan koma atau nama file payload.txt): ").strip()

payloads = []
if payload_input.lower().endswith(".txt") or payload_input.lower() == "file":
    filename = payload_input if payload_input.lower().endswith(".txt") else "payload.txt"
    if not os.path.exists(filename):
        print(f"[!] File {filename} tidak ditemukan.")
        sys.exit(1)
    with open(filename, "r") as f:
        payloads = [p.strip() for p in f.readlines() if p.strip()]
    print(f"[+] {len(payloads)} payload berhasil dimuat dari {filename}")
else:
    payloads = [p.strip() for p in payload_input.split(",") if p.strip()]

# File hasil
results_file = "results.txt"
open(results_file, "w").close()  # Kosongkan dulu

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
]

# Signature error SQL yang umum
error_signatures = [
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "mysql_fetch",
    "syntax error",
    "warning: mysql",
    "pg_query",
    "sqlstate",
    "odbc_exec",
    "fatal error",
    "sqlite3",
    "unknown column"
]

print("[+] Mulai scanning...\n")

for param in params:
    print(f"[*] Menguji parameter: {param}")
    for payload in payloads:
        try:
            parsed = urllib.parse.urlparse(target_url)
            query = dict(urllib.parse.parse_qsl(parsed.query))
            query[param] = payload
            new_query = urllib.parse.urlencode(query)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

            headers = {"User-Agent": random.choice(user_agents)}
            response = None
            for attempt in range(3):
                try:
                    response = requests.get(test_url, headers=headers, timeout=20, verify=True)
                    break
                except requests.exceptions.RequestException:
                    time.sleep(random.uniform(1.0, 2.5))
                    continue

            if not response:
                continue

            body = response.text.lower()
            if any(err in body for err in error_signatures):
                print(f"[!!] VALID SQL INJECTION ditemukan:")
                print(f"     ➤ URL     : {test_url}")
                print(f"     ➤ PAYLOAD : {payload}\n")

                # Simpan ke results.txt
                with open(results_file, "a") as f:
                    f.write(f"[VALID SQLi]\nURL: {test_url}\nPAYLOAD: {payload}\n\n")

            time.sleep(random.uniform(0.5, 1.5))

        except KeyboardInterrupt:
            print("\n[!] Dihentikan oleh pengguna.")
            sys.exit(0)
        except Exception as e:
            print(f"[ERR] Terjadi kesalahan: {e}")

print(f"[✓] Selesai scanning. Hasil tersimpan di: {results_file}")
