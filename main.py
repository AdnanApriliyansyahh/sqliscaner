import requests
import urllib.parse
import os

print("------------------------------------------")
print(" SQL Injection Detection Framework (Valid Only + Full URL)")
print("------------------------------------------")
print(" Gunakan hanya untuk pengujian legal / lab")
print("------------------------------------------")

url = input("[?] Masukkan URL target: ").strip()
params_input = input("[?] Masukkan parameter yang ingin diuji (pisahkan dengan koma): ").strip()
payload_input = input("[?] Masukkan payload (pisahkan dengan koma atau ketik 'file' untuk baca dari payload.txt): ").strip()

# --- Baca payload ---
payloads = []
if payload_input.lower() in ['file', 'payload.txt']:
    if os.path.exists("payload.txt"):
        with open("payload.txt", "r", encoding="utf-8") as f:
            payloads = [p.strip() for p in f if p.strip()]
        print(f"[+] {len(payloads)} payload berhasil dimuat dari payload.txt")
    else:
        print("[!] File payload.txt tidak ditemukan!")
        exit()
else:
    payloads = [p.strip() for p in payload_input.split(",") if p.strip()]

# --- Parameter ---
params = [p.strip() for p in params_input.split(",") if p.strip()]

print("\n[+] Mulai scanning...\n")

# --- Fungsi deteksi SQL Injection valid ---
def is_valid_sql_injection(response_text):
    sqli_signatures = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "sql syntax error",
        "mysql_fetch_array()",
        "pg_query():",
        "sqlstate",
        "sql error",
        "sqlite error",
        "microsoft odbc sql server",
        "ora-00933",
        "ora-01756",
        "fatal error",
        "unknown column",
        "unterminated string constant",
        "invalid query"
    ]
    response_text_lower = response_text.lower()
    for sig in sqli_signatures:
        if sig in response_text_lower:
            return True
    return False


# --- Loop utama ---
found_vuln = False
for param in params:
    print(f"[*] Menguji parameter: {param}")
    for payload in payloads:
        parsed = urllib.parse.urlparse(url)
        query = dict(urllib.parse.parse_qsl(parsed.query))
        query[param] = payload
        test_url = parsed._replace(query=urllib.parse.urlencode(query)).geturl()

        try:
            r = requests.get(test_url, timeout=10)
            if is_valid_sql_injection(r.text):
                found_vuln = True
                print(f"[🔥 VALID SQLi] {test_url}")
                with open("results.txt", "a", encoding="utf-8") as f:
                    f.write(f"VALID SQLi FOUND: {test_url}\n")
        except Exception as e:
            print(f"[ERR] Gagal menguji payload {payload}: {e}")

if not found_vuln:
    print("\n[OK] Tidak ditemukan SQL Injection yang valid.")
else:
    print("\n[✓] Selesai scanning.")
    print("[📄] Hasil disimpan di results.txt (full URL valid SQLi saja)")
