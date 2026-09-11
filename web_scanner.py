import requests
import sys

# Header keamanan yang wajib dianalisis
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

# Path file sensitif yang sering bocor
SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/phpinfo.php",
    "/robots.txt",
    "/config.json"
]

def scan_web_security(url):
    # Format URL agar memiliki skema http/https
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print("=" * 65)
    print(f"MOON Web Scanner (Hood_3) - Target: {url}")
    print("=" * 65)

    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        print(f"[+] Status HTTP: {response.status_code}")
        print(f"[+] Server Info: {response.headers.get('Server', 'Hidden / Unknown')}\n")
    except requests.exceptions.RequestException as e:
        print(f"[!] Gagal terhubung ke target: {e}")
        return

    # 1. Analisis Security Headers
    print("--- [ 1. Security Headers Analysis ] ---")
    headers_found = response.headers
    missing_headers = 0

    for header in SECURITY_HEADERS:
        if header in headers_found:
            print(f"[✓] {header:<30} : ADA")
        else:
            print(f"[✗] {header:<30} : TIDAK ADA (Risiko)")
            missing_headers += 1

    print(f"\nRingkasan Header: {len(SECURITY_HEADERS) - missing_headers}/{len(SECURITY_HEADERS)} header terpasang.")

    # 2. Scanning Kebocoran File Sensitif
    print("\n--- [ 2. Sensitive Files & Assets Exposure ] ---")
    base_url = url.rstrip("/")
    exposed_files = 0

    for path in SENSITIVE_PATHS:
        target_path = base_url + path
        try:
            res = requests.get(target_path, timeout=3, allow_redirects=False)
            if res.status_code == 200:
                print(f"[!] DITEMUKAN (EXPOSED) [200 OK] : {target_path}")
                exposed_files += 1
            else:
                print(f"[-] Aman [{res.status_code}]                : {path}")
        except requests.exceptions.RequestException:
            print(f"[!] Error saat memeriksa      : {path}")

    print("\n" + "=" * 65)
    print(f"Pemindaian Selesai! Riset Keamanan Selesai.")
    print("=" * 65)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else input("Masukkan URL Target (contoh: example.com): ")
    if target:
        scan_web_security(target)
    else:
        print("URL Target tidak boleh kosong.")
        