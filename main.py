import requests, base64, json, socket, time, os, ssl, random, re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor

SOURCES = [
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/protocols/vless",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/protocols/trojan",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
]

FALLBACK_CLEAN_IPS = ["104.16.132.229", "172.64.150.10", "www.visa.com"]
global_clean_ips = []

def get_fresh_ips():
    try:
        resp = requests.get("https://raw.githubusercontent.com/vfarid/cf-ip-scanner/main/ipv4.txt", timeout=10).text
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp)
        return list(ips) if ips else FALLBACK_CLEAN_IPS
    except: return FALLBACK_CLEAN_IPS

def check_tls_connection(host, port):
    try:
        context = ssl.create_default_context()
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock: return True
    except: return False

def optimize_link(conf):
    try:
        parsed = urlparse(conf)
        if parsed.scheme not in ["vless", "trojan"]: return None
        user_info, host_port = parsed.netloc.split("@")
        original_host, port = host_port.split(":")
        clean_ip = random.choice(global_clean_ips)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        params.update({'sni': original_host, 'host': original_host, 'fp': 'chrome', 'alpn': 'h2,http/1.1'})
        new_query = urlencode(params)
        return f"{parsed.scheme}://{user_info}@{clean_ip}:{port}?{new_query}#Rpix_Clean", original_host, int(port)
    except: return None

def process_config(conf):
    res = optimize_link(conf)
    if res and check_tls_connection(res[1], res[2]): return res[0]
    return None

def main():
    global global_clean_ips
    global_clean_ips = get_fresh_ips()
    raw_configs = set()
    for url in SOURCES:
        try:
            res = requests.get(url, timeout=10).text
            if "://" not in res[:50]: res = base64.b64decode(res).decode('utf-8', 'ignore')
            raw_configs.update([l for l in res.splitlines() if l.startswith(("vless://", "trojan://"))])
        except: continue
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(filter(None, executor.map(process_config, list(raw_configs))))
    os.makedirs("export", exist_ok=True)
    with open("export/sub.txt", "w", encoding="utf-8") as f: f.write("\n".join(results[:100]))
    with open("export/sub_b64.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(results[:100]).encode()).decode())

if __name__ == "__main__":
    main()
