import requests, base64, socket, ssl, random, re, os, time
from urllib.parse import urlparse, parse_qs, urlencode, unquote
from concurrent.futures import ThreadPoolExecutor

# تنظیمات اصلی
TARGET_COUNT = 50
EXPORT_DIR = "export"
SUB_FILE = f"{EXPORT_DIR}/sub.txt"
# منابع معتبر
SOURCES = [
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/protocols/vless",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/protocols/trojan",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity",
    "https://raw.githubusercontent.com/Lonewolf-sh/V2ray-Configs/main/All_Configs_Sub.txt"
]

def check_connection(target_ip, port, sni, timeout=1.5):
    try:
        context = ssl.create_default_context()
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection((target_ip, int(port)), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock: return True
    except: return False

def process_config(conf):
    try:
        conf = unquote(conf)
        parsed = urlparse(conf)
        user_info, host_port = parsed.netloc.split("@", 1)
        original_address, port = host_port.rsplit(":", 1) if ":" in host_port else (host_port, "443")
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        
        if params.get('security') == 'reality':
            if check_connection(original_address, port, params.get('sni', original_address)):
                return conf + "#⭐_Rpix_Direct"
        else:
            clean_ips = ["104.16.132.229", "172.64.150.10", "104.17.147.222"]
            clean_ip = random.choice(clean_ips)
            if check_connection(clean_ip, port, original_address):
                params.update({'sni': original_address, 'host': original_address})
                return f"{parsed.scheme}://{user_info}@{clean_ip}:{port}?{urlencode(params)}#🚀_Rpix_Clean"
    except: pass
    return None

def main():
    os.makedirs(EXPORT_DIR, exist_ok=True)
    raw_configs = set()
    for url in SOURCES:
        try:
            resp = requests.get(url, timeout=10).text
            raw_configs.update(re.findall(r'(?:vless|trojan)://[^\s]+', resp))
        except: continue

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(filter(None, executor.map(process_config, list(raw_configs))))

    final_str = "\n".join(results[:100])
    with open(SUB_FILE, "w", encoding="utf-8") as f: f.write(final_str)
    
    encoded = base64.b64encode(final_str.encode('utf-8')).decode('utf-8').replace("\n", "")
    with open(f"{EXPORT_DIR}/sub_ios.txt", "w") as f: f.write(encoded)
    
    # ثبت تعداد برای استفاده در اکشن (بسیار مهم)
    with open("count.txt", "w") as f: f.write(str(len(results)))

if __name__ == "__main__":
    main()
