import requests, base64, socket, ssl, random, re, os, time
from urllib.parse import urlparse, parse_qs, urlencode, unquote
from concurrent.futures import ThreadPoolExecutor

# تنظیمات بهینه شده
TARGET_COUNT = 50
CLEAN_INTERVAL = 12 * 3600
EXPORT_DIR = "export"
SUB_FILE = f"{EXPORT_DIR}/sub.txt"
LOG_FILE = f"{EXPORT_DIR}/last_clean.txt"

SOURCES = [
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/protocols/vless",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/protocols/trojan",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity",
    "https://raw.githubusercontent.com/Lonewolf-sh/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/V2raySami/Sami-V2ray/main/Sub.txt"
]

FALLBACK_CLEAN_IPS = ["104.16.132.229", "172.64.150.10", "104.17.147.222"]

def get_fresh_ips():
    try:
        urls = ["https://raw.githubusercontent.com/vfarid/cf-ip-scanner/main/ipv4.txt", "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/ips/clean"]
        all_ips = []
        for url in urls:
            try:
                resp = requests.get(url, timeout=5).text
                all_ips.extend(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp))
            except: continue
        return list(set(all_ips)) if all_ips else FALLBACK_CLEAN_IPS
    except: return FALLBACK_CLEAN_IPS

# پینگ را روی 1.5 ثانیه گذاشتم تا فایل خالی نماند
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
        if parsed.scheme not in ["vless", "trojan"] or "@" not in parsed.netloc: return None
        user_info, host_port = parsed.netloc.split("@", 1)
        original_address, port = host_port.rsplit(":", 1) if ":" in host_port else (host_port, "443")
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        security, net_type, sni = params.get('security', ''), params.get('type', 'tcp'), params.get('sni', original_address)
        
        if security == 'reality':
            if check_connection(original_address, port, sni):
                return conf + f"#⭐_Rpix_Reality"
        elif net_type in ['ws', 'grpc'] or security == 'tls':
            clean_ip = random.choice(global_clean_ips)
            if check_connection(clean_ip, port, original_address):
                params.update({'sni': original_address, 'host': original_address, 'fp': 'chrome'})
                return f"{parsed.scheme}://{user_info}@{clean_ip}:{port}?{urlencode(params)}#🚀_Rpix_Clean"
    except: pass
    return None

def main():
    global global_clean_ips
    os.makedirs(EXPORT_DIR, exist_ok=True)
    current_time = time.time()
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                if current_time - float(f.read().strip()) > CLEAN_INTERVAL:
                    if os.path.exists(SUB_FILE): os.remove(SUB_FILE)
            except: pass
    with open(LOG_FILE, "w") as f: f.write(str(current_time))

    prev_configs = []
    if os.path.exists(SUB_FILE):
        with open(SUB_FILE, "r", encoding="utf-8") as f: prev_configs = f.read().splitlines()

    global_clean_ips = get_fresh_ips()
    raw_configs = set()
    with requests.Session() as session:
        for url in SOURCES:
            try:
                resp = session.get(url, timeout=10).text
                content = base64.b64decode(resp).decode('utf-8','ignore') if "://" not in resp[:20] else resp
                raw_configs.update(re.findall(r'(?:vless|trojan)://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', content))
            except: continue

    with ThreadPoolExecutor(max_workers=100) as executor:
        new_results = list(filter(None, executor.map(process_config, list(raw_configs))))

    final_list = list(set(prev_configs + new_results))
    final_configs_str = "\n".join(final_list[:100]).strip()
    
    with open(SUB_FILE, "w", encoding="utf-8") as f: f.write(final_configs_str)
    
    encoded_data = base64.b64encode(final_configs_str.encode('utf-8')).decode('utf-8') if final_configs_str else ""
    for fname in ["sub_b64.txt", "sub_ios.txt"]:
        with open(f"{EXPORT_DIR}/{fname}", "w", encoding="utf-8") as f: f.write(encoded_data)

    with open("count.txt", "w") as f: f.write(str(len(final_list)))

if __name__ == "__main__":
    main()
