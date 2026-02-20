import requests, base64, socket, ssl, random, re, os
from urllib.parse import urlparse, parse_qs, urlencode, unquote, quote
from concurrent.futures import ThreadPoolExecutor

# تنظیمات اصلی
TARGET_COUNT = 50
TIMEOUT = 2.0 
EXPORT_DIR = "export"

# منابع معتبر
SOURCES = [
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/IranianCypherpunks/sub/main/config",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/master/result/nodes",
    "https://raw.githubusercontent.com/Saman_Nirumand/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/Saman_Nirumand/V2ray-Configs/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/yebekhe/TV2Ray/main/sub/configs"
]

CLEAN_IPS = ["104.16.1.1", "104.17.1.1", "104.18.1.1", "104.19.1.1"]

def decode_base64_if_needed(content):
    try:
        content = content.strip()
        if "://" in content:
            return content
        return base64.b64decode(content + '=' * (-len(content) % 4)).decode('utf-8', errors='ignore')
    except:
        return content

def check_connection(target_ip, port, sni):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target_ip, int(port)), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock: 
                return True
    except:
        return False

def process_config(conf, index):
    try:
        conf = unquote(conf).strip()
        parsed = urlparse(conf)
        if parsed.scheme not in ['vless', 'trojan']: return None
        
        if "@" not in parsed.netloc: return None
        user_info, host_port = parsed.netloc.split("@", 1)
        original_address, port = host_port.rsplit(":", 1) if ":" in host_port else (host_port, "443")
        
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        actual_sni = params.get('sni', params.get('host', original_address))
        clean_ip = random.choice(CLEAN_IPS)
        
        if check_connection(clean_ip, port, actual_sni):
            params.update({'sni': actual_sni, 'host': actual_sni})
            query_str = urlencode(params)
            is_reality = "reality" in conf.lower() or params.get('security') == 'reality'
            tag = "Reality" if is_reality else "Safe"
            remark = quote(f"🚀_IRPX_{tag}_{index}")
            return f"{parsed.scheme}://{user_info}@{clean_ip}:{port}?{query_str}#{remark}"
    except: pass
    return None

def main():
    try:
        if not os.path.exists(EXPORT_DIR): os.makedirs(EXPORT_DIR)
        all_raw = set()
        for s in SOURCES:
            try:
                res = requests.get(s, timeout=15).text
                decoded = decode_base64_if_needed(res)
                found = re.findall(r'(?:vless|trojan)://[^\s#\x00-\x1f]+', decoded)
                all_raw.update(found)
            except: continue
        
        if not all_raw: return False
        
        raw_list = list(all_raw)
        random.shuffle(raw_list)
        reality_raw = [c for c in raw_list if "reality" in c.lower()]
        others_raw = [c for c in raw_list if "reality" not in c.lower()]
        sorted_raw = reality_raw + others_raw
        
        final_results = []
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(process_config, conf, i+1) for i, conf in enumerate(sorted_raw[:800])]
            for future in futures:
                res = future.result()
                if res:
                    final_results.append(res)
                    if len(final_results) >= TARGET_COUNT: break

        if not final_results: return False
            
        final_str = "\n".join(final_results)
        b64_content = base64.b64encode(final_str.encode('utf-8')).decode('utf-8')
        
        with open(os.path.join(EXPORT_DIR, "sub.txt"), "w", encoding="utf-8") as f: f.write(final_str)
        with open(os.path.join(EXPORT_DIR, "sub_b64.txt"), "w", encoding="utf-8") as f: f.write(b64_content)
        with open("count.txt", "w") as f: f.write(str(len(final_results)))
        return True
    except: return False

if __name__ == "__main__":
    success = main()
    if os.environ.get('GITHUB_ACTIONS'):
        exit(0 if success else 1)
