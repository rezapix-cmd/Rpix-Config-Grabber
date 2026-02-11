import requests
import base64
import json
import socket
import time
import os
import ssl
import random
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor

# منابع دریافت کانفیگ
SOURCES = [
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/protocols/vless",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/protocols/trojan",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
]

FALLBACK_CLEAN_IPS = ["104.16.132.229", "172.64.150.10", "www.visa.com"]
global_clean_ips = []

def get_fresh_ips():
    ip_urls = ["https://raw.githubusercontent.com/vfarid/cf-ip-scanner/main/ipv4.txt"]
    collected = set()
    for url in ip_urls:
        try:
            resp = requests.get(url, timeout=10).text
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp)
            collected.update(ips)
        except: continue
    return list(collected) if collected else FALLBACK_CLEAN_IPS

def check_tls_connection(host, port):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return True
    except: return False

def optimize_link(conf):
    try:
        parsed = urlparse(conf)
        if parsed.scheme not in ["vless", "trojan"]: return None
        if "@" not in parsed.netloc: return None
        
        user_info, host_port = parsed.netloc.split("@")
        original_host, port = host_port.split(":") if ":" in host_port else (None, None)
        if not original_host: return None

        clean_ip = random.choice(global_clean_ips)
        params = parse_qs(parsed.query)
        
        params['sni'] = [original_host]
        params['host'] = [original_host]
        params['fp'] = ['chrome']
        params['alpn'] = ['h2,http/1.1']
        
        if params.get('type', [''])[0] == 'ws' and parsed.path and parsed.path != "/":
            params['path'] = [parsed.path]

        new_netloc = f"{user_info}@{clean_ip}:{port}"
        return urlunparse((parsed.scheme, new_netloc, "/", "", urlencode(params, doseq=True), parsed.fragment)), original_host, int(port)
    except: return None

def process_config(conf):
    data = optimize_link(conf)
    if data and check_tls_connection(data[1], data[2]): return data[0]
    return None

def main():
    global global_clean_ips
    global_clean_ips = get_fresh_ips()
    raw_configs = set()
    for url in SOURCES:
        try:
            res = requests.get(url, timeout=10).text
            if "://" not in res[:50]: res = base64.b64decode(res).decode('utf-8', 'ignore')
            for line in res.splitlines():
                if line.startswith(("vless://", "trojan://")): raw_configs.add(line)
        except: continue

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(process_config, list(raw_configs)))
    
    final = [f"{c.split('#')[0]}#Rpix_Clean_{i}" for i, c in filter(None, enumerate(results))][:100]
    os.makedirs("export", exist_ok=True)
    with open("export/sub.txt", "w", encoding="utf-8") as f: f.write("\n".join(final))
    with open("export/sub_b64.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(final).encode()).decode())

if __name
