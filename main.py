import requests
import base64
import socket
import ssl
import random
import re
import os
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor

# منابع کانفیگ
SOURCES = [
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/protocols/vless",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/protocols/trojan",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless"
]

# آی‌پی‌های زاپاس
FALLBACK_CLEAN_IPS = ["104.16.132.229", "172.64.150.10", "104.17.147.222"]
global_clean_ips = []

def get_fresh_ips():
    """دریافت آی‌پی‌های تمیز از گیت‌هاب"""
    try:
        resp = requests.get("https://raw.githubusercontent.com/vfarid/cf-ip-scanner/main/ipv4.txt", timeout=10).text
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp)
        return list(set(ips)) if ips else FALLBACK_CLEAN_IPS
    except:
        return FALLBACK_CLEAN_IPS

def check_connection(ip, port, sni):
    """تست اتصال SSL به سرور"""
    try:
        context = ssl._create_unverified_context()
        with socket.create_connection((ip, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                return True
    except:
        return False

def process_config(conf):
    """پردازش و اصلاح هر کانفیگ"""
    try:
        parsed = urlparse(conf)
        if parsed.scheme not in ["vless", "trojan"]:
            return None
        
        # استخراج اطلاعات کاربر و هاست
        if "@" not in parsed.netloc:
            return None
            
        user_info, host_port = parsed.netloc.split("@", 1)
        
        # مدیریت صحیح پورت (جلوگیری از خطا اگر پورت نباشد یا IPv6 باشد)
        if ":" in host_port:
            original_host, port = host_port.rsplit(":", 1)
            if not port.isdigit(): # اگر پورت عدد نبود
                return None
        else:
            original_host = host_port
            port = "443" # پورت پیش‌فرض

        # انتخاب آی‌پی تمیز
        clean_ip = random.choice(global_clean_ips)
        
        # پارس کردن پارامترها
        query = parse_qs(parsed.query)
        params = {k: v[0] for k, v in query.items()}
        
        # نکته مهم: فقط کانفیگ‌های وب‌سوکت یا GRPC معمولا پشت CDN هستند
        # اگر بخواهیم دقیق‌تر باشیم باید نوع تایپ را چک کنیم، اما فعلا طبق کد اصلی پیش می‌رویم
        
        params.update({
            'sni': original_host,
            'host': original_host,
            'fp': 'chrome'
        })
        
        new_query = urlencode(params)
        
        # تست اتصال با آی‌پی تمیز
        if check_connection(clean_ip, int(port), original_host):
            # ساخت لینک جدید
            final_link = f"{parsed.scheme}://{user_info}@{clean_ip}:{port}?{new_query}#{original_host}_Clean"
            return final_link
            
    except Exception as e:
        # در صورت بروز هرگونه خطا در پردازش، این کانفیگ رد می‌شود
        pass
        
    return None

def main():
    global global_clean_ips
    print("--- Starting Config Collector ---")
    
    # 1. دریافت آی‌پی‌های تمیز
    global_clean_ips = get_fresh_ips()
    print(f"Clean IPs found: {len(global_clean_ips)}")
    
    raw_configs = set()
    
    # 2. دانلود کانفیگ‌ها از منابع
    for url in SOURCES:
        try:
            print(f"Fetching: {url}")
            res = requests.get(url, timeout=10).text
            
            # تلاش برای دیکود کردن اگر بیس64 باشد
            if "vless://" not in res and "trojan://" not in res:
                try:
                    res = base64.b64decode(res).decode('utf-8', 'ignore')
                except:
                    pass
            
            # استخراج لینک‌ها با رجکس
            links = re.findall(r'(?:vless|trojan)://[^\s|#|\"|\']+', res)
            raw_configs.update(links)
        except Exception as e:
            print(f"Error fetching {url}: {e}")

    print(f"Total raw configs extracted: {len(raw_configs)}")
    
    # 3. پردازش و تست کانفیگ‌ها (با 50 ترد همزمان)
    valid_configs = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(process_config, list(raw_configs))
        valid_configs = [r for r in results if r is not None]

    # سوپاپ اطمینان
    if not valid_configs and raw_configs:
        print("No working clean configs found. Using raw fallback.")
        valid_configs = list(raw_configs)[:20]

    # 4. ذخیره خروجی
    os.makedirs("export", exist_ok=True)
    
    output_string = "\n".join(valid_configs)
    
    with open("export/sub.txt", "w", encoding="utf-8") as f:
        f.write(output_string)
        
    with open("export/sub_b64.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(output_string.encode()).decode())
    
    print(f"Finished. Saved {len(valid_configs)} configs to export/ folder.")

if __name__ == "__main__":
    main()
