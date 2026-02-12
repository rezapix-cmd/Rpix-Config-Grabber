import requests
import base64
import socket
import ssl
import random
import re
import os
from urllib.parse import urlparse, parse_qs, urlencode, unquote
from concurrent.futures import ThreadPoolExecutor

# --- تنظیمات و منابع ---
SOURCES = [
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/protocols/vless",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/protocols/trojan",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity"
]

# آی‌پی‌های تمیز اضطراری (اگر لیست آنلاین لود نشد)
FALLBACK_CLEAN_IPS = ["104.16.132.229", "172.64.150.10", "104.17.147.222", "198.41.203.1"]
global_clean_ips = []

def get_fresh_ips():
    """دریافت آی‌پی‌های تمیز کلادفلر از مخازن معتبر"""
    print("[-] در حال دریافت آی‌پی‌های تمیز...")
    try:
        # استفاده از لیست‌های معتبر اسکن شده
        urls = [
            "https://raw.githubusercontent.com/vfarid/cf-ip-scanner/main/ipv4.txt",
            "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/ips/clean"
        ]
        all_ips = []
        for url in urls:
            try:
                resp = requests.get(url, timeout=5).text
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp)
                all_ips.extend(ips)
            except: continue
            
        return list(set(all_ips)) if all_ips else FALLBACK_CLEAN_IPS
    except:
        return FALLBACK_CLEAN_IPS

def check_connection(target_ip, port, sni, timeout=2):
    """
    تست اتصال هوشمند.
    تلاش می‌کند با SNI مشخص شده به سرور هندشیک SSL بزند.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # ایجاد سوکت خام
        with socket.create_connection((target_ip, int(port)), timeout=timeout) as sock:
            # تلاش برای بستن سوکت در لایه SSL با SNI
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                return True
    except:
        return False

def process_config(conf):
    """
    پردازش هوشمند کانفیگ:
    ۱. اگر Reality باشد -> آی‌پی را عوض نمی‌کند، فقط تست می‌کند.
    ۲. اگر CDN باشد -> آی‌پی را به آی‌پی تمیز تغییر می‌دهد و تست می‌کند.
    """
    try:
        # دیکود کردن URL برای جلوگیری از خرابی کاراکترها
        conf = unquote(conf)
        parsed = urlparse(conf)
        
        if parsed.scheme not in ["vless", "trojan"]:
            return None
        
        # استخراج آدرس و پورت اصلی
        if "@" not in parsed.netloc: return None
        user_info, host_port = parsed.netloc.split("@", 1)
        
        if ":" in host_port:
            original_address, port = host_port.rsplit(":", 1)
        else:
            original_address = host_port
            port = "443"
            
        if not port.isdigit(): return None
        
        # پارس کردن پارامترها
        query_params = parse_qs(parsed.query)
        params = {k: v[0] for k, v in query_params.items()}
        
        # تشخیص نوع امنیت (TLS/Reality/None)
        security = params.get('security', '')
        net_type = params.get('type', 'tcp')
        sni = params.get('sni', original_address)
        
        # --- استراتژی ۱: کانفیگ‌های Reality یا مستقیم ---
        # این‌ها نباید تغییر آی‌پی داشته باشند چون به سرور خاصی وصل هستند
        if security == 'reality' or (net_type == 'tcp' and security != 'tls'):
            if check_connection(original_address, port, sni):
                # برگرداندن کانفیگ اصلی بدون تغییر (چون سالم است)
                return conf + "#Direct_Tested"
        
        # --- استراتژی ۲: کانفیگ‌های CDN (WebSocket / GRPC) ---
        # این‌ها را می‌توانیم با آی‌پی تمیز ترکیب کنیم
        elif net_type in ['ws', 'grpc'] or security == 'tls':
            # انتخاب آی‌پی تمیز تصادفی
            clean_ip = random.choice(global_clean_ips)
            
            # تنظیم پارامترها برای اتصال به آی‌پی تمیز
            # هاست اصلی باید در SNI و Host Header قرار بگیرد
            params['sni'] = original_address
            params['host'] = original_address
            if 'fp' not in params: params['fp'] = 'chrome'
            
            # ساخت کوئری جدید
            new_query = urlencode(params)
            
            # تست اتصال: وصل شدن به Clean IP اما درخواست SNI سرور اصلی
            if check_connection(clean_ip, port, original_address):
                # ساخت لینک نهایی
                final_link = f"{parsed.scheme}://{user_info}@{clean_ip}:{port}?{new_query}#{original_address}_CleanIP"
                return final_link

    except Exception:
        pass
    
    return None

def main():
    global global_clean_ips
    print("--- شروع عملیات اسکنر پیشرفته ---")
    
    # ۱. آپدیت لیست آی‌پی‌های تمیز
    global_clean_ips = get_fresh_ips()
    print(f"[+] تعداد آی‌پی تمیز یافت شده: {len(global_clean_ips)}")
    
    raw_configs = set()
    
    # ۲. دانلود کانفیگ‌ها
    with requests.Session() as session:
        for url in SOURCES:
            try:
                print(f"[*] در حال دانلود از: {url}")
                resp = session.get(url, timeout=10).text
                
                # دیکود بیس۶۴ احتمالی
                content = resp
                if "://" not in resp[:20]:
                    try:
                        content = base64.b64decode(resp).decode('utf-8', 'ignore')
                    except: pass
                
                # استخراج لینک‌ها با رجکس دقیق
                links = re.findall(r'(?:vless|trojan)://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', content)
                raw_configs.update(links)
            except Exception as e:
                print(f"[!] خطا در دریافت منبع: {e}")

    print(f"[+] مجموع کانفیگ‌های خام: {len(raw_configs)}")
    
    # ۳. تست و پردازش (مولتی ترد)
    valid_configs = []
    # تعداد تردها را بر اساس توان سیستم تنظیم کنید (۵۰ عدد مناسب است)
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(process_config, list(raw_configs)))
        # حذف مقادیر None
        valid_configs = [r for r in results if r]

    # ۴. ذخیره‌سازی
    output_dir = "export"
    os.makedirs(output_dir, exist_ok=True)
    
    # حذف تکراری‌ها
    unique_configs = list(set(valid_configs))
    
    # اگر هیچی پیدا نشد، برای جلوگیری از ارور سمت کلاینت، چندتا خام سالم می‌گذاریم
    if not unique_configs and raw_configs:
        print("[!] هیچ کانفیگ تمیزی ساخته نشد. استفاده از کانفیگ‌های خام.")
        unique_configs = list(raw_configs)[:10]

    final_str = "\n".join(unique_configs)
    
    # ذخیره فایل متنی
    with open(f"{output_dir}/sub.txt", "w", encoding="utf-8") as f:
        f.write(final_str)
        
    # ذخیره فایل بیس۶۴ (برای ایمپورت راحت در کلاینت‌ها)
    with open(f"{output_dir}/sub_b64.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(final_str.encode()).decode())
        
    print(f"\n[OK] تمام شد! {len(unique_configs)} کانفیگ سالم در پوشه export ذخیره شد.")

if __name__ == "__main__":
    main()
