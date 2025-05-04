import re
import time
import requests
import json
import schedule
import threading
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from dotenv import load_dotenv
import os

# === KONFIGURASI ===
load_dotenv()  # Load variables from .env file
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") 
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
log_path = "/var/log/apache2/access.log"
report_path = "report.json"

# === POLA SERANGAN ===
attack_patterns = [
    {"pattern": r"(GET|POST|HEAD) /(\.env|\.git|\.DS_Store)", "category": "Reconnaissance", "level": "Medium"},
    {"pattern": r"/(wp-content|wp-login|wp-admin)", "category": "WordPress Scan", "level": "Medium"},
    {"pattern": r"/(shell\?|cmd=|exec|passthru|system|wget|chmod)", "category": "Command Injection", "level": "High"},
    {"pattern": r"/(backup|old|main|home|bc|bk|new)", "category": "Directory Scan", "level": "Low"},
    {"pattern": r"\.\./\.\./\.\./etc/passwd", "category": "Path Traversal", "level": "High"},
    {"pattern": r"wp-config\.php", "category": "Sensitive File Access", "level": "Critical"},
    {"pattern": r"Mozi\.a", "category": "Malware Delivery (Mozi Botnet)", "level": "Critical"},
    {"pattern": r"POST /wls-wsat/CoordinatorPortType", "category": "RCE Attempt", "level": "Critical"},
    {"pattern": r"/zabbix\.php", "category": "Zabbix Exploit Attempt", "level": "High"},
]

# === COUNTER ===
threat_count = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
recon_count = 0
latest_evidence = None

# === AI Model Setup ===
def train_isolation_forest(data):
    if len(data) < 10:
        return None

    le = LabelEncoder()
    df = pd.DataFrame(data)
    df['method'] = le.fit_transform(df['method'])
    df['url'] = le.fit_transform(df['url'])
    df['ip'] = le.fit_transform(df['ip'])

    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(df[['method', 'url', 'ip']])
    return model, le

log_buffer = []

def parse_log_line(line):
    match = re.match(r'^(\S+) - - \[(.*?)\] "(\S+) (.*?) HTTP', line)
    if match:
        ip, timestamp, method, url = match.groups()
        return {
            "ip": ip,
            "timestamp": timestamp,
            "method": method,
            "url": url
        }
    return None

def classify_log_line(log_line):
    for attack in attack_patterns:
        if re.search(attack["pattern"], log_line):
            return {
                "matched": True,
                "category": attack["category"],
                "level": attack["level"],
                "timestamp": datetime.now(),
                "evidence": log_line.strip()
            }
    return {"matched": False}

def send_telegram_notification(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, json=payload)
    except Exception as e:
        print(f"[!] Gagal mengirim ke Telegram: {e}")

def format_alert(entry, is_ai=False):
    title = "🤖 *AI Deteksi Anomali!*" if is_ai else "🚨 *Ancaman Terdeteksi!*"
    return (
        f"{title}\n"
        f"Level: *{entry.get('level', 'AI-Detected')}*\n"
        f"Kategori: {entry.get('category', 'Anomaly')}\n"
        f"Waktu: {entry['timestamp']}\n"
        f"Evidence:\n`{entry['evidence']}`"
    )

def monitor_log():
    global threat_count, recon_count, latest_evidence, log_buffer

    model, encoder = None, None
    data_for_ai = []

    try:
        with open(log_path, "r") as f:
            f.seek(0, 2)  # baca dari akhir
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue

                result = classify_log_line(line)
                parsed = parse_log_line(line)
                if parsed:
                    data_for_ai.append(parsed)
                    if len(data_for_ai) >= 50:
                        model, encoder = train_isolation_forest(data_for_ai)
                        data_for_ai = []

                    if model and encoder:
                        df_pred = pd.DataFrame([parsed])
                        df_pred['method'] = encoder.transform([parsed['method']])
                        df_pred['url'] = encoder.transform([parsed['url']])
                        df_pred['ip'] = encoder.transform([parsed['ip']])
                        pred = model.predict(df_pred[['method', 'url', 'ip']])
                        if pred[0] == -1:
                            parsed['timestamp'] = datetime.now()
                            parsed['evidence'] = line.strip()
                            send_telegram_notification(format_alert(parsed, is_ai=True))

                if result["matched"]:
                    level = result["level"]
                    threat_count[level] += 1
                    latest_evidence = result["evidence"]
                    if result["category"] == "Reconnaissance":
                        recon_count += 1
                    send_telegram_notification(format_alert(result))

    except KeyboardInterrupt:
        print("\n[!] Monitoring dihentikan oleh pengguna.")
    except FileNotFoundError:
        print(f"[!] File log tidak ditemukan: {log_path}")

def daily_report():
    global threat_count, recon_count, latest_evidence

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = {
        "date": now,
        "threats": threat_count,
        "reconnaissance": recon_count,
        "latest_evidence": latest_evidence
    }

    # Menyimpan laporan ke file JSON
    with open(report_path, "w") as report_file:
        json.dump(report, report_file, indent=4)

    # Mengirim laporan harian ke Telegram
    telegram_message = (
        f"📊 *Laporan Harian Serangan*\n"
        f"Tanggal: {now}\n\n"
        f"🛡 Ancaman:\n"
        f"  - Low: {threat_count['Low']}\n"
        f"  - Medium: {threat_count['Medium']}\n"
        f"  - High: {threat_count['High']}\n"
        f"  - Critical: {threat_count['Critical']}\n"
        f"🔍 Scanning/Recon: {recon_count}\n\n"
        f"📁 Evidence Terbaru:\n`{latest_evidence}`"
    )
    send_telegram_notification(telegram_message)

    # Reset counter untuk hari berikutnya
    threat_count.update({"Low": 0, "Medium": 0, "High": 0, "Critical": 0})
    recon_count = 0
    latest_evidence = None

# Jadwal harian
schedule.every().day.at("08:00").do(daily_report)

if __name__ == "__main__":
    print("[*] Monitoring log dengan AI dimulai...")
    t = threading.Thread(target=monitor_log, daemon=True)
    t.start()

    while True:
        schedule.run_pending()
        time.sleep(1)
