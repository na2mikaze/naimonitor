🛡️ Naimonitor

AI-Powered Security Monitoring Tool for Apache/Linux Servers

Naimonitor adalah tools keamanan server berbasis AI yang memantau log server (Apache2), mendeteksi aktivitas mencurigakan secara real-time, mengirimkan notifikasi ke Telegram, dan menghasilkan dashboard report modern dengan grafik interaktif.

✨ Fitur Utama

🔥 Monitoring Realtime log Apache2

🤖 Deteksi AI untuk aktivitas mencurigakan (brute-force, botnet, scanning, automation scripts)

📲 Notifikasi Telegram setiap ada aktivitas berbahaya

📊 Dashboard Report Modern (HTML + Chart + Filter Harian/Mingguan/Bulanan)

⏰ Laporan Harian Otomatis terkirim setiap jam 08:00 pagi

⚡ Systemd Service untuk auto-run setelah server boot

🔒 Tidak auto-block IP → hanya monitoring & alert

📦 Instalasi
1️⃣ Clone Repository
git clone https://github.com/username/naimonitor.git
cd naimonitor

2️⃣ Setup Virtual Environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

3️⃣ Konfigurasi

Copy file contoh konfigurasi:

cp config.example.json config.json


Edit config.json untuk menambahkan:

Token Bot Telegram

Chat ID Telegram

Path log Apache (misalnya /var/log/apache2/access.log)

▶️ Menjalankan
Jalankan Manual
python naimonitor.py

Jalankan Sebagai Service
sudo cp systemd/naimonitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable naimonitor
sudo systemctl start naimonitor


Cek status:

sudo systemctl status naimonitor

📊 Dashboard Report

Laporan otomatis tersimpan di:

/opt/naimonitor/report.html


Fitur Dashboard:

Grafik jumlah ancaman per level (Low, Medium, High, Critical)

Statistik scanning/reconnaissance

Evidence serangan terbaru

Filter tanggal (Harian / Mingguan / Bulanan)

🛡️ Contoh Alert Telegram

📌 Notifikasi Realtime:

🚨 [HIGH] Suspicious login attempt detected!
IP: 192.168.1.100
Time: 2025-08-20 08:45:12
Evidence: Multiple failed login requests


📌 Laporan Harian:

📊 Naimonitor Daily Report
Date: 2025-08-20
- Critical: 2
- High: 5
- Medium: 12
- Low: 23
- Reconnaissance: 8

🔧 Struktur Project
naimonitor/
├── naimonitor.py          # Main script AI monitoring
├── requirements.txt       # Dependencies
├── README.md              # Dokumentasi
├── LICENSE                # Lisensi
├── config.example.json    # Contoh konfigurasi
├── report.html            # Dashboard report
├── systemd/
│   └── naimonitor.service # File systemd service
├── docs/
│   └── usage.md           # Dokumentasi tambahan
└── setup.sh               # Script auto instalasi (opsional)

🤝 Kontribusi

Pull request sangat diterima. Untuk perubahan besar, silakan buka issue terlebih dahulu untuk mendiskusikan apa yang ingin Anda ubah.

📜 Lisensi

MIT License
 © 2025

⚡ Dibuat dengan ❤️ oleh Nana Irmanto
