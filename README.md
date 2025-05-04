🛡️ naimonitor - AI-based Apache Server Log Security Monitor
naimonitor adalah tools monitoring keamanan server berbasis AI yang mendeteksi log mencurigakan pada Apache dan mengirimkan notifikasi real-time ke Telegram serta menampilkan dashboard report.html secara live. Tools ini open-source dan mudah diinstal di server Linux.
🚀 Fitur
- Deteksi pola serangan umum (WordPress scan, path traversal, command injection, dll)
- AI (Isolation Forest) untuk mendeteksi anomali akses otomatis
- Notifikasi real-time ke Telegram
- Dashboard HTML yang responsif (report.html)
- Laporan harian otomatis setiap jam 08.00
- Proteksi akses dashboard dengan username dan password
📦 Requirements
- Python 3.8+
- Apache2 (web server)
- Akses log: /var/log/apache2/access.log
- Linux/Ubuntu server
- Telegram Bot dan Chat ID
🔧 Instalasi Step-by-Step
1. Clone Repositori
cd /var/www/
sudo git clone https://github.com/username/naimonitor.git
cd naimonitor
2. Buat dan Aktifkan Virtual Environment
python3 -m venv venv
source venv/bin/activate
3. Install Dependensi
pip install -r requirements.txt
4. Buat File .env
nano .env

Contoh isi:
TELEGRAM_BOT_TOKEN=xxx
TELEGRAM_CHAT_ID=xxx
LOG_PATH=/var/log/apache2/access.log
5. Jalankan Tools Monitoring
python3 monitor.py
6. Salin report.html ke Apache Web Directory
sudo cp report.html /var/www/html/monitoring.html
7. Proteksi Akses ke report.html
a. Buat file password:
sudo apt install apache2-utils -y
sudo htpasswd -c /etc/apache2/.htpasswd username

b. Konfigurasi Apache:
sudo nano /etc/apache2/sites-available/000-default.conf

Tambahkan dalam <VirtualHost *:80>:
<Directory "/var/www/html">
    AuthType Basic
    AuthName "Restricted Access"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
</Directory>

c. Restart Apache:
sudo systemctl restart apache2
🖥️ Akses Dashboard
Buka di browser:
http://your_server_ip/monitoring.html

Login:
- Username: username
- Password: password
🌀 Jalankan Otomatis Saat Reboot (Opsional)
crontab -e

Tambahkan:
@reboot cd /var/www/naimonitor && /usr/bin/python3 monitor.py
🔒 Keamanan
- File .env dan .htpasswd tidak boleh diakses publik
- Gunakan HTTPS untuk akses dashboard
- Jangan commit .env atau data sensitif ke GitHub (pakai .gitignore)
🤝 Kontribusi
Pull Request dan Issue terbuka untuk pengembangan. Kamu juga bisa fork dan sesuaikan untuk keperluan lain.
📄 Lisensi
MIT License – bebas digunakan, dimodifikasi, dan dikembangkan selama mencantumkan credit kepada pembuat asli.
👤 Pembuat
naimonitor dibuat oleh [Nama Kamu]
Telegram: @username
GitHub: https://github.com/username
