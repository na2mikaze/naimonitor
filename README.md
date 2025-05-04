
# 🛡️ Naimonitor - AI-based Apache Server Log Security Monitor

`Naimonitor` adalah tools monitoring keamanan server berbasis AI yang mendeteksi log mencurigakan pada Apache dan mengirimkan notifikasi real-time ke Telegram serta menampilkan dashboard `report.html` secara live. Tools ini open-source dan mudah diinstal di server Linux.

## 🚀 Fitur

- Deteksi pola serangan umum (WordPress scan, path traversal, command injection, dll)
- AI (Isolation Forest) untuk mendeteksi anomali akses otomatis
- Notifikasi real-time ke Telegram
- Dashboard HTML yang responsif (`naireport.html`)
- Laporan harian otomatis setiap jam 08.00
- Proteksi akses dashboard dengan username dan password

## 📦 Requirements

- Python 3.8+
- Apache2 (web server)
- Akses log: /var/log/apache2/access.log
- Linux/Ubuntu server
- Telegram Bot dan Chat ID

## 🔧 Instalasi Step-by-Step

### 1. Clone Repositori

```bash
cd /var/www/
sudo git clone https://github.com/na2mikaze/naimonitor.git
cd naimonitor
```

### 2. Buat dan Aktifkan Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependensi

```bash
pip install -r requirements.txt
```

### 4. Buat File `.env`

```bash
nano .env
```

Contoh isi:

```env
TELEGRAM_BOT_TOKEN=xxx
TELEGRAM_CHAT_ID=xxx
LOG_PATH=/var/log/apache2/access.log
```

### 5. Jalankan Tools Monitoring

```bash
python3 monitor.py
```

### 6. Salin `naireport.html` ke Apache Web Directory

```bash
sudo cp naireport.html /var/www/html/naireport.html
```

### 7. Proteksi Akses ke `naireport.html`

**a. Buat file password:**

```bash
sudo apt install apache2-utils -y
sudo htpasswd -c /etc/apache2/.htpasswd naimonitor
```
```Buar password baru
New password: password
Re-type new password: password
```

**b. Konfigurasi Apache:**

```bash
sudo nano /etc/apache2/sites-available/000-default.conf
```

Tambahkan dalam `<VirtualHost *:80>`:

```apacheconf
<Directory "/var/www/html">
    AllowOverride None
</Directory>

<Directory "/var/www/html/naireport.html">
    # Proteksi akses hanya untuk naireport.html
    AuthType Basic
    AuthName "Restricted Access"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
</Directory>

```

**c. Restart Apache:**

```bash
sudo systemctl restart apache2
```

## 🖥️ Akses Dashboard

Buka di browser:

```
http://your_server_ip/naireport.html
```

Login:

- Username: naimonitor1
- Password: password

## 🌀 Jalankan Otomatis Saat Reboot (Opsional)

```bash
crontab -e
```

Tambahkan:

```cron
@reboot cd /var/www/naimonitor && /usr/bin/python3 naimonitor.py
```

## 🔒 Keamanan

- File `.env` dan `.htpasswd` tidak boleh diakses publik
- Gunakan HTTPS untuk akses dashboard

## 🤝 Kontribusi

Pull Request dan Issue terbuka untuk pengembangan. Kamu juga bisa fork dan sesuaikan untuk keperluan lain.

## 📄 Lisensi

MIT License – bebas digunakan, dimodifikasi, dan dikembangkan selama mencantumkan credit kepada pembuat asli.

## ⚠️ Disclaimer

1. **Penggunaan dan Tanggung Jawab**:  
   `Naimonitor` dirancang untuk membantu dalam mendeteksi ancaman dan aktivitas mencurigakan pada server Apache. Namun, penggunaan alat ini sepenuhnya merupakan tanggung jawab pengguna. Kami tidak bertanggung jawab atas kerugian atau kerusakan yang terjadi akibat penggunaan alat ini.

2. **Keamanan dan Perlindungan Data**:  
   `Naimonitor` berfungsi untuk memonitor dan menganalisis log Apache. Meskipun kami berusaha keras untuk memastikan alat ini bekerja dengan aman dan efektif, pastikan untuk selalu mengonfigurasi sistem dengan bijak dan sesuai dengan kebijakan keamanan yang berlaku pada organisasi atau server Anda. Alat ini tidak dimaksudkan untuk menggantikan perangkat keamanan profesional.

3. **Privasi dan Akses Data**:  
   Selama penggunaan alat ini, data yang dikumpulkan melalui log Apache akan diproses. Pastikan untuk memahami bahwa data log tersebut dapat berisi informasi sensitif yang terkait dengan pengguna dan perangkat yang mengakses server Anda. Jangan biarkan file log atau informasi sensitif lainnya dapat diakses oleh pihak yang tidak berwenang.

4. **Lisensi dan Penggunaan Kode**:  
   Kode sumber `Naimonitor` dilisensikan di bawah **MIT License**, yang memungkinkan siapa saja untuk menggunakan, memodifikasi, dan mendistribusikan ulang alat ini. Meskipun demikian, kami mengingatkan pengguna untuk menggunakan alat ini sesuai dengan hukum dan peraturan yang berlaku, serta menjaga keamanan dan privasi data.

5. **Pembaruan dan Dukungan**:  
   Alat ini dikembangkan dan dipelihara oleh pengembang komunitas dan mungkin tidak menyediakan dukungan langsung atau pembaruan rutin. Kami menyarankan untuk selalu mengikuti pengembangan terbaru dan memverifikasi apakah alat ini sesuai dengan kebutuhan dan sistem Anda.


## 👤 Pembuat

Naimonitor dibuat oleh [Nana Namikaze]  
GitHub: https://github.com/na2mikaze
