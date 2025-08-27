# 🛡️ NaiMonitor - AI-Powered Apache Security Monitoring Tool

NaiMonitor adalah tools open-source berbasis Artificial Intelligence (AI) yang dirancang untuk membantu administrator server dalam memantau keamanan server Apache secara real-time. NaiMonitor mampu mendeteksi aktivitas mencurigakan, memberikan notifikasi ke Telegram, serta menyajikan laporan interaktif melalui dashboard web modern.

## 🚀 Fitur Utama

- **Real-Time Monitoring**: Memantau log Apache secara langsung dan mendeteksi aktivitas mencurigakan secara cepat.
- **AI Threat Detection**: Analisis berbasis AI untuk mengenali pola serangan seperti brute-force, botnet, scanning, reconnaissance, hingga automated attack scripts.
- **Instant Telegram Alerts**: Mengirimkan notifikasi real-time ke Telegram setiap kali ada aktivitas mencurigakan, lengkap dengan detail serangan.
- **Daily/Weekly/Monthly Reports**: Membuat laporan otomatis dalam format HTML setiap hari jam tertentu, serta bisa diakses via perintah Telegram /laporan (harian, mingguan, bulanan).
- **Evidence Tracking**: Menyimpan bukti log serangan terbaru lengkap dengan tanggal & waktu untuk kebutuhan audit dan investigasi.
- **Customizable**: Dapat disesuaikan dengan kebutuhan organisasi Anda.

## 📊 Monitoring Data
NaiMonitor menampilkan informasi berikut:
- Jumlah ancaman berdasarkan level (Low, Medium, High, Critical).
- Jumlah aksi scanning / reconnaissance.
- Bukti (evidence) log terbaru.
- Statistik serangan per hari, minggu, atau bulan.

## 🔧 Cara Menggunakan
#### 1. Clone Repositori ini
```bash
git clone https://github.com/na2mikaze/NaiMonitor.git
cd NaiMonitor
```

#### 2. Instalasi
Jalankan script instalasi:
```bash
chmod +x setup.sh
./setup.sh
```

#### 3. Menjalankan NaiMonitor
Setelah instalasi, jalankan:
```bash
python3 monitor.py
```
Atau jalankan sebagai service:
```bash
systemctl start naimonitor
```

## 🤝 Kontribusi

Kontribusi selalu terbuka!
Jika Anda ingin berkontribusi atau menambahkan fitur baru, silakan buka isu atau buat pull request.

## 📄 MIT License

NaiMonitor dilisensikan di bawah MIT License.

## ⚠️ Disclaimer

NaiMonitor adalah alat monitoring yang ditujukan untuk keamanan server Apache.
Harap gunakan hanya pada server milik sendiri atau yang Anda miliki izin eksplisit untuk dipantau.

Dengan menggunakan NaiMonitor, Anda setuju bahwa:
1. Anda bertanggung jawab penuh atas penggunaan alat ini.
2. Pengembang tidak bertanggung jawab atas kerusakan, kehilangan data, atau konsekuensi hukum dari penggunaannya.
3. Alat ini tidak dimaksudkan untuk peretasan atau serangan.
4. Gunakan hanya untuk tujuan legal dan etis.

---

## 👤 Pembuat

NaiMonitor dibuat oleh [Nana I]
GitHub: https://github.com/na2mikaze
