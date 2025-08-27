# 🛡️ NaiMonitor - AI-Powered Apache Security Monitoring Tool

NaiMonitor adalah tools open-source berbasis Artificial Intelligence (AI) yang dirancang untuk membantu administrator server dalam memantau keamanan server Apache secara real-time. NaiMonitor mampu mendeteksi aktivitas mencurigakan, memberikan notifikasi ke Telegram, serta menyajikan laporan interaktif melalui dashboard web modern.

## 🚀 Fitur Utama

- **Real-Time Monitoring**: Mendeteksi aktivitas mencurigakan secara langsung dari log Apache.
- **AI Threat Detection**: Analisis berbasis AI untuk mengidentifikasi pola serangan seperti botnet, brute-force, scanning, reconnaissance, hingga automation script.
- **Alert Notification** : Mengirim notifikasi otomatis ke Telegram ketika terdeteksi aktivitas berbahaya.
- **Daily Report**: Membuat laporan harian secara otomatis (HTML) dengan statistik serangan.
- **Interactive Dashboard**: Dashboard modern, responsif, dan real-time dengan grafik interaktif, termasuk filter laporan harian, mingguan, dan bulanan.
- **Evidence Tracking**: Menyimpan bukti log terbaru sesuai tanggal & waktu.
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

NaiMonitor dibuat oleh [Nana Namikaze]
GitHub: https://github.com/na2mikaze
