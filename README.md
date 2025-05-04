# Naimonitor
Naimonitor adalah sebuah tools untuk memonitor serangan dan anomali pada server web Apache menggunakan teknologi kecerdasan buatan (AI). Tools ini dapat mendeteksi serangan seperti botnet, brute-force, dan eksploitasi kerentanannya, serta mengirimkan notifikasi melalui Telegram.

## Fitur Utama
- Mendeteksi ancaman dari log Apache seperti Reconnaissance, Command Injection, Path Traversal, dan lainnya.
- Menggunakan model AI (Isolation Forest) untuk mendeteksi anomali dari trafik yang tidak biasa.
- Mengirimkan notifikasi ke Telegram jika ancaman terdeteksi.
- Menyediakan laporan serangan dalam bentuk real-time melalui `naireport.html`.
- Melakukan update laporan harian secara otomatis.

## Instalasi

### 1. Clone Repository
Clone repository ini ke server Anda menggunakan Git:

```bash
git clone https://github.com/na2mikaze/naimonitor.git
cd naimonitor
