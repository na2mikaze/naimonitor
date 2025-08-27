#!/bin/bash
# setup.sh - Installer untuk Naimonitor AI Security Monitoring
# Dibuat oleh BOS 😎

set -e

SERVICE_NAME="naimonitor"
INSTALL_DIR="/opt/$SERVICE_NAME"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
LOG_FILE="/var/log/$SERVICE_NAME.log"

echo "🚀 Mulai instalasi $SERVICE_NAME ..."

# Update & install dependency
echo "📦 Install dependency..."
sudo apt update -y
sudo apt install -y python3 python3-venv python3-pip git

# Pastikan folder ada
echo "📂 Membuat folder instalasi di $INSTALL_DIR..."
sudo mkdir -p $INSTALL_DIR
sudo chown -R $USER:$USER $INSTALL_DIR

# Copy semua file project ke INSTALL_DIR (kalau script ini dijalankan dari repo lokal)
echo "📑 Menyalin file project..."
cp -r ./* $INSTALL_DIR/

# Buat virtual environment
echo "🐍 Membuat Python virtual environment..."
python3 -m venv $VENV_DIR

# Aktifkan venv & install requirements
echo "📦 Install Python requirements..."
$VENV_DIR/bin/pip install --upgrade pip
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    $VENV_DIR/bin/pip install -r $INSTALL_DIR/requirements.txt
else
    echo "⚠️ Tidak ada requirements.txt, skip..."
fi

# Copy config contoh kalau belum ada
if [ ! -f "$INSTALL_DIR/config.json" ]; then
    echo "⚙️ Membuat config.json dari config.example.json..."
    cp $INSTALL_DIR/config.example.json $INSTALL_DIR/config.json
else
    echo "⚙️ config.json sudah ada, skip..."
fi

# Buat log file
if [ ! -f "$LOG_FILE" ]; then
    echo "📝 Membuat log file di $LOG_FILE..."
    sudo touch $LOG_FILE
    sudo chown $USER:$USER $LOG_FILE
fi

# Buat systemd service
echo "🛠️ Membuat systemd service..."
sudo tee $SERVICE_FILE > /dev/null <<EOL
[Unit]
Description=Naimonitor AI Security Monitoring
After=network.target

[Service]
ExecStart=$VENV_DIR/bin/python $INSTALL_DIR/naimonitor.py
ExecStop=/bin/kill -s TERM \$MAINPID
WorkingDirectory=$INSTALL_DIR
Restart=always
User=$USER
Group=$USER
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd & enable service
echo "🔄 Mengaktifkan service..."
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME
sudo systemctl restart $SERVICE_NAME

# Status
echo "✅ Instalasi selesai!"
echo ""
echo "👉 Cek status service dengan:"
echo "   sudo systemctl status $SERVICE_NAME"
echo ""
echo "👉 Lihat log realtime dengan:"
echo "   journalctl -fu $SERVICE_NAME"
echo ""
echo "👉 Lihat log khusus di file:"
echo "   tail -f $LOG_FILE"
echo ""
echo "👉 Hentikan service dengan:"
echo "   sudo systemctl stop $SERVICE_NAME"
echo ""
echo "👉 Restart service dengan:"
echo "   sudo systemctl restart $SERVICE_NAME"
