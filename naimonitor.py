#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import time
import json
import threading
from datetime import datetime, timedelta
import requests

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
from telegram.error import BadRequest

# ========== KONFIG ==========
LOG_SOURCES = [
    "/var/log/auth.log",               # SSH brute force
    "/var/log/nginx/access.log",       # Web access logs untuk SQLi/LFI/RCE
    # Tambahkan log lain sesuai kebutuhan
]
EVENTS_FILE = "/var/www/naimonitor/events.jsonl"

TELEGRAM_TOKEN = ""
CHAT_ID = 12345 #Contoh

ALERT_FLUSH_INTERVAL = 60
MAX_EVIDENCE_LINES = 10

# ========== REGEX DETEKSI ==========
RE_FAILED = re.compile(
    r"Failed password for (invalid user\s+)?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) .* ssh2",
    re.IGNORECASE,
)
RE_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
RE_SQLI = re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(\%22)|(\")|(\;)|(\%3D)", re.IGNORECASE)
RE_LFI = re.compile(r"(\.\./|\.\.\\)", re.IGNORECASE)
RE_RCE = re.compile(r"(system\(|exec\(|passthru\()", re.IGNORECASE)

# ========== STATE AGGREGATOR ==========
batch_lock = threading.Lock()
current_batch = {}

# ========== UTIL ==========
def ensure_paths():
    os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)
    if not os.path.exists(EVENTS_FILE):
        open(EVENTS_FILE, "a").close()

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def telegram_send_text(text: str):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={"chat_id": CHAT_ID, "text": text},
            timeout=10,
        )
    except Exception as e:
        print(f"[!] Telegram send error: {e}")

def write_event(event: dict):
    try:
        with open(EVENTS_FILE, "a") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[!] Gagal menulis events.jsonl: {e}")

def parse_line(line: str):
    """Return (attack_type, ip)"""
    # SSH brute force
    m = RE_FAILED.search(line)
    if m:
        return "Brute Force", m.group("ip")
    m = RE_INVALID.search(line)
    if m:
        return "Brute Force", m.group("ip")
    # SQL Injection
    if RE_SQLI.search(line):
        return "SQL Injection", "-"
    # Path Traversal / LFI
    if RE_LFI.search(line):
        return "LFI Attempt", "-"
    # Remote Code Execution
    if RE_RCE.search(line):
        return "RCE Attempt", "-"
    return None, None

def add_to_batch(attack_type: str, ip: str, evidence_line: str):
    key = (attack_type, ip)
    with batch_lock:
        data = current_batch.get(key, {"count": 0, "evidence": []})
        data["count"] += 1
        if len(data["evidence"]) < MAX_EVIDENCE_LINES:
            data["evidence"].append(evidence_line.strip())
        current_batch[key] = data

def flush_batch_and_send():
    with batch_lock:
        if not current_batch:
            return
        snapshot = current_batch.copy()
        current_batch.clear()

    total_threats = sum(v["count"] for v in snapshot.values())

    attack_lines = []
    for (atype, ip), v in sorted(snapshot.items(), key=lambda x: (-x[1]["count"], x[0][1])):
        attack_lines.append(f"- {atype} ({ip}): {v['count']}")

    evidences = []
    for (atype, ip), v in snapshot.items():
        for ev in v["evidence"]:
            evidences.append(f"- {ev} (Source: {ip})")
    evidences = evidences[:MAX_EVIDENCE_LINES]

    msg = (
        "🚨 Security Alert 🚨\n"
        f"📅 Date: {now_str()}\n\n"
        f"📁 Log Sources: {', '.join(LOG_SOURCES)}\n"
        f"🔹 Total Threats: {total_threats}\n\n"
        "🔍 Attack Types:\n"
        + ("\n".join(attack_lines) if attack_lines else "- (none)") + "\n\n"
        "📂 Evidence:\n"
        + ("\n".join(evidences) if evidences else "- (no evidence captured)")
    )

    telegram_send_text(msg)

def tail_log(log_source):
    """Thread tail log per file"""
    ensure_paths()
    telegram_send_text(f"🚀 Naimonitor AI Monitoring dimulai untuk {log_source} ...")

    if not os.path.exists(log_source):
        print(f"[!] {log_source} belum ada. Menunggu...")
        while not os.path.exists(log_source):
            time.sleep(5)

    with open(log_source, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            attack_type, ip = parse_line(line)
            if attack_type and ip:
                event = {
                    "timestamp": now_str(),
                    "source": log_source,
                    "attack_type": attack_type,
                    "ip": ip,
                    "evidence": line.strip(),
                }
                write_event(event)
                add_to_batch(attack_type, ip, line)

def batch_flusher():
    while True:
        time.sleep(ALERT_FLUSH_INTERVAL)
        try:
            flush_batch_and_send()
        except Exception as e:
            print(f"[!] Gagal flush batch: {e}")

# ========== LAPORAN PERIODIK ==========
def load_events(limit_lines: int | None = None):
    ensure_paths()
    events = []
    try:
        with open(EVENTS_FILE, "r") as f:
            lines = f.readlines()[-limit_lines:] if limit_lines else f.readlines()
        for ln in lines:
            ln = ln.strip()
            if ln:
                try:
                    events.append(json.loads(ln))
                except Exception:
                    continue
    except Exception as e:
        print(f"[!] Gagal baca events.jsonl: {e}")
    return events

def filter_events_by_period(period: str):
    now = datetime.now()
    events = load_events()
    def parse_ts(s: str):
        try:
            return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return now
    if period == "daily":
        return [e for e in events if parse_ts(e["timestamp"]).date() == now.date()]
    elif period == "weekly":
        cutoff = now - timedelta(days=7)
        return [e for e in events if parse_ts(e["timestamp"]) >= cutoff]
    elif period == "monthly":
        cutoff = now - timedelta(days=30)
        return [e for e in events if parse_ts(e["timestamp"]) >= cutoff]
    return []

def build_period_report(period: str):
    period_title = {
        "daily": "📊 Laporan Hari Ini",
        "weekly": "📅 Laporan Minggu Ini",
        "monthly": "🗓️ Laporan Bulan Ini",
    }.get(period, "📊 Laporan")

    evs = filter_events_by_period(period)
    total = len(evs)

    counts = {}
    for e in evs:
        key = (e.get("attack_type", "Unknown"), e.get("ip", "-"))
        counts[key] = counts.get(key, 0) + 1

    attack_lines = []
    for (atype, ip), cnt in sorted(counts.items(), key=lambda x: (-x[1], x[0][1])):
        attack_lines.append(f"- {atype} ({ip}): {cnt}")

    evidence_lines = []
    for e in evs[-MAX_EVIDENCE_LINES:]:
        evidence_lines.append(f"- {e.get('evidence','')[:300]} (Source: {e.get('ip','-')})")

    msg = (
        f"{period_title} ({total} insiden)\n\n"
        f"📁 Log Sources: {', '.join(LOG_SOURCES)}\n"
        f"🔹 Total Threats: {total}\n\n"
        "🔍 Attack Types:\n"
        + ("\n".join(attack_lines) if attack_lines else "- (none)") + "\n\n"
        "📂 Evidence:\n"
        + ("\n".join(evidence_lines) if evidence_lines else "- (no evidence)")
    )
    return msg

# ========== TELEGRAM BOT UTILS ==========
async def safe_edit_message(message, new_text=None, new_markup=None):
    try:
        if new_text is not None and new_text != message.text:
            await message.edit_text(new_text, reply_markup=new_markup)
        elif new_markup is not None and new_markup != message.reply_markup:
            await message.edit_reply_markup(new_markup)
    except BadRequest as e:
        if "Message is not modified" not in str(e):
            raise

# ========== TELEGRAM BOT ==========
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await show_menu(update)

async def cmd_laporan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await show_menu(update)

async def show_menu(update: Update):
    keyboard = [
        [InlineKeyboardButton("📊 Hari Ini", callback_data="daily")],
        [InlineKeyboardButton("📅 Minggu Ini", callback_data="weekly")],
        [InlineKeyboardButton("🗓️ Bulan Ini", callback_data="monthly")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    if update.message:
        await update.message.reply_text("Pilih laporan monitoring:", reply_markup=reply_markup)
    else:
        await update.effective_chat.send_message("Pilih laporan monitoring:", reply_markup=reply_markup)

async def cb_buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    period = query.data
    msg = build_period_report(period)

    keyboard = [
        [InlineKeyboardButton("📊 Hari Ini", callback_data="daily")],
        [InlineKeyboardButton("📅 Minggu Ini", callback_data="weekly")],
        [InlineKeyboardButton("🗓️ Bulan Ini", callback_data="monthly")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await safe_edit_message(query.message, new_text=msg, new_markup=reply_markup)

def run_bot():
    app = Application.builder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("laporan", cmd_laporan))
    app.add_handler(CallbackQueryHandler(cb_buttons))

    # Thread per log source
    for log_src in LOG_SOURCES:
        t = threading.Thread(target=tail_log, args=(log_src,), daemon=True)
        t.start()

    t2 = threading.Thread(target=batch_flusher, daemon=True)
    t2.start()

    print("[*] Naimonitor berjalan (Realtime otomatis + menu laporan Telegram)...")
    app.run_polling(close_loop=False)

if __name__ == "__main__":
    run_bot()