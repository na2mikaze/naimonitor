#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NaiMonitor (with AI anomaly detection)
- Realtime monitoring (multiple log sources)
- Rule-based detection (regex)
- AI anomaly detection (IsolationForest) on streaming features
- Aggregated alerts (interval) + Telegram menu (Hari Ini / Minggu Ini / Bulan Ini)
- Writes events to events.jsonl

Notes:
- If scikit-learn / pandas not installed, AI will be disabled but rule-based features continue.
- Designed to run under a virtualenv and as systemd service.
"""

import os
import re
import time
import json
import math
import threading
from collections import deque
from datetime import datetime, timedelta
import requests

# Optional ML libs (graceful fallback)
MISSING_ML = False
try:
    import pandas as pd
    from sklearn.ensemble import IsolationForest
except Exception:
    MISSING_ML = True

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
from telegram.error import BadRequest

# ========== CONFIG ==========
LOG_SOURCES = [
    "/var/log/auth.log",
    "/var/log/nginx/access.log",
]
EVENTS_FILE = "/var/www/naimonitor/events.jsonl"

# Prefer environment variables (safer); fallback to empty string
TELEGRAM_TOKEN = ""
CHAT_ID = 12345 #Contoh

# You can hardcode token/chat (not recommended):
# TELEGRAM_TOKEN = "8134450609:AAHp3zIOCRJC1swTy7jgNqssXmORnU49xXQ"
# CHAT_ID = 1198097123

ALERT_FLUSH_INTERVAL = int(os.getenv("ALERT_FLUSH_INTERVAL", "60"))
MAX_EVIDENCE_LINES = int(os.getenv("MAX_EVIDENCE_LINES", "10"))

# ========== REGEX DETECTION ==========
RE_FAILED = re.compile(
    r"Failed password for (invalid user\s+)?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) .* ssh2",
    re.IGNORECASE,
)
RE_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
RE_SQLI = re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(\%22)|(\")|(\;)|(\%3D)", re.IGNORECASE)
RE_LFI = re.compile(r"(\.{2}/|\.{2}\\)", re.IGNORECASE)
RE_RCE = re.compile(r"(system\(|exec\(|passthru\()", re.IGNORECASE)

# ========== AGGREGATOR & AI STATE ==========
batch_lock = threading.Lock()
current_batch = {}

# AI buffers
RECENT_MAX = 2000
recent_entries = deque(maxlen=RECENT_MAX)
ai_lock = threading.Lock()
ai_model = None
records_since_retrain = 0
RETRAIN_EVERY = 200
MIN_TRAIN_SAMPLES = 200

# ========== UTIL FUNCTIONS ==========

def ensure_paths():
    os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)
    if not os.path.exists(EVENTS_FILE):
        open(EVENTS_FILE, "a").close()


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def stable_hash(s: str, mod: int = 100000) -> int:
    h = 0
    for ch in str(s):
        h = (h * 131 + ord(ch)) % 0x7fffffff
    return h % mod


def to_unix_ip(ip: str) -> int:
    try:
        if not ip or ":" in ip:
            return stable_hash(ip, 1000000)
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return stable_hash(ip, 1000000)
        return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    except Exception:
        return stable_hash(ip, 1000000)


# Telegram helper (uses requests so it works even if Application isn't used)
def telegram_send_text(text: str):
    if not TELEGRAM_TOKEN or not CHAT_ID:
        print("[!] TELEGRAM_TOKEN or CHAT_ID not set; skipping send")
        return
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


# ========== PARSING & RULE-BASED ==========

def parse_nginx_line(line: str):
    # try to parse common combined log format
    # fallback to putting raw into url
    try:
        # pattern: ip - - [time] "METHOD URL HTTP/x.x" STATUS SIZE
        m = re.match(r"^(\S+) \S+ \S+ \[([^\]]+)\] \"([A-Z]+) ([^\"]*) HTTP/[0-9.]+\" (\d{3}) (\S+)", line)
        if m:
            ip = m.group(1)
            method = m.group(3)
            url = m.group(4)
            status = int(m.group(5))
            size = 0 if m.group(6) == "-" else int(m.group(6))
            return {
                "service": "nginx",
                "ip": ip,
                "method": method,
                "url": url,
                "status": status,
                "size": size,
                "raw": line.strip(),
            }
    except Exception:
        pass
    return {"service": "nginx", "ip": "-", "method": "-", "url": line.strip(), "status": 0, "size": 0, "raw": line.strip()}


def parse_auth_line(line: str):
    # parse auth.log lines for SSH failures
    m = RE_FAILED.search(line)
    if m:
        return {
            "service": "ssh",
            "ip": m.group("ip"),
            "user": m.group("user"),
            "method": "SSH",
            "url": "-",
            "status": 0,
            "size": 0,
            "raw": line.strip(),
        }
    m = RE_INVALID.search(line)
    if m:
        return {
            "service": "ssh",
            "ip": m.group("ip"),
            "user": m.group("user"),
            "method": "SSH",
            "url": "-",
            "status": 0,
            "size": 0,
            "raw": line.strip(),
        }
    # fallback generic
    return {"service": "auth", "ip": "-", "method": "-", "url": line.strip(), "status": 0, "size": 0, "raw": line.strip()}


def parse_line(line: str, source: str):
    """Return parsed dict (always returns a dict)."""
    if "nginx" in source or "access.log" in source:
        return parse_nginx_line(line)
    else:
        return parse_auth_line(line)


# ========== AI HELPERS ==========

def features_from_entry(e: dict):
    method_h = stable_hash(e.get("method", "-"), 1000)
    url_h = stable_hash(e.get("url", "-"), 100000)
    ip_i = to_unix_ip(e.get("ip", "-"))
    status = int(e.get("status") or 0)
    size_log2 = int(math.log2((e.get("size") or 0) + 1))
    return [method_h, url_h, ip_i, status, size_log2]


def train_isolation_forest():
    global ai_model, records_since_retrain
    if MISSING_ML:
        return
    with ai_lock:
        try:
            if len(recent_entries) < MIN_TRAIN_SAMPLES:
                return
            rows = [features_from_entry(r) for r in list(recent_entries)]
            df = pd.DataFrame(rows, columns=["method_h", "url_h", "ip_i", "status", "size_log2"])
            model = IsolationForest(n_estimators=100, contamination=0.03, random_state=42, n_jobs=-1)
            model.fit(df)
            ai_model = model
            records_since_retrain = 0
            print(f"[*] AI model trained on {len(df)} samples")
        except Exception as e:
            print(f"[!] Gagal latih AI: {e}")


def ai_predict(entry: dict) -> bool:
    if MISSING_ML:
        return False
    with ai_lock:
        if ai_model is None:
            return False
        try:
            row = pd.DataFrame([features_from_entry(entry)], columns=["method_h", "url_h", "ip_i", "status", "size_log2"])
            pred = ai_model.predict(row)
            return int(pred[0]) == -1
        except Exception as e:
            print(f"[!] Gagal prediksi AI: {e}")
            return False


# ========== AGGREGATION (batch) ==========

def add_to_batch(atype: str, ip: str, evidence_line: str):
    key = (atype, ip)
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


# ========== TAIL LOG THREAD ==========

def tail_log(log_source: str):
    ensure_paths()
    telegram_send_text(f"🚀 Naimonitor AI Monitoring dimulai untuk {log_source} ...")

    # wait until file exists
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

            parsed = parse_line(line, log_source)
            # write event always
            event = {
                "timestamp": now_str(),
                "source": log_source,
                "attack_type": parsed.get("service", "Unknown"),
                "ip": parsed.get("ip", "-"),
                "evidence": parsed.get("raw", line.strip()),
            }
            write_event(event)

            # Rule-based detection: if pattern matched, add to batch
            # use parse_line's lessons: identify specific attack types
            atype, ip = None, None
            # we already have parsed; map rules similar to previous parse_line
            # SSH brute force
            if parsed.get("service") == "ssh" and parsed.get("ip"):
                atype, ip = "Brute Force", parsed.get("ip")
            else:
                # check nginx/raw for SQLi/LFI/RCE
                raw = parsed.get("raw","")
                if RE_SQLI.search(raw):
                    atype, ip = "SQL Injection", parsed.get("ip") or "-"
                elif RE_LFI.search(raw):
                    atype, ip = "LFI Attempt", parsed.get("ip") or "-"
                elif RE_RCE.search(raw):
                    atype, ip = "RCE Attempt", parsed.get("ip") or "-"

            if atype and ip:
                add_to_batch(atype, ip, line)

            # AI pipeline: append to recent_entries and possibly detect anomaly
            recent_entries.append(parsed)
            global records_since_retrain
            records_since_retrain += 1
            # retrain opportunistically
            if not MISSING_ML and records_since_retrain >= RETRAIN_EVERY:
                threading.Thread(target=train_isolation_forest, daemon=True).start()

            # if model present, predict
            try:
                if not MISSING_ML and ai_predict(parsed):
                    # record AI event
                    ai_event = {
                        "timestamp": now_str(),
                        "source": log_source,
                        "attack_type": "AI-Detected",
                        "ip": parsed.get("ip","-"),
                        "evidence": parsed.get("raw","")[:1000],
                    }
                    write_event(ai_event)
                    # immediate notification for AI anomaly
                    telegram_send_text(
                        f"🤖 AI Deteksi Anomali!\nDate: {now_str()}\nSource: {log_source}\nIP: {ai_event['ip']}\nEvidence: {ai_event['evidence'][:400]}"
                    )
            except Exception as e:
                print(f"[!] AI detect error: {e}")


# ========== BATCH FLUSHER THREAD ==========

def batch_flusher():
    while True:
        time.sleep(ALERT_FLUSH_INTERVAL)
        try:
            flush_batch_and_send()
        except Exception as e:
            print(f"[!] Gagal flush batch: {e}")


# ========== REPORTING (periodic) ==========
# same as previous build_period_report functions

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


# ========== TELEGRAM BOT HELPERS ==========
async def safe_edit_message(message, new_text=None, new_markup=None):
    try:
        if new_text is not None and new_text != message.text:
            await message.edit_text(new_text, reply_markup=new_markup)
        elif new_markup is not None and new_markup != message.reply_markup:
            await message.edit_reply_markup(new_markup)
    except BadRequest as e:
        if "Message is not modified" not in str(e):
            raise


# ========== TELEGRAM HANDLERS ==========
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


# ========== STARTUP & RUN ==========

def run_bot():
    global TELEGRAM_TOKEN, CHAT_ID
    if not TELEGRAM_TOKEN or not CHAT_ID:
        print("[!] TELEGRAM_TOKEN or CHAT_ID not configured. Set environment vars or edit the script.")

    app = Application.builder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("laporan", cmd_laporan))
    app.add_handler(CallbackQueryHandler(cb_buttons))

    # Start tail threads
    for log_src in LOG_SOURCES:
        t = threading.Thread(target=tail_log, args=(log_src,), daemon=True)
        t.start()

    # Start flusher
    t2 = threading.Thread(target=batch_flusher, daemon=True)
    t2.start()

    # If ML available, optionally seed initial training on existing events
    if not MISSING_ML:
        # load some historical events to help initial model (if file exists)
        evs = load_events(limit_lines=5000)
        for e in evs:
            parsed = {
                "service": e.get("source", ""),
                "ip": e.get("ip", "-"),
                "method": "-",
                "url": e.get("evidence", "")[:400],
                "status": 0,
                "size": 0,
                "raw": e.get("evidence", ""),
            }
            recent_entries.append(parsed)
        # train if enough
        if len(recent_entries) >= MIN_TRAIN_SAMPLES:
            try:
                train_isolation_forest()
            except Exception as e:
                print(f"[!] Initial AI train failed: {e}")

    print("[*] Naimonitor berjalan (Realtime + AI).")
    app.run_polling(close_loop=False)


if __name__ == "__main__":
    run_bot()

