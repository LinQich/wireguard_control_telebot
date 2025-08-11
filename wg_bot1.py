#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WireGuard Telegram Admin Bot (expanded)
- Stores client files in /etc/wireguard/clients
- Generates .conf and QR on the fly from stored client metadata
- Removes client files when peer deleted
"""

import os
import time
import subprocess
import locale
import qrcode
import json
import hashlib
import shutil

def safe_edit_message(bot, call, new_text, reply_markup=None, parse_mode=None):
    try:
        current_text = getattr(call.message, 'text', '') or ""
        # Get current markup as dict if possible
        try:
            current_markup = call.message.reply_markup.to_dict() if call.message.reply_markup else None
        except AttributeError:
            current_markup = None
        try:
            new_markup = reply_markup.to_dict() if reply_markup else None
        except AttributeError:
            new_markup = None
        if current_text.strip() == (new_text or "").strip() and current_markup == new_markup:
            return  # Don't edit if both text and markup are the same
        bot.edit_message_text(chat_id=call.message.chat.id,
                              message_id=call.message.message_id,
                              text=new_text,
                              reply_markup=reply_markup,
                              parse_mode=parse_mode)
    except Exception as e:
        if "Message is not modified" in str(e):
            return  # Ignore this specific error
        raise

from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    ContextTypes,
    filters
)

# CLEAN CONF FIX — исправление формата Key = Value
def clean_wg_conf(path):
    """Приводит конфиг WireGuard к формату 'Key = Value'"""
    import re
    try:
        if not os.path.exists(path):
            return
        lines_out = []
        with open(path, 'r') as f:
            for line in f:
                # Исправляем только строки с ключами в формате Key=Value (без пробела)
                if re.match(r'^[A-Za-z]+=[^=]', line):
                    key, value = line.split('=', 1)
                    line = f"{key.strip()} = {value.lstrip()}"
                lines_out.append(line)
        with open(path, 'w') as f:
            f.writelines(lines_out)
    except Exception as e:
        print(f"⚠️ Ошибка clean_wg_conf: {e}")



# -------------------- Paths --------------------
PARAMS_FILE = "/etc/wireguard/params"
BOT_PARAMS_FILE = "/etc/wireguard/bot_params"
WG_CONF = "/etc/wireguard/wg0.conf"
CLIENT_NAMES_FILE = "/etc/wireguard/client_names"
CLIENT_DIR = "/etc/wireguard/clients"
TEMP_DIR = "/tmp/wg_bot"
STAT_FILE = "/etc/wireguard/stat"
WG_INTERFACE = "wg0"

# -------------------- Helpers --------------------
ONLINE_THRESHOLD = 180  # seconds to consider peer online

def last_two_ip_octets(ip: str) -> str:
    try:
        ip_only = ip.split('/')[0]
        parts = ip_only.split('.')
        if len(parts) == 4:
            return f"{parts[2]}.{parts[3]}"
    except:
        pass
    return ""

def time_since(ts: int) -> str:
    try:
        if not ts or int(ts) == 0:
            return "никогда"
        delta = int(time.time()) - int(ts)
        if delta < 0:
            delta = 0
        hours = delta // 3600
        minutes = (delta % 3600) // 60
        return f"{hours} ч. {minutes} мин. назад"
    except:
        return "неизвестно"

def strip_inline_comment(value: str) -> str:
    if value is None:
        return ''
    return value.split('#', 1)[0].strip()

def load_params(path: str) -> dict:
    params = {}
    try:
        with open(path, 'r') as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    k, v = line.split('=', 1)
                    k = k.strip()
                    v = strip_inline_comment(v)
                    params[k] = v
    except FileNotFoundError:
        # Not fatal — may provide defaults
        print(f"⚠️ Конфиг {path} не найден.")
    except Exception as e:
        print(f"⚠️ Ошибка загрузки {path}: {e}")
    return params

SERVER_PARAMS = load_params(PARAMS_FILE)
BOT_PARAMS = load_params(BOT_PARAMS_FILE)

# TOKEN and ADMIN_IDS
TOKEN = BOT_PARAMS.get('TOKEN', '').strip()
ADMIN_IDS_RAW = BOT_PARAMS.get('ADMIN_IDS', '')
def parse_admin_ids(raw: str):
    if not raw:
        return []
    raw = strip_inline_comment(raw)
    raw = raw.replace(',', ' ')
    parts = [p.strip() for p in raw.split() if p.strip()]
    ids = []
    for p in parts:
        try:
            ids.append(int(p))
        except:
            continue
    return ids
ADMIN_IDS = parse_admin_ids(ADMIN_IDS_RAW)

def is_admin(update_or_id) -> bool:
    try:
        uid = update_or_id
        if hasattr(update_or_id, 'effective_user'):
            uid = update_or_id.effective_user.id
        return uid in ADMIN_IDS
    except:
        return False

def normalize_key(key: str) -> str:
    """Normalize base64 key (add padding). Only for keys."""
    if key is None:
        return ''
    k = key.strip()
    k = strip_inline_comment(k)
    if k == '':
        return ''
    pad = len(k) % 4
    if pad:
        k += '=' * (4 - pad)
    return k

def safe_filename_from_key(pubkey: str) -> str:
    """
    Make a safe filename for storing client files based on public key.
    Replace unsafe chars by URL-safe base64 alternative or use sha256 if prefer.
    We'll use sha256 to avoid any filesystem char issues.
    """
    h = hashlib.sha256(pubkey.encode('utf-8')).hexdigest()
    return h

def format_traffic(bytes_val: int) -> str:
    try:
        b = float(bytes_val)
    except:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.2f} {unit}"
        b /= 1024
    return f"{b:.2f} PB"

def format_handshake_time(timestamp: str) -> str:
    try:
        if not timestamp or timestamp == '0':
            return "никогда"
        if timestamp.isdigit():
            dt = datetime.fromtimestamp(int(timestamp))
            return dt.strftime("%d.%m.%Y %H:%M:%S")
        try:
            dt = datetime.strptime(timestamp, "%a %b %d %H:%M:%S %Y")
            return dt.strftime("%d.%m.%Y %H:%M:%S")
        except:
            return timestamp
    except:
        return timestamp

def ensure_dirs_and_files():
    os.makedirs(TEMP_DIR, exist_ok=True)
    os.makedirs(CLIENT_DIR, exist_ok=True)
    if not os.path.exists(CLIENT_NAMES_FILE):
        try:
            with open(CLIENT_NAMES_FILE, 'w') as f:
                pass
            os.chmod(CLIENT_NAMES_FILE, 0o600)
        except Exception as e:
            print(f"⚠️ Ошибка создания {CLIENT_NAMES_FILE}: {e}")
    if not os.path.exists(STAT_FILE):
        try:
            with open(STAT_FILE, 'w') as f:
                f.write("# Формат: <public_key>=<rx_bytes>:<tx_bytes>\n")
            os.chmod(STAT_FILE, 0o600)
        except Exception as e:
            print(f"⚠️ Ошибка создания {STAT_FILE}: {e}")

# -------------------- Client names (left: key, right: name) --------------------
def load_client_names() -> dict:
    """
    Read client_names file.
    Use rsplit('=',1) to keep '=' padding in key intact.
    Returns dict normalized_pubkey -> name (name as-is).
    """
    names = {}
    try:
        if os.path.exists(CLIENT_NAMES_FILE):
            with open(CLIENT_NAMES_FILE, 'r') as f:
                for raw in f:
                    line = raw.rstrip('\n')
                    if not line or line.strip().startswith('#'):
                        continue
                    if '=' in line:
                        left_right = line.rsplit('=', 1)
                        if len(left_right) == 2:
                            left = left_right[0].strip()
                            right = left_right[1]
                            nk = normalize_key(left)
                            names[nk] = right
    except Exception as e:
        print(f"⚠️ Ошибка загрузки имен клиентов: {e}")
    return names

def save_client_name(pub_key: str, name: str):
    try:
        names = load_client_names()
        nk = normalize_key(pub_key)
        names[nk] = name
        with open(CLIENT_NAMES_FILE, 'w') as f:
            for k, v in names.items():
                f.write(f"{k}={v}\n")
        os.chmod(CLIENT_NAMES_FILE, 0o600)
    except Exception as e:
        print(f"⚠️ Ошибка сохранения имени клиента: {e}")

def remove_client_name(pub_key: str):
    try:
        names = load_client_names()
        nk = normalize_key(pub_key)
        if nk in names:
            del names[nk]
            with open(CLIENT_NAMES_FILE, 'w') as f:
                for k, v in names.items():
                    f.write(f"{k}={v}\n")
            os.chmod(CLIENT_NAMES_FILE, 0o600)
    except Exception as e:
        print(f"⚠️ Ошибка удаления имени клиента: {e}")

# -------------------- Client files (per-client metadata and .conf) --------------------
def client_meta_path(pub_key: str) -> str:
    sf = safe_filename_from_key(pub_key)
    return os.path.join(CLIENT_DIR, f"{sf}.json")

def client_conf_path(pub_key: str) -> str:
    sf = safe_filename_from_key(pub_key)
    return os.path.join(CLIENT_DIR, f"{sf}.conf")

def load_client_meta() -> dict:
    """
    Load all client meta files, return dict normalized_pubkey -> meta dict
    """
    meta = {}
    try:
        if os.path.exists(CLIENT_DIR):
            for fn in os.listdir(CLIENT_DIR):
                if fn.endswith('.json'):
                    path = os.path.join(CLIENT_DIR, fn)
                    try:
                        with open(path, 'r') as f:
                            obj = json.load(f)
                            pub = normalize_key(obj.get('pub', ''))
                            if pub:
                                meta[pub] = obj
                    except Exception:
                        continue
    except Exception as e:
        print(f"⚠️ Ошибка чтения client meta: {e}")
    return meta

def save_client_meta(pub_key: str, priv_key: str, psk: str, ip: str, name: str):
    """
    Save per-client meta json and .conf
    meta contains: pub, priv, psk, ip, name
    """
    nk = normalize_key(pub_key)
    meta = {
        'pub': nk,
        'priv': priv_key,
        'psk': psk,
        'ip': ip,
        'name': name
    }
    meta_path = client_meta_path(nk)
    conf_path = client_conf_path(nk)
    try:
        with open(meta_path, 'w') as f:
            json.dump(meta, f)
        os.chmod(meta_path, 0o600)
        # write conf file
        conf_text = build_client_conf_from_meta(meta)
        with open(conf_path, 'w') as f:
            f.write(conf_text)
        os.chmod(conf_path, 0o600)
    except Exception as e:
        print(f"⚠️ Ошибка сохранения meta/conf: {e}")

def remove_client_files(pub_key: str):
    nk = normalize_key(pub_key)
    try:
        mp = client_meta_path(nk)
        cp = client_conf_path(nk)
        if os.path.exists(mp):
            os.remove(mp)
        if os.path.exists(cp):
            os.remove(cp)
    except Exception as e:
        print(f"⚠️ Ошибка удаления файлов клиента: {e}")

# -------------------- Generate client conf from meta --------------------
def build_client_conf_from_meta(meta_entry: dict) -> str:
    server_pub_key = normalize_key(SERVER_PARAMS.get('SERVER_PUB_KEY', ''))
    server_endpoint = SERVER_PARAMS.get('SERVER_PUB_IP', '')
    server_port = SERVER_PARAMS.get('SERVER_PORT', '')
    client_dns_1 = SERVER_PARAMS.get('CLIENT_DNS_1', '')
    client_dns_2 = SERVER_PARAMS.get('CLIENT_DNS_2', '')
    allowed_ips = SERVER_PARAMS.get('ALLOWED_IPS', '0.0.0.0/0')
    priv = meta_entry.get('priv', '')
    ip = meta_entry.get('ip', '')
    psk = meta_entry.get('psk', '')
    conf_content = f"""[Interface]
PrivateKey = {priv}
Address = {ip}/24
DNS = {client_dns_1},{client_dns_2}

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {psk}
Endpoint = {server_endpoint}:{server_port}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
    return conf_content

# -------------------- Stats monthly --------------------
def get_monthly_stats() -> dict:
    stats = {}
    try:
        if os.path.exists(STAT_FILE):
            with open(STAT_FILE, 'r') as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' in line:
                        pub_key, values = line.split('=', 1)
                        nk = normalize_key(pub_key)
                        if ':' in values:
                            rx, tx = values.split(':', 1)
                        else:
                            rx, tx = '0', '0'
                        try:
                            stats[nk] = {
                                'initial_rx': int(rx),
                                'initial_tx': int(tx)
                            }
                        except:
                            stats[nk] = {'initial_rx': 0, 'initial_tx': 0}
    except Exception as e:
        print(f"⚠️ Ошибка чтения файла статистики: {e}")
    return stats

def update_monthly_stats():
    pass


def update_traffic_stats_json():
    """Собирает статистику wg и сохраняет в компактный JSON"""
    try:
        wg_show = subprocess.getoutput(f'wg show {WG_INTERFACE} dump')
        if not wg_show:
            return
        peers_data = {}
        ts_now = int(time.time())
        for line in wg_show.splitlines()[1:]:
            if not line.strip():
                continue
            parts = line.split('	')
            pub_key = normalize_key(parts[0]) if len(parts) > 0 else ""
            endpoint = parts[2] if len(parts) > 2 else ""
            allowed_ips = parts[3] if len(parts) > 3 else ""
            try:
                lh = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0
            except:
                lh = 0
            try:
                rx = int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 0
            except:
                rx = 0
            try:
                tx = int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else 0
            except:
                tx = 0
            if pub_key:
                peers_data[pub_key] = {
                    "lh": lh,
                    "rx": rx,
                    "tx": tx,
                    "ep": endpoint,
                    "ip": allowed_ips
                }
        os.makedirs(os.path.dirname(TRAFFIC_STATS_FILE), exist_ok=True)
        with open(TRAFFIC_STATS_FILE, "w") as f:
            json.dump({"ts": ts_now, "peers": peers_data}, f, separators=(",", ":"))
        os.chmod(TRAFFIC_STATS_FILE, 0o600)
    except Exception as e:
        print(f"⚠️ Ошибка обновления {TRAFFIC_STATS_FILE}: {e}")


def find_available_ip() -> str:
    server_ip = SERVER_PARAMS.get('SERVER_WG_IPV4', '') or '10.66.66.1'
    parts = server_ip.split('.')
    if len(parts) >= 3:
        base_ip = '.'.join(parts[:3]) + '.'
    else:
        base_ip = '10.66.66.'
    used_ips = set()
    # Parse WG_CONF for AllowedIPs
    if os.path.exists(WG_CONF):
        try:
            with open(WG_CONF, 'r') as f:
                for raw in f:
                    line = raw.strip()
                    if 'AllowedIPs' in line:
                        try:
                            ip = line.split('=', 1)[1].strip().split('/')[0]
                            if ip.startswith(base_ip):
                                used_ips.add(ip)
                        except:
                            continue
        except:
            pass
    for i in range(2, 255):
        cand = f"{base_ip}{i}"
        if cand not in used_ips:
            return cand
    raise Exception("Нет свободных IP в подсети")

# -------------------- UI keyboard --------------------
def main_menu_keyboard():
    keyboard = [
        [InlineKeyboardButton("🖥️ Инфо о сервере", callback_data='server_info')],
        [InlineKeyboardButton("📋 Список пиров", callback_data='list_peers')],
        [InlineKeyboardButton("➕ Добавить пир", callback_data='add_peer')],
        [InlineKeyboardButton("🗑️ Удалить пир", callback_data='delete_peer')],
        [InlineKeyboardButton("💾 Сохранить конфиг", callback_data='save_config')],
        [InlineKeyboardButton("ℹ️ Инфо о пире", callback_data='peer_info')]
    ]
    return InlineKeyboardMarkup(keyboard)

# -------------------- Telegram Handlers --------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        await update.message.reply_text("🚫 Доступ запрещен")
        return
    await update.message.reply_text('🔹 Выберите действие:', reply_markup=main_menu_keyboard())

async def server_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    query = update.callback_query
    await query.answer()
    try:
        uptime = subprocess.getoutput('uptime -p')
        load = subprocess.getoutput("cat /proc/loadavg | awk '{print $1\", \"$2\", \"$3}'")
        mem_info = subprocess.getoutput("free -m | awk '/Mem/{printf \"%d/%d MB\", $3, $2}'")
        disk_info = subprocess.getoutput("df -h / | awk 'NR==2{printf \"%s/%s\", $3, $2}'")
        wg_stats = subprocess.getoutput(f'wg show {WG_INTERFACE} dump')
        peer_list = []
        # Read wg0.conf for PublicKey lines
        if os.path.exists(WG_CONF):
            with open(WG_CONF, 'r') as f:
                for raw in f:
                    line = raw.strip()
                    if line.lower().startswith('publickey'):
                        if '=' in line:
                            pub_key_part = line.split('=', 1)[1].strip()
                            pub_key = normalize_key(pub_key_part)
                            peer_list.append(pub_key)
        online_peers = []
        meta_all = load_client_meta()
        now_ts = int(time.time())
        interface_info = []
        if wg_stats:
            lines = wg_stats.splitlines()
            if lines:
                interface_info = lines[0].split('\t')
            for line in lines[1:]:
                if not line.strip():
                    continue
                parts = line.split('\t')
                # parts[0]=pubkey, parts[4]=last_handshake
                if len(parts) >= 5 and parts[4] != '0':
                    try:
                        last_hs = int(parts[4])
                    except:
                        continue
                    if now_ts - last_hs <= ONLINE_THRESHOLD:
                        online_peers.append(parts[0])
        client_names = load_client_names()
        online_peers_names = []
        # try to get IPs for online peers (last two octets)
        for pk in online_peers:
            name = client_names.get(normalize_key(pk), "Без имени")
            ip_val = meta_all.get(normalize_key(pk), {}).get('ip', '')
            # fallback: try to find AllowedIPs in WG_CONF
            if not ip_val and os.path.exists(WG_CONF):
                try:
                    with open(WG_CONF, 'r') as f:
                        conf_lines = f.readlines()
                    i = 0
                    while i < len(conf_lines):
                        ln = conf_lines[i].strip()
                        if ln.lower().startswith('publickey') and '=' in ln:
                            keypart = normalize_key(ln.split('=',1)[1].strip())
                            if keypart == pk:
                                j = i+1
                                found_ip = ''
                                while j < len(conf_lines):
                                    nxt = conf_lines[j].strip()
                                    if nxt == '' or nxt.startswith('['):
                                        break
                                    if nxt.lower().startswith('allowedips') and '=' in nxt:
                                        try:
                                            found_ip = nxt.split('=',1)[1].strip().split('/')[0]
                                        except:
                                            found_ip = ''
                                        break
                                    j += 1
                                if found_ip:
                                    ip_val = found_ip
                                break
                        i += 1
                except:
                    pass
            last_octets = last_two_ip_octets(ip_val) if ip_val else ""
            online_peers_names.append((name, last_octets))
        response = (
            f"🖥️ <b>Информация о сервере</b>\n\n"
            f"⏱ <b>Время работы:</b> {uptime}\n"
            f"📊 <b>Загрузка CPU:</b> {load}\n"
            f"💾 <b>Использовано RAM:</b> {mem_info}\n"
            f"💽 <b>Использовано диска:</b> {disk_info}\n\n"
            f"<b>Статистика WireGuard:</b>\n"
            f"Пиров онлайн: {len(online_peers)} из {len(peer_list)}\n"
        )
        if online_peers_names:
            response += "\n<b>Пиры в сети:</b>\n"
            def _oct_key(x):
                try:
                    parts = [int(p) if p.isdigit() else 0 for p in x.split('.')] if x else [0,0]
                    # ensure two parts
                    if len(parts) < 2:
                        parts = [0]*(2-len(parts)) + parts
                    return parts
                except:
                    return [0,0]
            for name, last_octets in sorted(online_peers_names, key=lambda t: _oct_key(t[1])):
                response += f"• 🟢{name} - {last_octets}\n"
        if wg_stats and interface_info and len(interface_info) >= 5:
            response += (
                f"\n<b>Интерфейс {WG_INTERFACE}:</b>\n"
                f"Порт: {interface_info[4]}\n"
                f"Публичный ключ: <code>{interface_info[0][:10]}...</code>"
            )
        await query.edit_message_text(text=response, parse_mode='HTML', reply_markup=main_menu_keyboard())
    except Exception as e:
        await query.edit_message_text(f"❌ Ошибка: {e}", reply_markup=main_menu_keyboard())

async def add_peer_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    query = update.callback_query
    await query.answer()
    try:
        await query.edit_message_text(text="🔹 Введите имя для нового пира:", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Назад", callback_data='cancel')]]))
        context.user_data['step'] = 'add_peer_name'
    except Exception as e:
        await query.edit_message_text(f"❌ Ошибка: {e}", reply_markup=main_menu_keyboard())

async def handle_peer_name(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    peer_name = update.message.text.strip()
    conf_filename = None
    qr_filename = None
    try:
        os.makedirs(TEMP_DIR, exist_ok=True)
        server_ip = SERVER_PARAMS.get('SERVER_WG_IPV4', '10.66.66.1')
        server_pub_key = normalize_key(SERVER_PARAMS.get('SERVER_PUB_KEY', ''))
        server_endpoint = SERVER_PARAMS.get('SERVER_PUB_IP', '')
        server_port = SERVER_PARAMS.get('SERVER_PORT', '')
        client_dns_1 = SERVER_PARAMS.get('CLIENT_DNS_1', '1.1.1.1')
        client_dns_2 = SERVER_PARAMS.get('CLIENT_DNS_2', '8.8.8.8')
        allowed_ips = SERVER_PARAMS.get('ALLOWED_IPS', '0.0.0.0/0')
        peer_ip = find_available_ip()
        # generate keys
        priv_key = subprocess.getoutput('wg genkey').strip()
        # get pubkey
        p_pub_proc = subprocess.Popen(['wg', 'pubkey'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        pub_key, err = p_pub_proc.communicate(input=priv_key)
        pub_key = normalize_key(pub_key.strip())
        psk_key = normalize_key(subprocess.getoutput('wg genpsk').strip())
        # runtime add
        add_peer_cmd = [
            'sudo', 'wg', 'set', WG_INTERFACE,
            'peer', pub_key,
            'preshared-key', '/dev/stdin',
            'allowed-ips', f"{peer_ip}/32"
        ]
        process = subprocess.Popen(add_peer_cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        _, stderr = process.communicate(input=psk_key)
        if process.returncode != 0:
            raise Exception(f"Ошибка добавления пира: {stderr}")
        # append to wg0.conf
        peer_conf_block = f"\n[Peer]\nPublicKey = {pub_key}\nPresharedKey = {psk_key}\nAllowedIPs = {peer_ip}/32\n"
        with open(WG_CONF, 'a') as f:
            f.write(peer_conf_block)
        # save client name and meta/conf
        save_client_name(pub_key, peer_name)
        save_client_meta(pub_key, priv_key, psk_key, peer_ip, peer_name)
        # add stat
        try:
            with open(STAT_FILE, 'a') as f:
                f.write(f"{pub_key}=0:0\n")
        except Exception as e:
            print(f"⚠️ Не удалось обновить stat: {e}")
        # save wg config
        save_result = subprocess.run(['sudo', 'wg-quick', 'save', WG_INTERFACE], capture_output=True, text=True)
        if save_result.returncode != 0:
            print(f"⚠️ Не удалось сохранить конфиг: {save_result.stderr}")
        # prepare temporary files for sending
        conf_content = build_client_conf_from_meta({'priv': priv_key, 'psk': psk_key, 'ip': peer_ip, 'name': peer_name})
        conf_filename = os.path.join(TEMP_DIR, f"{safe_filename_from_key(pub_key)}.conf")
        with open(conf_filename, 'w') as f:
            f.write(conf_content)
        qr = qrcode.QRCode()
        qr.add_data(conf_content)
        qr.make()
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_filename = os.path.join(TEMP_DIR, f"{safe_filename_from_key(pub_key)}.png")
        qr_img.save(qr_filename)
        # send files
        with open(conf_filename, 'rb') as f:
            await update.message.reply_document(f, caption=f"📁 Конфигурация для {peer_name}")
        with open(qr_filename, 'rb') as f:
            await update.message.reply_photo(f, caption=f"📲 QR код для {peer_name}")
        await update.message.reply_text(f"✅ Пир {peer_name} успешно добавлен с IP {peer_ip}", reply_markup=main_menu_keyboard())
    except Exception as e:
        await update.message.reply_text(f"❌ Ошибка при создании пира:\n{e}", reply_markup=main_menu_keyboard())
    finally:
        for filename in [conf_filename, qr_filename]:
            if filename and os.path.exists(filename):
                try:
                    os.remove(filename)
                except:
                    pass
        context.user_data.clear()

async def save_config(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    query = update.callback_query
    await query.answer()
    try:
        result = subprocess.run(['sudo', 'wg-quick', 'save', WG_INTERFACE], capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Ошибка сохранения: {result.stderr}")
        await query.edit_message_text(text="✅ Текущая конфигурация успешно сохранена в файл", reply_markup=main_menu_keyboard())
    except Exception as e:
        await query.edit_message_text(text=f"❌ Ошибка при сохранении: {e}", reply_markup=main_menu_keyboard())

async def delete_peer_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    query = update.callback_query
    await query.answer()
    try:
        peer_list = []
        client_names = load_client_names()
        if os.path.exists(WG_CONF):
            with open(WG_CONF, 'r') as f:
                for raw in f:
                    line = raw.strip()
                    if line.lower().startswith('publickey'):
                        if '=' in line:
                            pub_key_part = line.split('=', 1)[1].strip()
                            pub_key = normalize_key(pub_key_part)
                            name = client_names.get(pub_key, f"Peer {len(peer_list)+1}")
                            peer_list.append((pub_key, name))
        if not peer_list:
            await query.edit_message_text("ℹ️ Нет активных пиров.", reply_markup=main_menu_keyboard())
            return
        keyboard = []
        for pub_key, peer_name in peer_list:
            keyboard.append([InlineKeyboardButton(peer_name, callback_data=f'delpeer_{pub_key}')])
        keyboard.append([InlineKeyboardButton("🔙 Назад", callback_data='cancel')])
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(text="🔹 Выберите пира для удаления:", reply_markup=reply_markup)
    except Exception as e:
        await query.edit_message_text(f"❌ Ошибка: {e}", reply_markup=main_menu_keyboard())

async def delete_peer_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    query = update.callback_query
    await query.answer()
    peer_pub_key = query.data.split('_', 1)[1]
    context.user_data['peer_to_delete'] = peer_pub_key
    client_names = load_client_names()
    peer_name = client_names.get(peer_pub_key, "неизвестный пир")
    keyboard = [
        [InlineKeyboardButton("✅ Да, удалить", callback_data=f'confirmdel_{peer_pub_key}')],
        [InlineKeyboardButton("❌ Нет, отменить", callback_data='cancel')]
    ]
    await query.edit_message_text(
        text=f"⚠️ Вы уверены, что хотите удалить пира <b>{peer_name}</b>?",
        parse_mode='HTML',
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def delete_peer_execute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    query = update.callback_query
    await query.answer()
    peer_pub_key = query.data.split('_', 1)[1]
    try:
        remove_cmd = ['sudo', 'wg', 'set', WG_INTERFACE, 'peer', peer_pub_key, 'remove']
        remove_result = subprocess.run(remove_cmd, capture_output=True, text=True)
        if remove_result.returncode != 0:
            raise Exception(f"Ошибка удаления: {remove_result.stderr}")
        # remove from wg0.conf
        if os.path.exists(WG_CONF):
            with open(WG_CONF, 'r') as f:
                lines = f.readlines()
            new_lines = []
            peer_found = False
            i = 0
            while i < len(lines):
                line = lines[i]
                lstrip = line.strip()
                if lstrip.lower().startswith('publickey'):
                    if '=' in line:
                        key_part = line.split('=', 1)[1].strip()
                        current_pub_key = normalize_key(key_part)
                        if current_pub_key == peer_pub_key:
                            peer_found = True
                            i += 1
                            while i < len(lines):
                                nxt = lines[i]
                                if nxt.strip() == '' or nxt.lstrip().startswith('['):
                                    break
                                i += 1
                            continue
                new_lines.append(line)
                i += 1
            if not peer_found:
                raise Exception("Пир не найден в конфигурации")
            with open(WG_CONF, 'w') as f:
                f.writelines(new_lines)
        # remove client name and files
        remove_client_name(peer_pub_key)
        remove_client_files(peer_pub_key)
        # save wg config
        save_result = subprocess.run(['sudo', 'wg-quick', 'save', WG_INTERFACE], capture_output=True, text=True)
        if save_result.returncode != 0:
            print(f"⚠️ Не удалось сохранить конфиг: {save_result.stderr}")
        await query.edit_message_text(text="✅ Пир успешно удален", reply_markup=main_menu_keyboard())
    except Exception as e:
        await query.edit_message_text(text=f"❌ Ошибка при удалении: {e}", reply_markup=main_menu_keyboard())
    finally:
        context.user_data.clear()


async def list_peers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    query = update.callback_query
    await query.answer()
    try:
        peer_list = []
        client_names = load_client_names()
        if os.path.exists(WG_CONF):
            with open(WG_CONF, 'r') as f:
                for raw in f:
                    line = raw.strip()
                    if line.lower().startswith('publickey') and '=' in line:
                        pub_key_part = line.split('=', 1)[1].strip()
                        pub_key = normalize_key(pub_key_part)
                        name = client_names.get(pub_key, f"Peer {len(peer_list)+1}")
                        peer_list.append((pub_key, name))
        if not peer_list:
            await query.edit_message_text(" ℹ️ В конфигурации нет пиров.", reply_markup=main_menu_keyboard())
            return
        wg_show = subprocess.getoutput(f'wg show {WG_INTERFACE} dump')
        response = "📋 <b>Список пиров:</b>\n\n"
        active_peers = {}
        if wg_show:
            for line in wg_show.splitlines()[1:]:
                if not line.strip():
                    continue
                parts = line.split('\t')
                if len(parts) >= 5:
                    pub_key = normalize_key(parts[0])
                    active_peers[pub_key] = {
                        'last_handshake': parts[4] if len(parts) > 4 else '0',
                        'received': parts[5] if len(parts) > 5 else '0',
                        'sent': parts[6] if len(parts) > 6 else '0',
                        'endpoint': parts[2] if len(parts) > 2 else '',
                        'allowed_ips': parts[3] if len(parts) > 3 else ''
                    }
        # Prepare sorting
        meta_all = load_client_meta()
        now_ts_local = int(time.time())
        peers_detailed = []
        for pub_key, peer_name in peer_list:
            peers_detailed.append((pub_key, peer_name, active_peers.get(pub_key)))
        def sort_key(item):
            pub_key, peer_name, info = item
            lh = int(info.get('last_handshake', '0')) if info else 0
            if lh != 0 and now_ts_local - lh <= ONLINE_THRESHOLD:
                status_priority = 0  # 🟢 онлайн
            elif lh == 0:
                status_priority = 2  # 🟡 подключен (нет handshake)
            else:
                status_priority = 1  # 🔴 оффлайн
            return (status_priority,)
        peers_detailed.sort(key=sort_key)
        # Build response
        for pub_key, peer_name, peer_info in peers_detailed:
            if peer_info:
                last_hs_raw = peer_info.get('last_handshake', '0')
                try:
                    lh_int = int(last_hs_raw)
                except:
                    lh_int = 0
                if lh_int != 0 and now_ts_local - lh_int <= ONLINE_THRESHOLD:
                    online_status = "🟢 онлайн"
                elif lh_int == 0:
                    online_status = "🟡 подключен (нет handshake)"
                else:
                    online_status = f"🔴 оффлайн (последний handshake {time_since(lh_int)})"
                last_handshake = format_handshake_time(last_hs_raw) if last_hs_raw != '0' else "никогда"
                try:
                    received = format_traffic(int(peer_info.get('received', 0)))
                except:
                    received = format_traffic(0)
                try:
                    sent = format_traffic(int(peer_info.get('sent', 0)))
                except:
                    sent = format_traffic(0)
                response += (
                    f"🔹 <b>{peer_name}</b> ({online_status})\n"
                    f"├ Последнее подключение: {last_handshake}\n"
                    f"├ Трафик:\n"
                    f"│  📥 {received}\n"
                    f"│  📤 {sent}\n"
                    f"└ Ключ: <code>{pub_key[:10]}...</code>\n\n"
                )
            else:
                response += f"🔹 <b>{peer_name}</b> (🔴 неактивен)\n\n"
        await query.edit_message_text(text=response, parse_mode='HTML', reply_markup=main_menu_keyboard())
    except Exception as e:
        await query.edit_message_text(text=f"❌ Ошибка при получении списка пиров: {e}", reply_markup=main_menu_keyboard())
async def peer_info_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    query = update.callback_query
    await query.answer()
    try:
        peer_list = []
        client_names = load_client_names()
        if os.path.exists(WG_CONF):
            with open(WG_CONF, 'r') as f:
                for raw in f:
                    line = raw.strip()
                    if line.lower().startswith('publickey'):
                        if '=' in line:
                            pub_key_part = line.split('=', 1)[1].strip()
                            pub_key = normalize_key(pub_key_part)
                            name = client_names.get(pub_key, f"Peer {len(peer_list)+1}")
                            peer_list.append((pub_key, name))
        if not peer_list:
            await query.edit_message_text("ℹ️ Нет активных пиров.", reply_markup=main_menu_keyboard())
            return
        keyboard = []
        for pub_key, peer_name in peer_list:
            keyboard.append([InlineKeyboardButton(peer_name, callback_data=f'peerinfo_{pub_key}')])
        keyboard.append([InlineKeyboardButton("🔙 Назад", callback_data='cancel')])
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(text="🔹 Выберите пира для просмотра информации:", reply_markup=reply_markup)
    except Exception as e:
        await query.edit_message_text(f"❌ Ошибка: {e}", reply_markup=main_menu_keyboard())


async def peer_info_show(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    query = update.callback_query
    await query.answer()
    peer_pub_key = query.data.split('_', 1)[1]
    try:
        client_names = load_client_names()
        peer_name = client_names.get(peer_pub_key, "неизвестный пир")
        wg_show = subprocess.getoutput(f'wg show {WG_INTERFACE} dump')
        peer_found = False
        peer_info = None
        if wg_show:
            for line in wg_show.splitlines()[1:]:
                if not line.strip():
                    continue
                parts = line.split('\t')
                if len(parts) >= 8 and normalize_key(parts[0]) == peer_pub_key:
                    peer_found = True
                    peer_info = {
                        'last_handshake': parts[4],
                        'received': int(parts[5]) if parts[5].isdigit() else 0,
                        'sent': int(parts[6]) if parts[6].isdigit() else 0,
                        'endpoint': parts[2],
                        'allowed_ips': parts[3]
                    }
                    break
        if not peer_found:
            found_in_conf = False
            if os.path.exists(WG_CONF):
                with open(WG_CONF, 'r') as f:
                    for raw in f:
                        line = raw.strip()
                        if line.lower().startswith('publickey') and '=' in line:
                            keypart = normalize_key(line.split('=', 1)[1].strip())
                            if keypart == peer_pub_key:
                                found_in_conf = True
                                break
            if found_in_conf:
                await query.edit_message_text(
                    text=f"ℹ️ Пир <b>{peer_name}</b> есть в конфигурации, но не активен.",
                    parse_mode='HTML',
                    reply_markup=main_menu_keyboard()
                )
            else:
                await query.edit_message_text(text="❌ Пир не найден в конфигурации.", reply_markup=main_menu_keyboard())
            return
        monthly_stats = get_monthly_stats().get(peer_pub_key, {'initial_rx': 0, 'initial_tx': 0})
        monthly_rx = max(0, peer_info['received'] - monthly_stats.get('initial_rx', 0))
        monthly_tx = max(0, peer_info['sent'] - monthly_stats.get('initial_tx', 0))
        last_handshake = format_handshake_time(str(peer_info.get('last_handshake', '0')))
        total_received = format_traffic(peer_info.get('received', 0))
        total_sent = format_traffic(peer_info.get('sent', 0))
        monthly_received = format_traffic(monthly_rx)
        monthly_sent = format_traffic(monthly_tx)
        try:
            lh_int = int(peer_info.get('last_handshake', 0))
        except:
            lh_int = 0
        if lh_int != 0 and (int(time.time()) - lh_int) <= ONLINE_THRESHOLD:
            online_status = "🟢 онлайн"
        elif lh_int == 0:
            online_status = "🟡 подключен (нет handshake)"
        else:
            online_status = f"🔴 оффлайн (последний handshake {time_since(lh_int)})"
        response = (
            f"🔹 <b>{peer_name}</b> ({online_status})\n"
            f"└ Трафик: 📥 {total_received}  📤 {total_sent}\n"
            f"└ За месяц: 📥 {monthly_received}  📤 {monthly_sent}\n"
            f"└ Последний handshake: {last_handshake}\n"
        )
        await query.edit_message_text(text=response, parse_mode='HTML', reply_markup=main_menu_keyboard())
    except Exception as e:
        await query.edit_message_text(text=f"❌ Ошибка получения информации о пире: {e}", reply_markup=main_menu_keyboard())

# -------------------- Download handlers --------------------
async def download_peer_conf(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    query = update.callback_query
    await query.answer()
    peer_pub_key = query.data.split('_', 2)[2]
    # try meta json first
    meta_path = client_meta_path(peer_pub_key)
    conf_path = client_conf_path(peer_pub_key)
    temp_path = None
    try:
        if os.path.exists(conf_path):
            # read canonical conf and send
            with open(conf_path, 'rb') as f:
                await query.message.reply_document(f, caption=f"Конфигурация для {os.path.basename(conf_path)}")
        elif os.path.exists(meta_path):
            with open(meta_path, 'r') as f:
                meta = json.load(f)
            conf_text = build_client_conf_from_meta(meta)
            os.makedirs(TEMP_DIR, exist_ok=True)
            temp_path = os.path.join(TEMP_DIR, f"{safe_filename_from_key(peer_pub_key)}.conf")
            with open(temp_path, 'w') as f:
                f.write(conf_text)
            with open(temp_path, 'rb') as f:
                await query.message.reply_document(f, caption=f"Конфигурация для {meta.get('name','')}")
        else:
            await query.edit_message_text(text="❌ Невозможно сгенерировать .conf — данные клиента не найдены.", reply_markup=main_menu_keyboard())
            return
        await query.edit_message_text(text="✅ Файл отправлен.", reply_markup=main_menu_keyboard())
    except Exception as e:
        await query.edit_message_text(text=f"❌ Ошибка при отправке .conf: {e}", reply_markup=main_menu_keyboard())
    finally:
        try:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
        except:
            pass

async def download_peer_qr(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    query = update.callback_query
    await query.answer()
    peer_pub_key = query.data.split('_', 2)[2]
    meta_path = client_meta_path(peer_pub_key)
    conf_text = None
    temp_path = None
    try:
        if os.path.exists(client_conf_path(peer_pub_key)):
            with open(client_conf_path(peer_pub_key), 'r') as f:
                conf_text = f.read()
        elif os.path.exists(meta_path):
            with open(meta_path, 'r') as f:
                meta = json.load(f)
            conf_text = build_client_conf_from_meta(meta)
        else:
            await query.edit_message_text(text="❌ Невозможно сгенерировать QR — данные клиента не найдены.", reply_markup=main_menu_keyboard())
            return
        # generate QR to temp
        os.makedirs(TEMP_DIR, exist_ok=True)
        temp_path = os.path.join(TEMP_DIR, f"{safe_filename_from_key(peer_pub_key)}.png")
        qr = qrcode.QRCode()
        qr.add_data(conf_text)
        qr.make()
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_img.save(temp_path)
        with open(temp_path, 'rb') as f:
            await query.message.reply_photo(f, caption="QR конфигурации")
        await query.edit_message_text(text="✅ QR отправлен.", reply_markup=main_menu_keyboard())
    except Exception as e:
        await query.edit_message_text(text=f"❌ Ошибка при отправке QR: {e}", reply_markup=main_menu_keyboard())
    finally:
        try:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
        except:
            pass

async def cancel_action(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    query = update.callback_query
    await query.answer()
    context.user_data.clear()
    await query.edit_message_text(text="❌ Действие отменено.", reply_markup=main_menu_keyboard())

async def button_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if not is_admin(update):
        await query.answer("🚫 Доступ запрещен")
        return
    await query.answer()
    data = query.data
    if data == 'server_info':
        await server_info(update, context)
    elif data == 'list_peers':
        await list_peers(update, context)
    elif data == 'add_peer':
        await add_peer_start(update, context)
    elif data == 'delete_peer':
        await delete_peer_start(update, context)
    elif data == 'save_config':
        await save_config(update, context)
    elif data == 'peer_info':
        await peer_info_start(update, context)
    elif data.startswith('delpeer_'):
        await delete_peer_confirm(update, context)
    elif data.startswith('confirmdel_'):
        await delete_peer_execute(update, context)
    elif data.startswith('peerinfo_'):
        await peer_info_show(update, context)
    elif data.startswith('download_conf_'):
        await download_peer_conf(update, context)
    elif data.startswith('download_qr_'):
        await download_peer_qr(update, context)
    elif data == 'cancel':
        await cancel_action(update, context)

async def handle_text_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    step = context.user_data.get('step')
    if step == 'add_peer_name':
        await handle_peer_name(update, context)
    else:
        await update.message.reply_text("Выберите действие из меню:", reply_markup=main_menu_keyboard())

# -------------------- Main --------------------
def main():
    # CLEAN CONF FIX
    clean_wg_conf(WG_CONF)
    print("🟢 Бот запускается...")
    ensure_dirs_and_files()
    update_monthly_stats()
    # create client dir if not exists
    os.makedirs(CLIENT_DIR, exist_ok=True)
    try:
        if not TOKEN:
            print("❌ Ошибка: TOKEN не задан в /etc/wireguard/bot_params")
            return
        application = Application.builder().token(TOKEN).build()
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CallbackQueryHandler(button_router))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_input))
        print("🟢 Бот готов к работе!")
        application.run_polling()
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")

if __name__ == '__main__':
    main()
