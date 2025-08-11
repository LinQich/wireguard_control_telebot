#!/bin/bash

set -e

# ===== Проверка root =====
if [ "$EUID" -ne 0 ]; then
    echo "Пожалуйста, запустите скрипт от root (sudo)"
    exit 1
fi

echo "=== Установка WireGuard Telegram Bot ==="

# ===== Установка зависимостей =====
echo "Устанавливаем зависимости..."
apt update
apt install -y python3 python3-pip python3-venv git fonts-noto-color-emoji

# ===== Каталог для настроек =====
mkdir -p /etc/wireguard

# ===== Запрос данных пользователя =====
read -p "Введите TOKEN (получите у @BotFather): " TOKEN
read -p "Введите ADMIN_ID (узнайте у @getmyid_bot): " ADMIN_ID

# ===== Создание bot_params =====
cat > /etc/wireguard/bot_params <<EOL
TOKEN=${TOKEN}
ADMIN_IDS=${ADMIN_ID}
EOL
chmod 600 /etc/wireguard/bot_params

# ===== Клонирование репозитория =====
echo "Скачиваем бота..."
cd /opt
if [ -d "wireguard_control_telebot" ]; then
    rm -rf wireguard_control_telebot
fi
git clone https://github.com/LinQich/wireguard_control_telebot.git
cd wireguard_control_telebot

# ===== Проверка и создание путей =====
echo "Проверяем необходимые файлы и каталоги..."
mkdir -p /etc/wireguard/clients
touch /etc/wireguard/client_names
chmod 600 /etc/wireguard/client_names
chmod 700 /etc/wireguard/clients

# ===== Замена хардкодных путей в коде =====
echo "Правим хардкодные пути в коде..."
sed -i 's#/etc/wireguard/client_names#/etc/wireguard/client_names#g' wg_bot1.py
sed -i 's#/etc/wireguard/clients#/etc/wireguard/clients#g' wg_bot1.py

# ===== Установка Python-зависимостей =====
echo "Устанавливаем Python-зависимости..."
pip3 install --upgrade pip
if [ -f requirements.txt ]; then
    pip3 install -r requirements.txt
else
    pip3 install python-telegram-bot qrcode[pil]
fi

# ===== Создание службы systemd =====
SERVICE_FILE=/etc/systemd/system/wg-telegram-bot.service

cat > "$SERVICE_FILE" <<EOL
[Unit]
Description=WireGuard Telegram Bot
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/wireguard_control_telebot/wg_bot1.py
Restart=on-failure
EnvironmentFile=/etc/wireguard/bot_params
WorkingDirectory=/opt/wireguard_control_telebot

[Install]
WantedBy=multi-user.target
EOL

# ===== Запуск сервиса =====
echo "Запускаем службу..."
systemctl daemon-reload
systemctl enable wg-telegram-bot
systemctl restart wg-telegram-bot

sleep 2
if systemctl is-active --quiet wg-telegram-bot; then
    echo "✅ Бот установлен и запущен!"
else
    echo "❌ Ошибка запуска бота!"
    journalctl -u wg-telegram-bot --no-pager | tail -n 20
fi
