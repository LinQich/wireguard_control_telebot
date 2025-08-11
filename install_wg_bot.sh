#!/usr/bin/env bash
set -e

PARAMS_FILE="/etc/wireguard/params"
BOT_PARAMS_FILE="/etc/wireguard/bot_params"
WG_DIR="/etc/wireguard"
CLIENTS_DIR="$WG_DIR/clients"
BOT_REPO="https://github.com/LinQich/wireguard_control_telebot.git"
BOT_FILE="wg_bot1.py"

# --------------------- Цвета для вывода ---------------------
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
NC="\e[0m"

# --------------------- Функции ---------------------
detect_distro() {
    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="redhat"
    else
        echo -e "${RED}Неподдерживаемая ОС${NC}"
        exit 1
    fi
}

install_dependencies() {
    echo -e "${GREEN}Устанавливаю зависимости...${NC}"
    if [ "$DISTRO" == "debian" ]; then
        apt update
        apt install -y wireguard qrencode python3 python3-pip git curl sudo
    else
        yum install -y epel-release
        yum install -y wireguard-tools qrencode python3 python3-pip git curl sudo
    fi
    pip3 install python-telegram-bot qrcode[pil]
}

random_port() {
    shuf -i 49152-65535 -n 1
}

is_private_ip() {
    local ip=$1
    if [[ $ip =~ ^10\. ]] || [[ $ip =~ ^192\.168\. ]] || ([[ $ip =~ ^172\. ]] && (( ${ip#172.} >= 16 && ${ip#172.} <= 31 ))); then
        return 0
    else
        return 1
    fi
}

fill_params_file() {
    echo -e "${YELLOW}Заполняем $PARAMS_FILE...${NC}"
    mkdir -p "$WG_DIR"
    touch "$PARAMS_FILE"

    read -rp "Внешний IP сервера [автоопределение]: " SERVER_PUB_IP
    SERVER_PUB_IP=${SERVER_PUB_IP:-$(curl -s ifconfig.me)}

    read -rp "Сетевой интерфейс сервера [eth0]: " SERVER_PUB_NIC
    SERVER_PUB_NIC=${SERVER_PUB_NIC:-eth0}

    read -rp "Имя интерфейса WireGuard [wg0]: " SERVER_WG_NIC
    SERVER_WG_NIC=${SERVER_WG_NIC:-wg0}

    while true; do
        read -rp "IPv4 адрес для WireGuard (частная сеть) [10.66.66.1]: " SERVER_WG_IPV4
        SERVER_WG_IPV4=${SERVER_WG_IPV4:-10.66.66.1}
        if is_private_ip "$SERVER_WG_IPV4"; then
            break
        else
            echo -e "${RED}Адрес не из частной сети. Попробуйте снова.${NC}"
        fi
    done

    read -rp "IPv6 адрес для WireGuard [fd42:42:42::1]: " SERVER_WG_IPV6
    SERVER_WG_IPV6=${SERVER_WG_IPV6:-fd42:42:42::1}

    read -rp "Порт WireGuard [случайный]: " SERVER_PORT
    SERVER_PORT=${SERVER_PORT:-$(random_port)}

    SERVER_PRIV_KEY=$(wg genkey)
    SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

    read -rp "DNS 1 [8.8.8.8]: " CLIENT_DNS_1
    CLIENT_DNS_1=${CLIENT_DNS_1:-8.8.8.8}

    read -rp "DNS 2 [8.8.4.4]: " CLIENT_DNS_2
    CLIENT_DNS_2=${CLIENT_DNS_2:-8.8.4.4}

    ALLOWED_IPS="0.0.0.0/0,::/0"

    cat > "$PARAMS_FILE" <<EOF
SERVER_PUB_IP=$SERVER_PUB_IP
SERVER_PUB_NIC=$SERVER_PUB_NIC
SERVER_WG_NIC=$SERVER_WG_NIC
SERVER_WG_IPV4=$SERVER_WG_IPV4
SERVER_WG_IPV6=$SERVER_WG_IPV6
SERVER_PORT=$SERVER_PORT
SERVER_PRIV_KEY=$SERVER_PRIV_KEY
SERVER_PUB_KEY=$SERVER_PUB_KEY
CLIENT_DNS_1=$CLIENT_DNS_1
CLIENT_DNS_2=$CLIENT_DNS_2
ALLOWED_IPS=$ALLOWED_IPS
EOF
    chmod 600 "$PARAMS_FILE"
    echo -e "${GREEN}Файл $PARAMS_FILE создан.${NC}"
}

setup_bot_params() {
    echo -e "${YELLOW}Настройка $BOT_PARAMS_FILE...${NC}"
    mkdir -p "$WG_DIR"
    read -rp "Введите TOKEN бота: " TOKEN
    read -rp "Введите ADMIN_IDS (через запятую, без пробелов): " ADMIN_IDS

    cat > "$BOT_PARAMS_FILE" <<EOF
TOKEN=$TOKEN
ADMIN_IDS=$ADMIN_IDS
EOF
    chmod 600 "$BOT_PARAMS_FILE"
    echo -e "${GREEN}Файл $BOT_PARAMS_FILE создан.${NC}"
}

install_bot() {
    echo -e "${GREEN}Скачиваю бота...${NC}"
    cd "$WG_DIR"
    if [ ! -d "$WG_DIR/wireguard_control_telebot" ]; then
        git clone "$BOT_REPO"
    else
        cd wireguard_control_telebot && git pull && cd ..
    fi

    cp "$WG_DIR/wireguard_control_telebot/$BOT_FILE" "$WG_DIR/"
    mkdir -p "$CLIENTS_DIR"

    cat > /etc/systemd/system/wg_bot.service <<EOF
[Unit]
Description=WireGuard Control Telegram Bot
After=network.target

[Service]
ExecStart=/usr/bin/python3 $WG_DIR/$BOT_FILE
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable wg_bot
    systemctl restart wg_bot
    echo -e "${GREEN}Бот установлен и запущен.${NC}"
}

# --------------------- Логика режимов ---------------------
run_full() {
    echo -e "${GREEN}Скрипт запущен в режиме: Full${NC}"
    detect_distro
    install_dependencies
    fill_params_file
    setup_bot_params
    install_bot
}

run_light() {
    echo -e "${GREEN}Скрипт запущен в режиме: Light${NC}"
    detect_distro
    install_dependencies
    if [ ! -f "$PARAMS_FILE" ]; then
        echo -e "${YELLOW}Файл $PARAMS_FILE не найден. Создаём...${NC}"
        fill_params_file
    fi
    setup_bot_params
    install_bot
}

# --------------------- Запуск ---------------------
MODE=$1
if [ -z "$MODE" ]; then
    echo "Выберите режим установки:"
    echo "1) Полная установка WireGuard + бот"
    echo "2) Установка только бота"
    read -rp "Введите 1 или 2: " choice
    case "$choice" in
        1) MODE="full" ;;
        2) MODE="light" ;;
        *) echo -e "${RED}Неверный выбор${NC}" ; exit 1 ;;
    esac
fi

case "$MODE" in
    full) run_full ;;
    light) run_light ;;
    *) echo -e "${RED}Неверный режим${NC}" ; exit 1 ;;
esac
