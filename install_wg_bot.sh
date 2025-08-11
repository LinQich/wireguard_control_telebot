#!/usr/bin/env bash
set -euo pipefail

#
# install_wg_bot.sh
# Universal installer for WireGuard + Telegram bot (full | light)
#
# Usage:
#   sudo bash install_wg_bot.sh full
#   sudo bash install_wg_bot.sh light
#   sudo bash install_wg_bot.sh        # interactive menu
#
# Features:
# - Detects distro (Debian/Ubuntu or RHEL-family)
# - Full mode: installs WireGuard, generates keys, creates /etc/wireguard/params and wg0.conf,
#              opens firewall, enables IP forwarding, optionally creates first client,
#              installs bot and systemd service.
# - Light mode: installs only bot; verifies (and interactively fills) /etc/wireguard/params
# - Picks random server port in 49152-65535 (if not provided)
# - Uses wget or curl automatically when run online via the one-liner
# - Shows final systemd service status
#

# -------------------- Config --------------------
REPO_URL="https://github.com/LinQich/wireguard_control_telebot.git"
BOT_FILE="wg_bot1.py"
INSTALL_DIR="/opt/wireguard_control_telebot"
WG_DIR="/etc/wireguard"
CLIENTS_DIR="${WG_DIR}/clients"
PARAMS_FILE="${WG_DIR}/params"
BOT_PARAMS_FILE="${WG_DIR}/bot_params"
WG_CONF="${WG_DIR}/wg0.conf"
SERVICE_NAME="wg_bot"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
DEFAULT_WG_IP="10.66.66.1"
RANDOM_PORT_MIN=49152
RANDOM_PORT_MAX=65535

# colors
GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
NC="\e[0m"

# -------------------- Helpers --------------------
log()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    error "Скрипт должен быть запущен с правами root. Выполните: sudo $0"
    exit 1
  fi
}

detect_online_run() {
  # If running from process substitution or from pipe, $0 is -bash or similar.
  if [ -t 0 ]; then
    echo "local"
  else
    echo "online"
  fi
}

choose_downloader_cmd() {
  if command -v wget >/dev/null 2>&1; then
    echo "wget -qO-"
  elif command -v curl >/dev/null 2>&1; then
    echo "curl -fsSL"
  else
    echo ""
  fi
}

detect_pkg_manager() {
  if command -v apt >/dev/null 2>&1; then
    PKG="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PKG="dnf"
  elif command -v yum >/dev/null 2>&1; then
    PKG="yum"
  else
    error "Не удалось определить пакетный менеджер (ожидается apt, dnf или yum)."
    exit 1
  fi
  log "Пакетный менеджер: ${PKG}"
}

rand_port() {
  if command -v shuf >/dev/null 2>&1; then
    shuf -i ${RANDOM_PORT_MIN}-${RANDOM_PORT_MAX} -n 1
  else
    echo $(( ( RANDOM % (RANDOM_PORT_MAX - RANDOM_PORT_MIN + 1) ) + RANDOM_PORT_MIN ))
  fi
}

is_private_ipv4() {
  local ip=$1
  if [[ $ip =~ ^10\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
     [[ $ip =~ ^192\.168\.[0-9]+\.[0-9]+$ ]] || \
     [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+$ ]]; then
    return 0
  fi
  return 1
}

prompt_private_ip() {
  local input
  while true; do
    read -rp "Введите начальный IPv4 адрес сети WireGuard (пример ${DEFAULT_WG_IP}) [Enter для дефолта]: " input
    input=${input:-$DEFAULT_WG_IP}
    if is_private_ipv4 "$input"; then
      echo "$input"
      return 0
    else
      warn "Адрес не в приватных диапазонах RFC1918. Попробуйте ещё раз."
    fi
  done
}

ensure_dirs() {
  mkdir -p "${WG_DIR}"
  mkdir -p "${CLIENTS_DIR}"
  mkdir -p "${INSTALL_DIR}"
  chmod 700 "${WG_DIR}" || true
  chmod 700 "${CLIENTS_DIR}" || true
}

install_system_packages() {
  log "Устанавливаем системные пакеты..."
  if [[ "${PKG}" == "apt" ]]; then
    apt update
    apt install -y wireguard qrencode python3 python3-pip python3-venv git curl fonts-noto-color-emoji ufw iproute2 iptables || true
  else
    # RHEL-family
    ${PKG} install -y epel-release || true
    ${PKG} install -y wireguard-tools qrencode python3 python3-pip python3-virtualenv git curl google-noto-emoji-color-fonts firewalld iproute || true
  fi
}

install_python_deps() {
  log "Устанавливаем Python-библиотеки..."
  python3 -m pip install --upgrade pip
  python3 -m pip install "python-telegram-bot>=20.0" qrcode[pil] Pillow || true
}

create_params_interactive() {
  log "Создаём/дополняем ${PARAMS_FILE}"
  mkdir -p "${WG_DIR}"

  local server_pub_ip server_pub_nic server_wg_nic server_wg_ipv4 server_wg_ipv6 server_port server_priv server_pub dns1 dns2 allowed

  server_pub_ip=$(curl -s ifconfig.me || echo "")
  read -rp "Внешний IP сервера [${server_pub_ip}]: " tmp
  server_pub_ip=${tmp:-$server_pub_ip}

  server_pub_nic=$(ip -o -4 route show to default | awk '{print $5;exit}' || echo "")
  read -rp "Сетевой интерфейс сервера для NAT [${server_pub_nic}]: " tmp
  server_pub_nic=${tmp:-$server_pub_nic}

  read -rp "Имя интерфейса WireGuard [wg0]: " tmp
  server_wg_nic=${tmp:-wg0}

  server_wg_ipv4=$(prompt_private_ip)

  read -rp "IPv6 адрес для WireGuard [fd42:42:42::1]: " tmp
  server_wg_ipv6=${tmp:-fd42:42:42::1}

  read -rp "Порт WireGuard [Enter => случайный 49152–65535]: " tmp
  server_port=${tmp:-$(rand_port)}

  # try to reuse existing keys if present
  if [[ -f "${WG_DIR}/server_private.key" ]]; then
    server_priv=$(cat "${WG_DIR}/server_private.key")
    server_pub=$(echo "${server_priv}" | wg pubkey)
  else
    server_priv=$(wg genkey)
    server_pub=$(echo "${server_priv}" | wg pubkey)
    # save private key locally
    echo "${server_priv}" > "${WG_DIR}/server_private.key"
    chmod 600 "${WG_DIR}/server_private.key"
  fi

  read -rp "DNS1 [8.8.8.8]: " tmp
  dns1=${tmp:-8.8.8.8}
  read -rp "DNS2 [8.8.4.4]: " tmp
  dns2=${tmp:-8.8.4.4}
  allowed="0.0.0.0/0,::/0"

  cat > "${PARAMS_FILE}" <<EOF
SERVER_PUB_IP=${server_pub_ip}
SERVER_PUB_NIC=${server_pub_nic}
SERVER_WG_NIC=${server_wg_nic}
SERVER_WG_IPV4=${server_wg_ipv4}
SERVER_WG_IPV6=${server_wg_ipv6}
SERVER_PORT=${server_port}
SERVER_PRIV_KEY=${server_priv}
SERVER_PUB_KEY=${server_pub}
CLIENT_DNS_1=${dns1}
CLIENT_DNS_2=${dns2}
ALLOWED_IPS=${allowed}
EOF

  chmod 600 "${PARAMS_FILE}"
  log "Файл ${PARAMS_FILE} создан/обновлён (порт ${server_port})"
}

validate_and_fill_params_light() {
  # Check required keys and interactively ask for missing ones
  ensure_dirs
  touch "${PARAMS_FILE}"
  chmod 600 "${PARAMS_FILE}"
  local required=(SERVER_PUB_IP SERVER_PUB_NIC SERVER_WG_NIC SERVER_WG_IPV4 SERVER_WG_IPV6 SERVER_PORT SERVER_PRIV_KEY SERVER_PUB_KEY CLIENT_DNS_1 CLIENT_DNS_2 ALLOWED_IPS)
  local missing=()
  for k in "${required[@]}"; do
    if ! grep -qE "^${k}=" "${PARAMS_FILE}"; then
      missing+=("$k")
    fi
  done

  if ((${#missing[@]})); then
    warn "В ${PARAMS_FILE} не хватает параметров: ${missing[*]}"
    read -rp "Хотите заполнить недостающие параметры интерактивно? [Y/n]: " ans
    ans=${ans:-Y}
    if [[ "${ans,,}" =~ ^y ]]; then
      create_params_interactive
    else
      error "Заполните ${PARAMS_FILE} вручную и повторите установку."
      exit 1
    fi
  else
    log "Файл ${PARAMS_FILE} содержит все обязательные параметры."
  fi
}

create_wg_conf_from_params() {
  source "${PARAMS_FILE}"
  local addr="${SERVER_WG_IPV4}/24"
  local listen="${SERVER_PORT}"
  local priv="${SERVER_PRIV_KEY}"
  local pubnic="${SERVER_PUB_NIC:-$(ip -o -4 route show to default | awk '{print $5; exit}')}"
  cat > "${WG_CONF}" <<EOF
[Interface]
Address = ${addr}
ListenPort = ${listen}
PrivateKey = ${priv}
SaveConfig = true
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${pubnic} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${pubnic} -j MASQUERADE
EOF
  chmod 600 "${WG_CONF}"
  log "Сформирован ${WG_CONF}"
}

firewall_configure() {
  source "${PARAMS_FILE}"
  if [[ "${PKG}" == "apt" ]]; then
    log "Настраиваем ufw..."
    if ! command -v ufw >/dev/null 2>&1; then
      apt install -y ufw || true
    fi
    ufw allow "${SERVER_PORT}/udp" || true
    ufw reload || true
  else
    log "Настраиваем firewalld..."
    systemctl enable --now firewalld || true
    firewall-cmd --permanent --add-port="${SERVER_PORT}/udp" || true
    firewall-cmd --permanent --add-masquerade || true
    firewall-cmd --reload || true
  fi
}

enable_ip_forwarding() {
  log "Включаем IP форвардинг..."
  mkdir -p /etc/sysctl.d
  cat > /etc/sysctl.d/99-wireguard-forward.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
  sysctl --system >/dev/null || true
}

start_wireguard_service() {
  log "Активируем wg-quick@${SERVER_WG_NIC:-wg0}..."
  systemctl enable --now "wg-quick@${SERVER_WG_NIC:-wg0}" || true
}

create_first_client_optional() {
  source "${PARAMS_FILE}"
  read -rp "Создать первого клиента (client1) прямо сейчас? [Y/n]: " ans
  ans=${ans:-Y}
  if [[ "${ans,,}" =~ ^y ]]; then
    CLIENT_NAME="client1"
    CLIENT_PRIV=$(wg genkey)
    CLIENT_PUB=$(echo "${CLIENT_PRIV}" | wg pubkey)
    CLIENT_PSK=$(wg genpsk)
    # server ip e.g. 10.x.y.z -> client gets .2
    IFS='.' read -r a b c d <<< "${SERVER_WG_IPV4}"
    client_octet=$((d+1))
    CLIENT_IP="${a}.${b}.${c}.${client_octet}"
    # runtime add peer
    wg set "${SERVER_WG_NIC:-wg0}" peer "${CLIENT_PUB}" preshared-key /dev/stdin allowed-ips "${CLIENT_IP}/32" <<< "${CLIENT_PSK}" || true
    # append to wg0.conf
    cat >> "${WG_CONF}" <<EOF

[Peer]
PublicKey = ${CLIENT_PUB}
PresharedKey = ${CLIENT_PSK}
AllowedIPs = ${CLIENT_IP}/32
EOF
    CLIENT_CONF="${CLIENTS_DIR}/${CLIENT_NAME}.conf"
    cat > "${CLIENT_CONF}" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = ${CLIENT_IP}/24
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PSK}
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive = 25
EOF
    chmod 600 "${CLIENT_CONF}"
    # QR generation
    if command -v qrencode >/dev/null 2>&1; then
      qrencode -o "${CLIENTS_DIR}/${CLIENT_NAME}.png" -t png < "${CLIENT_CONF}" || true
    else
      python3 - <<PY || true
import qrcode
txt=open("${CLIENT_CONF}").read()
img=qrcode.make(txt)
img.save("${CLIENTS_DIR}/${CLIENT_NAME}.png")
PY
    fi
    log "Создан клиент: ${CLIENT_CONF}"
    log "QR: ${CLIENTS_DIR}/${CLIENT_NAME}.png"
  fi
}

clone_and_install_bot() {
  log "Клонируем бота в ${INSTALL_DIR}..."
  rm -rf "${INSTALL_DIR}"
  git clone --depth 1 "${REPO_URL}" "${INSTALL_DIR}"
  chmod -R 755 "${INSTALL_DIR}" || true
  if [[ -f "${INSTALL_DIR}/requirements.txt" ]]; then
    python3 -m pip install -r "${INSTALL_DIR}/requirements.txt" || true
  else
    install_python_deps
  fi
}

create_bot_params_interactive() {
  log "Создаём ${BOT_PARAMS_FILE}..."
  read -rp "Введите TOKEN (BotFather): " token
  read -rp "Введите ADMIN_IDS (через пробел или запятую): " admin_raw
  admin_raw="${admin_raw%%#*}"
  admin_raw="${admin_raw//,/ }"
  mkdir -p "$(dirname "${BOT_PARAMS_FILE}")"
  cat > "${BOT_PARAMS_FILE}" <<EOF
TOKEN=${token}
ADMIN_IDS=${admin_raw}
EOF
  chmod 600 "${BOT_PARAMS_FILE}"
  log "${BOT_PARAMS_FILE} создан."
}

create_systemd_bot_service() {
  log "Создаём systemd-сервис ${SERVICE_NAME}..."
  cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=WireGuard Telegram Bot
After=network.target

[Service]
Type=simple
ExecStartPre=/bin/bash -c 'if [ -f "${PARAMS_FILE}" ]; then PORT=\$(grep "^SERVER_PORT=" "${PARAMS_FILE}" | cut -d'=' -f2); if [ -n "\$PORT" ]; then if command -v ufw >/dev/null 2>&1; then ufw allow \${PORT}/udp || true; elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --permanent --add-port=\${PORT}/udp >/dev/null 2>&1 || true; firewall-cmd --reload >/dev/null 2>&1 || true; fi; fi; fi'
ExecStart=/usr/bin/python3 "${INSTALL_DIR}/${BOT_FILE}"
Restart=on-failure
WorkingDirectory=${INSTALL_DIR}
User=root

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}" || true
}

check_service_status() {
  sleep 2
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    log "✅ Сервис ${SERVICE_NAME} запущен."
    journalctl -u "${SERVICE_NAME}" --no-pager -n 5
  else
    error "❌ Сервис ${SERVICE_NAME} не запущен. Посмотрите логи:"
    journalctl -u "${SERVICE_NAME}" -e | sed -n '1,120p'
    exit 1
  fi
}

# -------------------- Modes --------------------
full_mode() {
  log "Скрипт запущен в режиме: Full"
  detect_pkg_manager
  install_system_packages
  ensure_dirs
  # create params interactively
  create_params_interactive
  create_wg_conf_from_params
  firewall_configure
  enable_ip_forwarding
  start_wireguard_service
  create_first_client_optional
  clone_and_install_bot
  create_bot_params_interactive
  create_systemd_bot_service
  check_service_status
  log "Full install завершён. Параметры в ${PARAMS_FILE}"
}

light_mode() {
  log "Скрипт запущен в режиме: Light"
  detect_pkg_manager
  install_system_packages
  ensure_dirs
  validate_and_fill_params_light
  clone_and_install_bot
  create_bot_params_interactive
  create_systemd_bot_service
  check_service_status
  log "Light install завершён."
}

# -------------------- Entrypoint --------------------
require_root

RUNMODE=""
if [[ "${#@}" -ge 1 ]]; then
  arg1="${1,,}"
  if [[ "${arg1}" == "full" || "${arg1}" == "light" ]]; then
    RUNMODE="${arg1}"
  else
    error "Неправильный аргумент. Используйте 'full' или 'light'."
    exit 1
  fi
else
  echo "Выберите режим установки:"
  echo " 1) Full  - полная установка WireGuard + бот"
  echo " 2) Light - установка только бота (WireGuard уже настроен)"
  read -rp "Введите 1 или 2: " choice
  case "${choice}" in
    1) RUNMODE="full" ;;
    2) RUNMODE="light" ;;
    *) error "Неверный выбор"; exit 1 ;;
  esac
fi

# report online/local
runmode_type=$(detect_online_run)
log "Запуск скрипта (${runmode_type}) в режиме: ${RUNMODE}"

# detect package manager early
detect_pkg_manager

# execute mode
if [[ "${RUNMODE}" == "full" ]]; then
  full_mode
else
  light_mode
fi

log "Готово. Рекомендуется проверить содержимое ${PARAMS_FILE}, ${BOT_PARAMS_FILE} и логи systemd."
