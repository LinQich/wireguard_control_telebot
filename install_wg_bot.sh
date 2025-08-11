#!/usr/bin/env bash
set -euo pipefail

# install_wg_bot.sh
# Universal installer for WireGuard + Telegram bot
# Usage:
#   sudo ./install_wg_bot.sh full   # full install: wg server + bot
#   sudo ./install_wg_bot.sh light  # light install: only bot, wg must exist

# ----------------------- CONFIG -----------------------
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

# ----------------------- HELPERS -----------------------
log() { echo -e "\e[1;32m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }
err() { echo -e "\e[1;31m[ERROR]\e[0m $*" >&2; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Запустите скрипт от root (sudo)."
    exit 1
  fi
}

detect_pkg_manager() {
  if command -v apt >/dev/null 2>&1; then
    PKG="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PKG="dnf"
  else
    err "Поддерживаются только Debian/Ubuntu или RHEL-family (dnf)."
    exit 1
  fi
  log "Пакетный менеджер: ${PKG}"
}

safe_mkdirs() {
  mkdir -p "${WG_DIR}"
  mkdir -p "${CLIENTS_DIR}"
  mkdir -p "${INSTALL_DIR}"
  chmod 700 "${WG_DIR}"
  chmod 700 "${CLIENTS_DIR}"
}

rand_port() {
  if command -v shuf >/dev/null 2>&1; then
    shuf -i ${RANDOM_PORT_MIN}-${RANDOM_PORT_MAX} -n 1
  else
    # bash random fallback
    echo $(( ( RANDOM % (RANDOM_PORT_MAX - RANDOM_PORT_MIN + 1) ) + RANDOM_PORT_MIN ))
  fi
}

is_private_ipv4() {
  local ip=$1
  # simple validation: matches RFC1918 blocks
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
    read -rp "Введите начальный IPv4 адрес сети WireGuard (пример: ${DEFAULT_WG_IP}) [Enter для дефолта]: " input
    input=${input:-$DEFAULT_WG_IP}
    if is_private_ipv4 "$input"; then
      echo "$input"
      return 0
    else
      warn "Адрес не из приватных диапазонов RFC1918. Попробуйте снова."
    fi
  done
}

install_packages() {
  log "Устанавливаем системные пакеты..."
  if [[ "${PKG}" == "apt" ]]; then
    apt update
    apt install -y wireguard qrencode python3 python3-pip python3-venv git curl fonts-noto-color-emoji ufw
  else
    dnf install -y epel-release || true
    dnf install -y wireguard-tools qrencode python3 python3-pip python3-virtualenv git curl google-noto-emoji-color-fonts firewalld
  fi
}

install_python_deps() {
  log "Устанавливаем python-библиотеки..."
  python3 -m pip install --upgrade pip
  # require compatible python-telegram-bot; user used v20 earlier
  python3 -m pip install "python-telegram-bot>=20.0" qrcode[pil] Pillow
}

create_params_file() {
  local server_pub_ip server_pub_nic server_priv server_pub server_port server_wg_ip server_wg_ipv6
  server_wg_ip="$1"   # passed as e.g. 10.66.66.1
  server_wg_ipv6="fd42:42:42::1"
  server_priv=$(wg genkey)
  server_pub=$(echo "${server_priv}" | wg pubkey)
  server_pub_ip=$(curl -s ifconfig.me || echo "")
  server_pub_nic=$(ip -o -4 route show to default | awk '{print $5;exit}' || echo "")
  server_port=$(rand_port)
  cat > "${PARAMS_FILE}" <<EOF
SERVER_PUB_IP=${server_pub_ip}
SERVER_PUB_NIC=${server_pub_nic}
SERVER_WG_NIC=wg0
SERVER_WG_IPV4=${server_wg_ip}
SERVER_WG_IPV6=${server_wg_ipv6}
SERVER_PORT=${server_port}
SERVER_PRIV_KEY=${server_priv}
SERVER_PUB_KEY=${server_pub}
CLIENT_DNS_1=1.1.1.1
CLIENT_DNS_2=8.8.8.8
ALLOWED_IPS=0.0.0.0/0,::/0
EOF
  chmod 600 "${PARAMS_FILE}"
  log "Создан ${PARAMS_FILE} (порт ${server_port})"
}

create_wg_conf() {
  # read params
  source "${PARAMS_FILE}"
  local addr="${SERVER_WG_IPV4}/24"
  local v6="${SERVER_WG_IPV6}"
  local listen="${SERVER_PORT}"
  local priv="${SERVER_PRIV_KEY}"
  local pubnic="${SERVER_PUB_NIC}"
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
  log "Создан ${WG_CONF}"
}

firewall_setup() {
  source "${PARAMS_FILE}"
  if [[ "${PKG}" == "apt" ]]; then
    log "Устанавливаем/настраиваем ufw..."
    # ensure ufw enabled
    if ! command -v ufw >/dev/null 2>&1; then
      apt install -y ufw || true
    fi
    ufw allow "${SERVER_PORT}/udp" || true
    ufw reload || true
  else
    log "Настраиваем firewalld..."
    systemctl enable --now firewalld
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

start_wireguard() {
  log "Включаем и запускаем интерфейс wg-quick@wg0..."
  systemctl enable --now wg-quick@wg0 || true
}

clone_bot() {
  log "Клонируем бота в ${INSTALL_DIR}..."
  rm -rf "${INSTALL_DIR}"
  git clone --depth 1 "${REPO_URL}" "${INSTALL_DIR}"
  chmod -R 755 "${INSTALL_DIR}"
}

create_bot_params() {
  local token admin_raw
  read -rp "Введите TOKEN (получите у @BotFather): " token
  read -rp "Введите ADMIN_ID (узнайте у @getmyid_bot). Можно несколько через запятую/пробел: " admin_raw
  mkdir -p "$(dirname "${BOT_PARAMS_FILE}")"
  # sanitize ADMIN_IDS: remove comments
  admin_raw="${admin_raw%%#*}"
  cat > "${BOT_PARAMS_FILE}" <<EOF
TOKEN=${token}
ADMIN_IDS=${admin_raw}
EOF
  chmod 600 "${BOT_PARAMS_FILE}"
  log "Создан ${BOT_PARAMS_FILE}"
}

create_systemd_service() {
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
  systemctl enable --now "${SERVICE_NAME}"
  log "Сервис ${SERVICE_NAME} создан и запущен"
}

check_port_remote() {
  source "${PARAMS_FILE}"
  if command -v nc >/dev/null 2>&1; then
    if nc -z -w3 "${SERVER_PUB_IP}" "${SERVER_PORT}" >/dev/null 2>&1; then
      log "Порт ${SERVER_PORT} доступен снаружи (${SERVER_PUB_IP}:${SERVER_PORT})"
    else
      warn "Порт ${SERVER_PORT} кажется закрытым извне. Проверьте провайдера/фаервол."
    fi
  else
    warn "nc не найден: пропускаем проверку доступности порта."
  fi
}

# ----------------------- LIGHT MODE (only bot) -----------------------
light_mode_install() {
  detect_pkg_manager
  safe_mkdirs
  # check params file
  if [[ ! -f "${PARAMS_FILE}" ]]; then
    err "${PARAMS_FILE} не найден. В режиме light требуется настроенный WireGuard."
    exit 1
  fi

  # verify required keys present
  local required=(SERVER_PUB_IP SERVER_PUB_NIC SERVER_WG_NIC SERVER_WG_IPV4 SERVER_WG_IPV6 SERVER_PORT SERVER_PRIV_KEY SERVER_PUB_KEY CLIENT_DNS_1 CLIENT_DNS_2 ALLOWED_IPS)
  local miss=()
  for k in "${required[@]}"; do
    if ! grep -q "^${k}=" "${PARAMS_FILE}"; then
      miss+=("${k}")
    fi
  done
  if ((${#miss[@]})); then
    err "В ${PARAMS_FILE} отсутствуют обязательные параметры: ${miss[*]}"
    exit 1
  fi

  install_packages
  install_python_deps
  clone_bot
  create_bot_params
  create_systemd_service
  check_port_remote

  log "Light install завершен. Проверьте логи: journalctl -u ${SERVICE_NAME} -f"
}

# ----------------------- FULL MODE (wg + bot) -----------------------
full_mode_install() {
  detect_pkg_manager
  install_packages
  install_python_deps
  safe_mkdirs

  # ask network
  local chosen_ip
  chosen_ip=$(prompt_private_ip)
  log "Выбрана сеть: ${chosen_ip}"

  create_params_file "${chosen_ip}"
  create_wg_conf
  firewall_setup
  enable_ip_forwarding
  start_wireguard

  # optional: create first client?
  read -rp "Создать первого клиента (client1) сразу сейчас? [Y/n]: " create_client
  create_client=${create_client:-Y}
  if [[ "${create_client,,}" =~ ^y ]]; then
    # create client keys and conf, save to /etc/wireguard/clients
    source "${PARAMS_FILE}"
    CLIENT_NAME="client1"
    CLIENT_PRIV=$(wg genkey)
    CLIENT_PUB=$(echo "${CLIENT_PRIV}" | wg pubkey)
    CLIENT_PSK=$(wg genpsk)
    # compute client IP (server ip like 10.x.y.z => client gets .2)
    IFS='.' read -r a b c d <<< "${SERVER_WG_IPV4}"
    client_octet=$((d+1))
    CLIENT_IP="${a}.${b}.${c}.${client_octet}"
    # add peer runtime and to wg0.conf
    # add via wg set (preshared-key from stdin)
    if command -v sudo >/dev/null 2>&1; then
      sudo wg set wg0 peer "${CLIENT_PUB}" preshared-key /dev/stdin allowed-ips "${CLIENT_IP}/32" <<< "${CLIENT_PSK}" || true
    else
      wg set wg0 peer "${CLIENT_PUB}" preshared-key /dev/stdin allowed-ips "${CLIENT_IP}/32" <<< "${CLIENT_PSK}" || true
    fi
    # append to wg0.conf persistently
    cat >> "${WG_CONF}" <<EOF

[Peer]
PublicKey = ${CLIENT_PUB}
PresharedKey = ${CLIENT_PSK}
AllowedIPs = ${CLIENT_IP}/32
EOF

    CLIENT_CONF_PATH="${CLIENTS_DIR}/${CLIENT_NAME}.conf"
    cat > "${CLIENT_CONF_PATH}" <<EOF
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
    chmod 600 "${CLIENT_CONF_PATH}"
    # generate QR if qrencode exists or via python qrcode lib later; try qrencode first
    if command -v qrencode >/dev/null 2>&1; then
      qrencode -o "${CLIENTS_DIR}/${CLIENT_NAME}.png" -t png < "${CLIENT_CONF_PATH}" || true
    else
      # fallback: create basic PNG via python - but skip if python deps not available
      python3 - <<PYCODE || true
import qrcode, sys
txt=open("${CLIENT_CONF_PATH}").read()
img=qrcode.make(txt)
img.save("${CLIENTS_DIR}/${CLIENT_NAME}.png")
PYCODE
    fi
    log "Первый клиент создан: ${CLIENT_CONF_PATH}"
    log "QR: ${CLIENTS_DIR}/${CLIENT_NAME}.png"
  fi

  clone_bot
  create_bot_params
  create_systemd_service
  check_port_remote

  log "Full install завершен. Проверьте логи: journalctl -u ${SERVICE_NAME} -f"
}

# ----------------------- ENTRYPOINT -----------------------
require_root

if [[ "${#@}" -lt 1 ]]; then
  echo "Usage: $0 full|light"
  exit 1
fi

MODE="$1"
case "${MODE}" in
  full)
    full_mode_install
    ;;
  light)
    light_mode_install
    ;;
  *)
    echo "Unknown mode: ${MODE}"
    echo "Usage: $0 full|light"
    exit 1
    ;;
esac
