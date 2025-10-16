#!/usr/bin/env bash
set -euo pipefail

add_more_clients() {
  local skip_prompt="${1:-false}"

  if [[ "$skip_prompt" != "true" ]]; then
    read -rp "是否继续添加更多客户端？(y/N): " ADD_MORE
    [[ "${ADD_MORE,,}" == "y" ]] || return
  else
    echo "开始添加新客户端..."
  fi

  install -d -m 700 /etc/wireguard/clients

  declare -A USED_HOSTS=()

  local SERVER_HOST="${SERVER_IP##*.}"
  [[ -n "$SERVER_HOST" ]] && USED_HOSTS["$SERVER_HOST"]=1

  if [[ -n "${CLIENT_IP:-}" ]]; then
    local CLIENT_HOST="${CLIENT_IP##*.}"
    [[ -n "$CLIENT_HOST" ]] && USED_HOSTS["$CLIENT_HOST"]=1
  fi

  if [[ -d /etc/wireguard/clients ]]; then
    while IFS= read -r CONF_FILE; do
      local ADDR_LINE
      ADDR_LINE="$(grep -m1 '^Address = ' "$CONF_FILE" || true)"
      if [[ -n "$ADDR_LINE" ]]; then
        local ADDR_VALUE="${ADDR_LINE#Address = }"
        local ADDR_IP="${ADDR_VALUE%%/*}"
        local HOST_OCT="${ADDR_IP##*.}"
        [[ -n "$HOST_OCT" ]] && USED_HOSTS["$HOST_OCT"]=1
      fi
    done < <(find /etc/wireguard/clients -maxdepth 2 -type f -name '*.conf' 2>/dev/null)
  fi

  local NEXT_HOST=0
  for HOST in "${!USED_HOSTS[@]}"; do
    if (( HOST > NEXT_HOST )); then
      NEXT_HOST=$HOST
    fi
  done
  NEXT_HOST=$((NEXT_HOST+1))

  while true; do
    read -rp "新客户端名称: " NEWC
    [[ -z "$NEWC" ]] && break

    install -d -m 700 "/etc/wireguard/clients/${NEWC}"

    umask 077
    wg genkey | tee "/etc/wireguard/clients/${NEWC}/${NEWC}_privatekey" | wg pubkey > "/etc/wireguard/clients/${NEWC}/${NEWC}_publickey"
    local NEWC_PRIV="$(cat "/etc/wireguard/clients/${NEWC}/${NEWC}_privatekey")"
    local NEWC_PUB="$(cat "/etc/wireguard/clients/${NEWC}/${NEWC}_publickey")"

    while [[ -n "${USED_HOSTS[$NEXT_HOST]:-}" ]]; do
      NEXT_HOST=$((NEXT_HOST+1))
      if (( NEXT_HOST >= 255 )); then
        echo "IPv4 网段已无可用地址，无法继续添加。"
        return
      fi
    done

    local NEWC_IP="${o1}.${o2}.${o3}.${NEXT_HOST}"
    USED_HOSTS["$NEXT_HOST"]=1
    NEXT_HOST=$((NEXT_HOST+1))

    local NEWC_CONF="/etc/wireguard/clients/${NEWC}/${NEWC}.conf"
    cat > "$NEWC_CONF" <<EOF
[Interface]
PrivateKey = ${NEWC_PRIV}
Address = ${NEWC_IP}/${WG_PREFIX}
DNS = ${DNS_IP}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
Endpoint = ${ENDPOINT_HOST}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    chmod 600 "$NEWC_CONF"

    wg set wg0 peer "${NEWC_PUB}" allowed-ips "${NEWC_IP}/32"

    echo "已创建客户端 ${NEWC}，配置文件：${NEWC_CONF}"
    if command -v qrencode >/dev/null 2>&1; then
      echo "二维码如下："
      qrencode -t ansiutf8 < "${NEWC_CONF}"
    fi

    read -rp "继续添加下一个？(y/N): " CONT
    [[ "${CONT,,}" == "y" ]] || break
  done
}

# =============== 基本校验 ===============
if [[ $EUID -ne 0 ]]; then
  echo "请用 root 运行：sudo $0"
  exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
  echo "缺少 iproute2/ip 命令，请先安装基础网络组件。"
  exit 1
fi

WG_CONF_PATH="/etc/wireguard/wg0.conf"
if [[ -f "$WG_CONF_PATH" ]]; then
  echo "检测到 WireGuard 已部署。"
  read -rp "是否继续添加客户端？(y/N): " ADD_ON_EXIST
  if [[ "${ADD_ON_EXIST,,}" != "y" ]]; then
    echo "已取消，未做任何修改。"
    exit 0
  fi

  SERVER_ADDR_LINE="$(grep -m1 '^Address = ' "$WG_CONF_PATH" || true)"
  if [[ -z "$SERVER_ADDR_LINE" ]]; then
    echo "无法从 ${WG_CONF_PATH} 读取 Address 字段，请检查现有配置。"
    exit 1
  fi

  SERVER_ADDR_VALUE="${SERVER_ADDR_LINE#Address = }"
  SERVER_IP="${SERVER_ADDR_VALUE%%/*}"
  WG_PREFIX="${SERVER_ADDR_VALUE##*/}"
  if [[ -z "${SERVER_IP:-}" || -z "${WG_PREFIX:-}" ]]; then
    echo "无法解析服务端地址或掩码，请检查现有配置。"
    exit 1
  fi

  IFS='.' read -r o1 o2 o3 o4 <<<"$SERVER_IP"

  LISTEN_LINE="$(grep -m1 '^ListenPort = ' "$WG_CONF_PATH" || true)"
  WG_PORT="${LISTEN_LINE#ListenPort = }"
  WG_PORT="${WG_PORT:-51820}"

  SERVER_PUB_KEY="$(cat /etc/wireguard/server_publickey 2>/dev/null || true)"
  if [[ -z "$SERVER_PUB_KEY" && -f /etc/wireguard/server_privatekey ]]; then
    SERVER_PUB_KEY="$(wg pubkey < /etc/wireguard/server_privatekey 2>/dev/null || true)"
  fi
  if [[ -z "$SERVER_PUB_KEY" ]]; then
    SERVER_PUB_KEY="$(wg show wg0 public-key 2>/dev/null || true)"
  fi
  if [[ -z "$SERVER_PUB_KEY" ]]; then
    echo "无法获取服务端公钥，请确认现有部署正常。"
    exit 1
  fi

  DNS_IP=""
  ENDPOINT_HOST=""
  CLIENT_IP=""

  FIRST_CLIENT_CONF="$(find /etc/wireguard/clients -maxdepth 2 -type f -name '*.conf' -print -quit 2>/dev/null || true)"
  if [[ -n "$FIRST_CLIENT_CONF" ]]; then
    CLIENT_ADDR_LINE="$(grep -m1 '^Address = ' "$FIRST_CLIENT_CONF" || true)"
    if [[ -n "$CLIENT_ADDR_LINE" ]]; then
      CLIENT_ADDR_VALUE="${CLIENT_ADDR_LINE#Address = }"
      CLIENT_IP="${CLIENT_ADDR_VALUE%%/*}"
    fi

    DNS_LINE="$(grep -m1 '^DNS = ' "$FIRST_CLIENT_CONF" || true)"
    if [[ -n "$DNS_LINE" ]]; then
      DNS_IP="${DNS_LINE#DNS = }"
    fi

    ENDPOINT_LINE="$(grep -m1 '^Endpoint = ' "$FIRST_CLIENT_CONF" || true)"
    if [[ -n "$ENDPOINT_LINE" ]]; then
      ENDPOINT_VALUE="${ENDPOINT_LINE#Endpoint = }"
      if [[ "$ENDPOINT_VALUE" == \[*\]*:* ]]; then
        ENDPOINT_HOST="${ENDPOINT_VALUE%%]*}"
        ENDPOINT_HOST="${ENDPOINT_HOST#[}"
        ENDPOINT_PORT="${ENDPOINT_VALUE##*:}"
      else
        ENDPOINT_HOST="${ENDPOINT_VALUE%:*}"
        ENDPOINT_PORT="${ENDPOINT_VALUE##*:}"
      fi
      if [[ "$ENDPOINT_PORT" =~ ^[0-9]+$ ]]; then
        WG_PORT="$ENDPOINT_PORT"
      fi
    fi
  fi

  DNS_IP="${DNS_IP:-8.8.8.8}"
  ENDPOINT_HOST="${ENDPOINT_HOST:-<REPLACE_ME>}"

  add_more_clients true
  exit 0
fi

# =============== 发行版检测 ===============
OS_ID=""; OS_VER_ID=""
if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-}"; OS_VER_ID="${VERSION_ID:-}"
else
  echo "无法检测系统类型（缺少 /etc/os-release）"; exit 1
fi

echo "检测到系统：${OS_ID} ${OS_VER_ID}"

# =============== 交互式参数 ===============
read -rp "WireGuard UDP 端口 [默认 51820]: " WG_PORT
WG_PORT=${WG_PORT:-51820}

read -rp "WireGuard 网段（IPv4）[默认 10.0.0.0/24]: " WG_SUBNET
WG_SUBNET=${WG_SUBNET:-10.0.0.0/24}

# 计算服务端/首个客户端的地址
WG_NET_BASE="${WG_SUBNET%/*}"
WG_PREFIX="${WG_SUBNET#*/}"
IFS='.' read -r o1 o2 o3 o4 <<<"$WG_NET_BASE"
SERVER_IP="${o1}.${o2}.${o3}.1"
CLIENT_IP="${o1}.${o2}.${o3}.2"

read -rp "服务端隧道地址 [默认 ${SERVER_IP}]: " SERVER_IP_IN
SERVER_IP=${SERVER_IP_IN:-$SERVER_IP}

read -rp "首个客户端地址（/32）[默认 ${CLIENT_IP}]: " CLIENT_IP_IN
CLIENT_IP=${CLIENT_IP_IN:-$CLIENT_IP}

read -rp "DNS（客户端使用）[默认 8.8.8.8]: " DNS_IP
DNS_IP=${DNS_IP:-8.8.8.8}

# 自动探测出口网卡
DEFAULT_WAN_IF=""
DEFAULT_ROUTE_OUTPUT="$(ip route get 1.1.1.1 2>/dev/null || true)"
if [[ -n "$DEFAULT_ROUTE_OUTPUT" ]]; then
  DEFAULT_WAN_IF="$(awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}' <<<"$DEFAULT_ROUTE_OUTPUT")"
  DEFAULT_WAN_IF="${DEFAULT_WAN_IF%%@*}"
fi
AVAILABLE_IFS=()
while IFS= read -r IF_LINE; do
  IF_NAME="${IF_LINE#*: }"
  IF_NAME="${IF_NAME%%:*}"
  IF_NAME="${IF_NAME%%@*}"
  IF_NAME="${IF_NAME//[[:space:]]/}"
  [[ -z "$IF_NAME" || "$IF_NAME" == "lo" ]] && continue
  case " ${AVAILABLE_IFS[*]} " in
    *" $IF_NAME "*) continue ;;
  esac
  AVAILABLE_IFS+=("$IF_NAME")
done < <(ip -o link show 2>/dev/null)
if [[ -z "$DEFAULT_WAN_IF" && ${#AVAILABLE_IFS[@]} -gt 0 ]]; then
  DEFAULT_WAN_IF="${AVAILABLE_IFS[0]}"
fi
DEFAULT_WAN_IF="${DEFAULT_WAN_IF:-eth0}"
if [[ ${#AVAILABLE_IFS[@]} -eq 0 ]]; then
  AVAILABLE_IFS=("$DEFAULT_WAN_IF")
fi
echo "检测到可用网卡：${AVAILABLE_IFS[*]}"
read -rp "VPS 出口网卡名（用于 NAT）[默认 ${DEFAULT_WAN_IF}]: " WAN_IF
WAN_IF=${WAN_IF:-$DEFAULT_WAN_IF}

# 尝试探测公网 IP（可手动输入）
PUB_IP_GUESS="$( (command -v curl >/dev/null && curl -s --max-time 3 ifconfig.me) || true )"
if [[ -z "$PUB_IP_GUESS" ]] && command -v dig >/dev/null 2>&1; then
  PUB_IP_GUESS="$(dig -4 +short myip.opendns.com @resolver1.opendns.com || true)"
fi
read -rp "VPS 公网 IP/域名（用于客户端 Endpoint）[默认 ${PUB_IP_GUESS:-<必填或稍后手动替换>}]: " ENDPOINT_HOST
ENDPOINT_HOST=${ENDPOINT_HOST:-${PUB_IP_GUESS:-"<REPLACE_ME>"}}

read -rp "为首个客户端起个名字 [默认 phone]: " CLIENT_NAME
CLIENT_NAME=${CLIENT_NAME:-phone}

# =============== 安装依赖 ===============
echo ">> 安装 WireGuard 及工具..."
case "$OS_ID" in
  ubuntu|debian)
    apt-get update -y
    BASE_PACKAGES=(wireguard wireguard-tools iproute2 iptables qrencode wireguard-go)
    apt-get install -y "${BASE_PACKAGES[@]}"

    if apt-cache show wireguard-dkms >/dev/null 2>&1; then
      apt-get install -y wireguard-dkms || echo "警告: wireguard-dkms 安装失败，请手动安装。"
    else
      echo "提示: 当前仓库未提供 wireguard-dkms。"
    fi

    HEADER_PKG="linux-headers-$(uname -r)"
    if apt-cache show "$HEADER_PKG" >/dev/null 2>&1; then
      apt-get install -y "$HEADER_PKG" || true
    fi

    if ! command -v wireguard-go >/dev/null 2>&1; then
      if apt-cache show wireguard-go >/dev/null 2>&1; then
        apt-get install -y wireguard-go || echo "警告: wireguard-go 安装失败，请手动安装。"
      else
        echo "提示: 仓库中未找到 wireguard-go，如内核缺少模块请手动安装。"
      fi
    fi
    ;;
  centos|rocky|almalinux|rhel)
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y epel-release || true
      dnf install -y wireguard-tools iproute iptables qrencode wireguard-go
    else
      yum install -y epel-release || true
      yum install -y wireguard-tools iproute iptables qrencode wireguard-go
    fi
    ;;
  *)
    echo "未内置的系统：请自行安装 wireguard-tools/iptables/qrencode 后重试。"
    exit 1
    ;;
esac

MODULE_AVAILABLE=false
if modprobe wireguard 2>/dev/null; then
  MODULE_AVAILABLE=true
else
  if find /lib/modules -maxdepth 3 -name 'wireguard.ko*' 2>/dev/null | grep -q '.'; then
    MODULE_AVAILABLE=true
  fi
fi
if [[ $MODULE_AVAILABLE == false ]]; then
  if command -v wireguard-go >/dev/null 2>&1; then
    echo "提示: 未能加载内核模块，将尝试使用 wireguard-go。"
  else
    echo "警告: 内核缺少 wireguard 模块且未检测到 wireguard-go，wg-quick 可能启动失败。"
  fi
fi

# =============== 生成密钥 ===============
install -d -m 700 /etc/wireguard
cd /etc/wireguard

if [[ ! -f server_privatekey ]]; then
  umask 077
  wg genkey | tee server_privatekey | wg pubkey > server_publickey
fi

SERVER_PRIV_KEY="$(cat server_privatekey)"
SERVER_PUB_KEY="$(cat server_publickey)"

# 客户端密钥
install -d -m 700 "/etc/wireguard/clients/${CLIENT_NAME}"
umask 077
wg genkey | tee "/etc/wireguard/clients/${CLIENT_NAME}/${CLIENT_NAME}_privatekey" | wg pubkey > "/etc/wireguard/clients/${CLIENT_NAME}/${CLIENT_NAME}_publickey"
CLIENT_PRIV_KEY="$(cat "/etc/wireguard/clients/${CLIENT_NAME}/${CLIENT_NAME}_privatekey")"
CLIENT_PUB_KEY="$(cat "/etc/wireguard/clients/${CLIENT_NAME}/${CLIENT_NAME}_publickey")"

# =============== 写服务端配置 ===============
WG_CONF=/etc/wireguard/wg0.conf

cat > "$WG_CONF" <<EOF
[Interface]
Address = ${SERVER_IP}/${WG_PREFIX}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
# 开启转发的同时做 NAT、允许 wg0 进出转发
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${WAN_IF} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${WAN_IF} -j MASQUERADE

[Peer]
# ${CLIENT_NAME}
PublicKey = ${CLIENT_PUB_KEY}
AllowedIPs = ${CLIENT_IP}/32
EOF

chmod 600 "$WG_CONF"

# =============== 开启内核转发（持久） ===============
SYSCTL_D="/etc/sysctl.d"
install -d "$SYSCTL_D"
SYSCTL_FILE="${SYSCTL_D}/99-wireguard-forward.conf"
cat > "$SYSCTL_FILE" <<EOF
net.ipv4.ip_forward=1
EOF
sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

# =============== 放行防火墙（如存在） ===============
if command -v ufw >/dev/null 2>&1; then
  echo ">> 检测到 UFW，放行 UDP ${WG_PORT}"
  ufw allow "${WG_PORT}"/udp || true
fi

if command -v firewall-cmd >/dev/null 2>&1; then
  echo ">> 检测到 firewalld，放行 UDP ${WG_PORT}"
  firewall-cmd --permanent --add-port="${WG_PORT}"/udp || true
  firewall-cmd --reload || true
fi

# =============== 启动 WireGuard 并设为自启 ===============
systemctl stop wg-quick@wg0 2>/dev/null || true
wg-quick down wg0 2>/dev/null || true
wg-quick up wg0
if ! wg show wg0 >/dev/null 2>&1; then
  echo "错误: wg0 启动失败，请检查上方日志并确认内核模块或 wireguard-go 安装。"
  exit 1
fi
systemctl enable wg-quick@wg0 >/dev/null

# =============== 生成客户端配置（含二维码） ===============
CLIENT_DIR="/etc/wireguard/clients/${CLIENT_NAME}"
CLIENT_CONF="${CLIENT_DIR}/${CLIENT_NAME}.conf"

cat > "$CLIENT_CONF" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_IP}/${WG_PREFIX}
DNS = ${DNS_IP}
# 建议：某些网络下如丢包可在两端加 MTU = 1420
# MTU = 1420

[Peer]
PublicKey = ${SERVER_PUB_KEY}
Endpoint = ${ENDPOINT_HOST}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

chmod 600 "$CLIENT_CONF"

# 也将 peer 动态写入（避免 up/down）
wg set wg0 peer "${CLIENT_PUB_KEY}" allowed-ips "${CLIENT_IP}/32" || true

# =============== 输出结果与二维码 ===============
echo
echo "================= 部署完成 ================="
echo "服务端配置: /etc/wireguard/wg0.conf"
echo "客户端配置: ${CLIENT_CONF}"
echo "重要：请在云厂商安全组放行 UDP 端口 ${WG_PORT}"
echo "-------------------------------------------"
echo "当前状态："
wg show || true
echo "-------------------------------------------"
if command -v qrencode >/dev/null 2>&1; then
  echo "下面是 ${CLIENT_NAME}.conf 的二维码（手机 WireGuard 直接扫码导入）："
  echo
  qrencode -t ansiutf8 < "${CLIENT_CONF}"
  echo
else
  echo "未安装 qrencode，无法在终端显示二维码。你可以将 ${CLIENT_CONF} 复制到手机导入。"
fi

add_more_clients

echo "全部完成！如需查看：wg show；如需停用：wg-quick down wg0"
