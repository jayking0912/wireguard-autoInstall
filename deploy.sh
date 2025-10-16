#!/usr/bin/env bash
set -euo pipefail

# =============== 基本校验 ===============
if [[ $EUID -ne 0 ]]; then
  echo "请用 root 运行：sudo $0"
  exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
  echo "缺少 iproute2/ip 命令，请先安装基础网络组件。"
  exit 1
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
DEFAULT_WAN_IF_RAW="$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5; exit}')"
DEFAULT_WAN_IF="${DEFAULT_WAN_IF_RAW%%@*}"
AVAILABLE_IFS=()
while IFS= read -r IF_LINE; do
  IF_NAME="${IF_LINE#*: }"
  IF_NAME="${IF_NAME%%:*}"
  IF_NAME="${IF_NAME//[[:space:]]/}"
  [[ -z "$IF_NAME" || "$IF_NAME" == "lo" ]] && continue
  IF_NAME="${IF_NAME%%@*}"
  [[ -z "$IF_NAME" ]] && continue
  DUPLICATED=false
  for EXIST_IF in "${AVAILABLE_IFS[@]}"; do
    if [[ "$EXIST_IF" == "$IF_NAME" ]]; then
      DUPLICATED=true
      break
    fi
  done
  $DUPLICATED && continue
  AVAILABLE_IFS+=("$IF_NAME")
done < <(ip -o link show 2>/dev/null)
if [[ ${#AVAILABLE_IFS[@]} -eq 0 ]]; then
  AVAILABLE_IFS=("${DEFAULT_WAN_IF:-eth0}")
fi
DEFAULT_LIST_IF="${DEFAULT_WAN_IF:-${AVAILABLE_IFS[0]}}"
DEFAULT_LIST_IF="${DEFAULT_LIST_IF:-eth0}"
echo "检测到可用网卡：${AVAILABLE_IFS[*]}"
read -rp "VPS 出口网卡名（用于 NAT）[默认 ${DEFAULT_LIST_IF}]: " WAN_IF
WAN_IF=${WAN_IF:-$DEFAULT_LIST_IF}

# 尝试探测公网 IP（可手动输入）
PUB_IP_GUESS="$( (command -v curl >/dev/null && curl -s --max-time 3 ifconfig.me) || true )"
if [[ -z "$PUB_IP_GUESS" && command -v dig >/dev/null 2>&1 ]]; then
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
    # wireguard 包在较新 Debian/Ubuntu 中包含内核模块；qrencode 生成二维码
    apt-get install -y wireguard wireguard-tools iproute2 iptables qrencode
    ;;
  centos|rocky|almalinux|rhel)
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y epel-release || true
      dnf install -y wireguard-tools iproute iptables qrencode
    else
      yum install -y epel-release || true
      yum install -y wireguard-tools iproute iptables qrencode
    fi
    ;;
  *)
    echo "未内置的系统：请自行安装 wireguard-tools/iptables/qrencode 后重试。"
    exit 1
    ;;
esac

modprobe wireguard || true

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
cat > "${SYSCTL_D}/99-wireguard-forward.conf" <<EOF
net.ipv4.ip_forward=1
EOF
sysctl --system >/dev/null

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

# =============== 可选：继续添加更多客户端 ===============
read -rp "是否继续添加更多客户端？(y/N): " ADD_MORE
if [[ "${ADD_MORE,,}" == "y" ]]; then
  declare -A USED_HOSTS=()
  SERVER_HOST="${SERVER_IP##*.}"
  USED_HOSTS["$SERVER_HOST"]=1
  CLIENT_HOST="${CLIENT_IP##*.}"
  USED_HOSTS["$CLIENT_HOST"]=1
  if [[ -d /etc/wireguard/clients ]]; then
    while IFS= read -r CONF_FILE; do
      ADDR_LINE="$(grep -m1 '^Address = ' "$CONF_FILE" || true)"
      if [[ -n "$ADDR_LINE" ]]; then
        ADDR_VALUE="${ADDR_LINE#Address = }"
        ADDR_IP="${ADDR_VALUE%%/*}"
        HOST_OCT="${ADDR_IP##*.}"
        [[ -n "$HOST_OCT" ]] && USED_HOSTS["$HOST_OCT"]=1
      fi
    done < <(find /etc/wireguard/clients -maxdepth 2 -type f -name '*.conf' 2>/dev/null)
  fi
  NEXT_HOST=0
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
    NEWC_PRIV="$(cat "/etc/wireguard/clients/${NEWC}/${NEWC}_privatekey")"
    NEWC_PUB="$(cat "/etc/wireguard/clients/${NEWC}/${NEWC}_publickey")"
    while [[ -n "${USED_HOSTS[$NEXT_HOST]:-}" ]]; do
      NEXT_HOST=$((NEXT_HOST+1))
      if (( NEXT_HOST >= 255 )); then
        echo "IPv4 网段已无可用地址，无法继续添加。"
        break 2
      fi
    done
    NEWC_IP="${o1}.${o2}.${o3}.${NEXT_HOST}"
    USED_HOSTS["$NEXT_HOST"]=1
    NEXT_HOST=$((NEXT_HOST+1))
    NEWC_CONF="/etc/wireguard/clients/${NEWC}/${NEWC}.conf"
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
fi

echo "全部完成！如需查看：wg show；如需停用：wg-quick down wg0"
