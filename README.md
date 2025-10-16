# WireGuard Auto Install

`deploy.sh` 自动化在常见 Linux 发行版（Debian/Ubuntu、RHEL/CentOS 系列）上安装并配置 WireGuard 服务端，生成首个客户端配置，并支持后续交互式追加客户端。

## 前置要求

- 一台可访问互联网的 VPS，推荐 Debian/Ubuntu 或包含 WireGuard 官方包的其他系统。
- 拥有 root 权限；脚本需通过 `sudo` 或直接以 root 执行。
- 云安全组需开放 WireGuard 所用 UDP 端口（默认 `51820`）。

## 快速开始

```bash
curl -fsSL https://raw.githubusercontent.com/jayking0912/wireguard-autoInstall/main/deploy.sh -o deploy.sh && sudo bash deploy.sh
```

或在已克隆的仓库中运行：

```bash
sudo bash deploy.sh
```

执行过程中脚本将交互式询问以下信息：

1. WireGuard 监听端口、网段、服务端与首个客户端地址。
2. 客户端使用的 DNS 服务器。
3. VPS 出口网卡名称（自动探测，可修改）。
4. 客户端访问服务端的公网 IP 或域名。
5. 首个客户端名称。

脚本会自动：

- 安装 WireGuard、`wireguard-tools`、`iptables`、`qrencode` 等依赖。
- 生成服务端与客户端密钥，写入 `/etc/wireguard/wg0.conf` 及客户端配置目录。
- 启用 IPv4 转发与 NAT，开启 `wg-quick@wg0` 并设置开机自启。
- 输出客户端配置文件路径与二维码（若安装了 `qrencode`）。

## 追加客户端

在脚本末尾选择继续添加客户端时，脚本会：

- 为每个新客户端生成独立的密钥与配置文件。
- 自动分配 IP，从网段的末尾数字递增（例如 `...2`, `...3`, `...4`），避免与已存在客户端冲突。
- 将新客户端的公钥和地址即时写入运行中的 `wg0`，无需手动重启。

## 常见运维操作

- 查看状态：`wg show`
- 停止服务：`wg-quick down wg0`
- 启动服务：`wg-quick up wg0`
- 客户端配置文件目录：`/etc/wireguard/clients/<客户端名>/`

如需手动管理客户端，可编辑对应配置后运行 `wg set` 手动更新。若网段地址耗尽，可调整 `deploy.sh` 中的网段默认值或在执行时指定更大的网段。
