#!/usr/bin/env bash
# 开机自启安装脚本 (DSM7/systemd)
# 用法: bash cf_autostart_install.sh [部署目录]
#   - 缺省为脚本所在目录(cf_web.py / cf_ips.db 同目录), 适配任意机器
#   - 需要 sudo 权限(复制到 /etc/systemd/system 并 enable/start)
set -euo pipefail
SERVICE="cf-optimizer.service"
DEPLOY_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
RUN_USER="${RUN_USER:-$(id -un)}"
RUN_GROUP="${RUN_GROUP:-$(id -gn)}"
cd "$DEPLOY_DIR"

echo "1. 停止现有服务（如有）"
python3 cf_web.py --stop 2>/dev/null || true
sleep 2

echo "2. 生成 systemd 单元文件"
cat > "$DEPLOY_DIR/$SERVICE" <<EOF
[Unit]
Description=CF Optimizer Web Service
After=local-fs.target network.target
Wants=local-fs.target

[Service]
Type=simple
WorkingDirectory=$DEPLOY_DIR
ExecStartPre=/bin/sh -c 'while [ ! -f "$DEPLOY_DIR/cf_ips.db" ]; do echo "Waiting for volume..."; sleep 3; done'
ExecStart=/usr/bin/python3 $DEPLOY_DIR/cf_web.py --db cf_ips.db --host 0.0.0.0 --port 8787 --log cf_web.log --pidfile cf_web.pid --no-browser --child
ExecStop=/usr/bin/python3 $DEPLOY_DIR/cf_web.py --pidfile $DEPLOY_DIR/cf_web.pid --stop
Restart=on-failure
RestartSec=12
User=$RUN_USER
Group=$RUN_GROUP
StandardOutput=append:$DEPLOY_DIR/cf_web.log
StandardError=append:$DEPLOY_DIR/cf_web.log

[Install]
WantedBy=multi-user.target
EOF

echo "3. 生成 sudoers 白名单(供网页端 重启/停止/开机自启 使用)"
SYSTEMCTL_BIN="$(command -v systemctl || echo /usr/bin/systemctl)"
SYSTEMCTL_REAL="$(readlink -f "$SYSTEMCTL_BIN" 2>/dev/null || echo "$SYSTEMCTL_BIN")"
cat > "$DEPLOY_DIR/cf-optimizer.sudoers" <<EOF
# cf-optimizer 管理台: 允许 $RUN_USER 无密码控制本服务(仅限以下命令)
$RUN_USER ALL=(root) NOPASSWD: $SYSTEMCTL_BIN start $SERVICE, $SYSTEMCTL_BIN stop $SERVICE, $SYSTEMCTL_BIN restart $SERVICE, $SYSTEMCTL_BIN enable $SERVICE, $SYSTEMCTL_BIN disable $SERVICE, $SYSTEMCTL_BIN is-active $SERVICE, $SYSTEMCTL_BIN is-enabled $SERVICE
$RUN_USER ALL=(root) NOPASSWD: $SYSTEMCTL_REAL start $SERVICE, $SYSTEMCTL_REAL stop $SERVICE, $SYSTEMCTL_REAL restart $SERVICE, $SYSTEMCTL_REAL enable $SERVICE, $SYSTEMCTL_REAL disable $SERVICE, $SYSTEMCTL_REAL is-active $SERVICE, $SYSTEMCTL_REAL is-enabled $SERVICE
EOF

echo "4. 安装到 /etc/systemd/system 并启用开机自启"
if [ -n "${SUDO_PASS:-}" ]; then
    SUDO="echo $SUDO_PASS | sudo -S"
else
    SUDO="sudo"
fi

$SUDO bash -c "
set -e
cp '$DEPLOY_DIR/$SERVICE' /etc/systemd/system/$SERVICE
if command -v visudo >/dev/null 2>&1; then
  visudo -cf '$DEPLOY_DIR/cf-optimizer.sudoers'
  cp '$DEPLOY_DIR/cf-optimizer.sudoers' /etc/sudoers.d/cf-optimizer
  chmod 0440 /etc/sudoers.d/cf-optimizer
else
  echo '警告: 未找到 visudo, 跳过 sudoers 授权(网页端开机自启开关将不可用)'
fi
systemctl daemon-reload
systemctl enable $SERVICE
systemctl restart $SERVICE
"
sleep 3
echo "5. 服务状态"
$SUDO systemctl is-enabled "$SERVICE"
$SUDO systemctl is-active "$SERVICE"
echo "6. 验证访问(login cookie)"
CRED_USER="$(python3 -c "import json;print(json.load(open('cf_secret.json'))['user'])" 2>/dev/null || echo admin)"
CRED_PASS="$(python3 -c "import json;print(json.load(open('cf_secret.json'))['pass'])" 2>/dev/null || echo '')"
if [ -n "$CRED_PASS" ]; then
    curl -s -c /tmp/cj -m 6 -o /dev/null -X POST \
        --data-urlencode "user=$CRED_USER" --data-urlencode "pass=$CRED_PASS" \
        'http://127.0.0.1:8787/api/login' -w 'login:%{http_code}\n' \
        && curl -s -b /tmp/cj -m 6 -o /dev/null -w 'export:%{http_code}\n' \
        'http://127.0.0.1:8787/api/export?fmt=csv&top=3'
else
    echo "提示: 未找到 cf_secret.json, 请按实际账号密码测试"
fi
echo "已完成: systemd 开机自启 + 崩溃自动重启(Restart=on-failure)"