#!/usr/bin/env bash
# 开机自启安装脚本 (DSM7/systemd)
# 用法: bash install_autostart.sh [部署目录]
#   - 缺省 /vol1/1000/cf-optimizer-main
#   - 需要 sudo 权限(复制到 /etc/systemd/system 并 enable/start)
set -euo pipefail
DEPLOY_DIR="${1:-/vol1/1000/cf-optimizer-main}"
SERVICE="cf-optimizer.service"
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
User=zqy
Group=Administrators
StandardOutput=append:$DEPLOY_DIR/cf_web.log
StandardError=append:$DEPLOY_DIR/cf_web.log

[Install]
WantedBy=multi-user.target
EOF

echo "3. 安装到 /etc/systemd/system 并启用开机自启"
if [ -n "${SUDO_PASS:-}" ]; then
    SUDO="echo $SUDO_PASS | sudo -S"
else
    SUDO="sudo"
fi

$SUDO bash -c "
set -e
cp '$DEPLOY_DIR/$SERVICE' /etc/systemd/system/$SERVICE
systemctl daemon-reload
systemctl enable $SERVICE
systemctl restart $SERVICE
"
sleep 3
echo "4. 服务状态"
$SUDO systemctl is-enabled "$SERVICE"
$SUDO systemctl is-active "$SERVICE"
echo "5. 验证访问(login cookie)"
curl -sk -c /tmp/cj -m 6 -o /dev/null -X POST -d 'user=zqy' -d 'pass=PLACEHOLDER' \
    'https://127.0.0.1:8787/api/login' -w 'login:%{http_code}\n' \
    && curl -sk -b /tmp/cj -m 6 -o /dev/null -w 'export:%{http_code}\n' \
    'https://127.0.0.1:8787/api/export?fmt=csv&top=3' || echo "提示: 按实际账号密码测试"
echo "已完成: systemd 开机自启 + 崩溃自动重启(Restart=on-failure)"