#!/bin/bash
# FLAG をローテーターが書き込むファイルから /root/flag.txt へ反映（root のみ読取可）。
# ローテーションに追従するため、バックグラウンドで定期的に再コピーする。
FLAG_SRC="${FLAG_FILE:-/flags/service-c.txt}"

refresh_flag() {
    if [ -f "$FLAG_SRC" ]; then
        cp "$FLAG_SRC" /root/flag.txt
    else
        echo "FLAG{not_rotated_yet}" > /root/flag.txt
    fi
    chown root:root /root/flag.txt
    chmod 600 /root/flag.txt
}

refresh_flag
( while true; do sleep 10; refresh_flag; done ) &

exec /usr/sbin/sshd -D -e
