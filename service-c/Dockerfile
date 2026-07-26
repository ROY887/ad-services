# service-c — シナリオ2（.bash_history + sudo find 権限昇格）の SSH コンテナ実装。
# 本番は競技側 VM (Ubuntu 20.04)。単一マシン検証では Alpine で代用する
# （シナリオ2は sudoers 設定の脆弱性であり OS 依存はない）。
FROM alpine:3.23

# openssh: SSH サーバ / sudo: 権限昇格の対象 / findutils: GNU find(/usr/bin/find)
# shadow: useradd / chpasswd / bash: ログインシェル
RUN apk add --no-cache openssh sudo findutils shadow bash \
    && ssh-keygen -A

# --- 一般ユーザー ctf-user（デモ用にパスワード認証を許可）---
RUN useradd -m -s /bin/bash ctf-user \
    && echo 'ctf-user:ctf-pass' | chpasswd

# --- 脆弱点: find に NOPASSWD sudo を付与 ---
RUN echo 'ctf-user ALL=(ALL) NOPASSWD: /usr/bin/find' > /etc/sudoers.d/ctf-user \
    && chmod 440 /etc/sudoers.d/ctf-user \
    && grep -q '^#includedir /etc/sudoers.d' /etc/sudoers || echo '#includedir /etc/sudoers.d' >> /etc/sudoers

# --- 過去の作業跡として sudo find の履歴を混入（攻撃者へのヒント）---
COPY bash_history /home/ctf-user/.bash_history
RUN chown ctf-user:ctf-user /home/ctf-user/.bash_history

# パスワード認証を有効化（root ログインは禁止）
RUN sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
CMD ["/entrypoint.sh"]
