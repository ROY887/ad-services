# A&D CTF — 単一マシン構築（神田ひとりで作れる範囲）

計画書・設計書の A&D CTF 環境を、**他メンバーの成果物に依存せず 1 台のマシンで
再現する**ための構成。本番はチームごとに VM を IaC で配布するが、ここでは
docker-compose でその代用を行う。

## 全体構成

```
┌────────────────────────────────────────────────────────────┐
│ 1 台のマシン (docker)                                        │
│                                                            │
│  [flag-rotator] ──書込──> ./flags/service-a.txt            │
│        │(engineering-design-5th-grade / 居林)              │
│        └──INSERT──> flagdb(MySQL)                          │
│                                                            │
│  [service-a]  公開:8101 (SSRF 脆弱) / 内部:9200(ES相当)     │
│        ▲ SSRF 攻撃                読取: ./flags/service-a.txt│
│                                                            │
│  [sla-checker] ──GET /health──> service-a                  │
│        └──POST /sla──> score-server                        │
│                                                            │
│  [score-server] :8001  ← flagdb をポーリング取込           │
│        │(神田)   FLAG提出受付 / スコア計算 / 二重提出防止    │
│        └──push──> CTFd :8000（スコア表示）                 │
└────────────────────────────────────────────────────────────┘
```

## コンポーネント別 可否と担当

| 機能 | 本来の担当 | 状態 | 単独構築の扱い |
| --- | --- | --- | --- |
| スコア管理 (score-server) |  ✅完成 | `~/score-server` |
| FLAG ローテーション |  ✅存在 | `~/engineering-design-5th-grade` |
| **SLA 死活監視** |  ✅**新規自作** | `~/sla-checker` |
| 脆弱サービス | 実験実習班 | ⚠️ **3 種を自作** | `./service-a`（SSRF）/ `./service-b`（Mass Assignment+IDOR＋バックアップ漏洩）/ `./service-c`（sudo find 権限昇格・SSH）。他は下記代用方針 |
| VM 自動配布 (IaC) | インフラ班 | ✗ 単独不可 | **docker-compose で代用**（本ファイル） |

## 既知の制約

- `sla-checker` は TCP チェック（service-c/SSH 用）を追加済みだが、コンテナ
  イメージの再ビルドには `python:3.12-slim` の取得が必要。Docker Hub 到達時に
  `docker compose build sla-checker` を再実行すること。到達不可な環境では
  ホスト側で `cd ~/sla-checker && python3 main.py --once` として実行できる
  （動作確認はこの方法で実施済み）。

## 起動手順

```bash
# 1) score-server（別 compose、:8001）
cd ~/score-server && docker compose up -d

# 2) CTFd（別 compose、:8000）
cd ~/CTFd && docker compose up -d

# 3) 競技サービス + SLA チェッカー（本 compose）
cd ~/ad-services && docker compose up -d --build
```

## 動作確認済みの A/D ループ

- **攻撃 (service-a / SSRF)**: `POST /api/v1/profile/image` に
  `{"image_url":"http://127.0.0.1:9200/system-logs/_search?q=FLAG"}`
  → 外部非公開の内部 ES（loopback のみ）から FLAG を SSRF で奪取。
- **攻撃 (service-b / Mass Assignment+IDOR)**: `ctf-user` でログイン →
  `PUT /api/v1/user/profile {"is_admin":true}` で昇格 →
  `GET /api/v1/user/info?id=1` で admin の `secret_note`（FLAG）を IDOR 取得。
- **攻撃 (service-b / バックアップ漏洩)**: 昇格後に
  `POST /api/v1/admin/backup` → 生成物が固定パスで公開される →
  `GET /assets/backups/system_backup.tar.gz`（無認可）を DL・解凍し、
  `db_dump.sql` / `rotation_secret.txt` から FLAG・ローテーション秘密鍵を奪取。
- **攻撃 (service-c / sudo find 権限昇格)**: `ctf-user` で SSH ログイン →
  `.bash_history` と `sudo -l` から `find` の NOPASSWD を発見 →
  `sudo /usr/bin/find ... -exec /bin/sh -p \;` で root 昇格し `/root/flag.txt` 奪取。
- **提出**: 奪取した FLAG を score-server へ提出 → 加点、二重提出は拒否。
- **SLA**: sla-checker が HTTP（service-a/b）と TCP+バナー（service-c=SSH）で
  判定 → score-server で `sla_rate` と防御ポイントが再計算（全 UP で defense=5.0）。
- **表示**: ラウンド切替時に score-server が CTFd へ push、スコアボードに反映。

## 単独では作れない部分と代用案

| 本来 | 単独不可の理由 | 代用案（本リポジトリ） |
| --- | --- | --- |
| Packer/Ansible/Terraform で校内ハイパーバイザに VM 一斉配布 | 物理クラスタ・権限が必要 | **docker-compose** で 1 チーム分のサービススタックを再現。チーム数はサービスを複製して増やす |
| Ubuntu 20.04 VM + SecGen による脆弱ミドルウェア群 | SecGen 一式・VM 基盤が必要 | 各シナリオを**軽量コンテナのアプリ実装**として再現（service-a = SSRF を実装済み） |
| Grafana による SLA 可視化 | 別担当の未着手領域 | まず score-server の `/scoreboard`（`sla_rate` 含む）で可視化。必要なら Grafana を後付け |

## 残シナリオ（同方式で追加可能・未実装）

実装済み: シナリオ1=service-a（SSRF）、シナリオ2=service-c（sudo find 権限昇格・SSH）、
シナリオ3＋4=service-b（Mass Assignment / IDOR / バックアップ漏洩）。残りは:

- シナリオ5: vsftpd 2.3.4 バックドア + Dirty Pipe。バックドア部分はコンテナで
  再現できるが、**Dirty Pipe（カーネル脆弱性）は実 VM 相当が必要**で単一コンテナ
  では忠実に再現できない（コンテナはホストカーネルを共有するため）。

> 追加時は `sla-checker/config.py` の `TARGETS` と score-server `scripts/seed.py`
> に service を追記し、両者の `service_id` を一致させること。
