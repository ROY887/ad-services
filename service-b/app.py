"""service-b — シナリオ3（Mass Assignment 経由の管理者昇格 ＆ IDOR）実装。

計画書シナリオ3を単一コンテナで再現する:
  - users テーブルに is_admin カラムを持つ。
  - PUT /api/v1/user/profile は受け取った JSON をそのまま UPDATE に流す
    （Mass Assignment 不備）→ {"is_admin": true} を送れば管理者へ昇格できる。
  - GET /api/v1/user/info?id=X は認可チェックが甘く、自分以外の id も引ける
    （IDOR）。ただし FLAG を含む secret_note は「管理者にのみ」返す。
  - GET /health は SLA チェッカー用。

攻撃チェーン:
  1) POST /login {"username":"ctf-user","password":"password"}  → token
  2) GET  /api/v1/user/info?id=1  (token)   → secret_note は隠される（非管理者）
  3) PUT  /api/v1/user/profile {"is_admin": true} (token)  → 管理者へ昇格
  4) GET  /api/v1/user/info?id=1  (token)   → secret_note に FLAG が出る

シナリオ4（バックアップ漏洩）— 3 で管理者昇格した後に連結:
  5) POST /api/v1/admin/backup (token)      → 公開ディレクトリに固定名で生成
  6) GET  /assets/backups/system_backup.tar.gz (無認可) → DL・解凍で FLAG 奪取

防御（競技者が施す想定のパッチ）:
  - profile 更新は許可カラムをホワイトリスト化（is_admin を弾く）。
  - info 取得は session ユーザー ID と要求 ID の一致を検証（IDOR 対策）。
  - /assets/backups/ を Nginx で deny、またはバックアップ名をランダム化。
"""

import io
import os
import secrets
import sqlite3
import tarfile

from flask import Flask, request, jsonify, g, send_from_directory

FLAG_FILE = os.environ.get("FLAG_FILE", "/flags/service-b.txt")
PORT = int(os.environ.get("PORT", "8102"))
DB_PATH = os.environ.get("DB_PATH", "/tmp/service-b.db")

# Web 公開ディレクトリ（計画書 /var/www/html/assets 相当）
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", "/app/public")
BACKUP_SUBDIR = "assets/backups"
BACKUP_NAME = "system_backup.tar.gz"   # 推測可能な固定名（＝脆弱点）

# token -> user_id
SESSIONS: dict[str, int] = {}

app = Flask(__name__)


def read_flag() -> str:
    try:
        with open(FLAG_FILE, encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "FLAG{not_rotated_yet}"


def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close_db(exc):  # noqa: ARG001
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0,
            display_name TEXT
        );
        INSERT INTO users (id, username, password, is_admin, display_name) VALUES
            (1, 'admin',    'S3cretAdminPw!', 1, 'Administrator'),
            (2, 'ctf-user', 'password',       0, 'CTF User');
        """
    )
    conn.commit()
    conn.close()


def current_user() -> sqlite3.Row | None:
    token = request.headers.get("X-Session-Token", "")
    uid = SESSIONS.get(token)
    if uid is None:
        return None
    return db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/")
def index():
    return jsonify(service="service-b", scenario="Mass Assignment + IDOR")


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    row = db().execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (data.get("username"), data.get("password")),
    ).fetchone()
    if row is None:
        return jsonify(error="invalid credentials"), 401
    token = secrets.token_hex(16)
    SESSIONS[token] = row["id"]
    return jsonify(token=token, user_id=row["id"])


@app.put("/api/v1/user/profile")
def update_profile():
    user = current_user()
    if user is None:
        return jsonify(error="unauthorized"), 401
    data = request.get_json(silent=True) or {}

    # --- 脆弱点: Mass Assignment。受け取ったキーを無検証で UPDATE ---
    allowed_columns = {"username", "password", "is_admin", "display_name"}
    updates = {k: v for k, v in data.items() if k in allowed_columns}
    if not updates:
        return jsonify(error="no updatable fields"), 400

    sets = ", ".join(f"{k} = ?" for k in updates)
    db().execute(
        f"UPDATE users SET {sets} WHERE id = ?",
        (*updates.values(), user["id"]),
    )
    db().commit()
    row = db().execute("SELECT id, username, is_admin, display_name FROM users WHERE id = ?",
                       (user["id"],)).fetchone()
    return jsonify(updated=dict(row))


@app.get("/api/v1/user/info")
def user_info():
    viewer = current_user()
    if viewer is None:
        return jsonify(error="unauthorized"), 401

    # --- 脆弱点: IDOR。要求 id が自分自身かをチェックしない ---
    target_id = request.args.get("id", type=int)
    if target_id is None:
        return jsonify(error="id required"), 400
    row = db().execute(
        "SELECT id, username, is_admin, display_name FROM users WHERE id = ?",
        (target_id,),
    ).fetchone()
    if row is None:
        return jsonify(error="not found"), 404

    result = dict(row)
    # secret_note（FLAG 含む）は「閲覧者が管理者のとき」だけ返す
    #   → Mass Assignment で is_admin を立てないと FLAG は見えない
    if viewer["is_admin"]:
        result["secret_note"] = read_flag() if target_id == 1 else "(none)"
    return jsonify(result)


@app.post("/api/v1/admin/backup")
def admin_backup():
    """シナリオ4: 管理者専用のシステムバックアップ生成機能。

    生成物を Web 公開ディレクトリ配下（固定名）に置くのが脆弱点。
    シナリオ3で管理者へ昇格していないと実行できない。
    """
    user = current_user()
    if user is None:
        return jsonify(error="unauthorized"), 401
    if not user["is_admin"]:
        return jsonify(error="admin only"), 403

    # DB ダンプ + ローテーション用シークレットキーを含むバックアップを生成
    dump = io.StringIO()
    for row in db().execute("SELECT id, username, is_admin, display_name FROM users"):
        dump.write(f"INSERT INTO users VALUES ({row['id']},'{row['username']}',"
                   f"{row['is_admin']},'{row['display_name']}');\n")
    dump.write(f"-- flag: {read_flag()}\n")
    db_dump = dump.getvalue().encode()
    rotation_secret = (f"ROTATION_SECRET_KEY={read_flag()}\n"
                       f"# このキーで FLAG ローテーションが復元できてしまう\n").encode()

    backup_dir = os.path.join(PUBLIC_DIR, BACKUP_SUBDIR)
    os.makedirs(backup_dir, exist_ok=True)
    path = os.path.join(backup_dir, BACKUP_NAME)
    with tarfile.open(path, "w:gz") as tar:
        for name, data in [("db_dump.sql", db_dump), ("rotation_secret.txt", rotation_secret)]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

    return jsonify(ok=True, path=f"/{BACKUP_SUBDIR}/{BACKUP_NAME}")


@app.get("/assets/<path:filename>")
def public_assets(filename):
    """静的配信。/assets/backups/ を無認可で公開してしまう（＝脆弱点）。

    防御: 本来は Nginx で `location /assets/backups/ { deny all; }` を入れるか、
    バックアップ名にランダムハッシュを付与して直アクセスを防ぐ。
    """
    return send_from_directory(os.path.join(PUBLIC_DIR, "assets"), filename)


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
