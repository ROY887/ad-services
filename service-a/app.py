"""service-a — シナリオ1（SSRF から内部データ回収）の実行可能な最小実装。

計画書シナリオ1を単一コンテナで再現する:
  - 内部 Elasticsearch 相当を 127.0.0.1:9200 にだけ待ち受けさせる（外部非公開）。
    system-logs 相当のレスポンスに FLAG を埋め込む。FLAG はローテーターが
    書き込むファイル (FLAG_FILE) から都度読み込むため、ローテーションに追従する。
  - 公開 API (0.0.0.0:8101) のプロフィール画像取得 POST /api/v1/profile/image は
    渡された image_url をサーバ側でフェッチする（SSRF フィルタ無し = 脆弱）。
  - GET /health は SLA チェッカー用（常に {"status":"ok"}）。

攻撃:
  curl -XPOST http://<host>:8101/api/v1/profile/image \
       -H 'Content-Type: application/json' \
       -d '{"image_url":"http://127.0.0.1:9200/system-logs/_search?q=FLAG"}'
  → レスポンスに FLAG が含まれる。

防御（競技者が施す想定のパッチ）:
  image_url のホストを解決し 127.0.0.1 / localhost / プライベート IP を弾く。
"""

import os
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
from flask import Flask, request, jsonify

FLAG_FILE = os.environ.get("FLAG_FILE", "/flags/service-a.txt")
PUBLIC_PORT = int(os.environ.get("PORT", "8101"))
INTERNAL_PORT = 9200


def read_flag() -> str:
    try:
        with open(FLAG_FILE, encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "FLAG{not_rotated_yet}"


# --- 内部 Elasticsearch 相当（127.0.0.1:9200 のみ） -------------------
class _InternalESHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if "/system-logs/_search" in self.path:
            body = {
                "hits": {
                    "total": {"value": 1},
                    "hits": [
                        {
                            "_index": "system-logs",
                            "_source": {
                                "level": "INFO",
                                "message": f"rotation secret {read_flag()}",
                            },
                        }
                    ],
                }
            }
            payload = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):  # ログ抑制
        return


def _run_internal_es():
    # loopback のみにバインド → 外部から直接は届かない（SSRF が必須になる）
    HTTPServer(("127.0.0.1", INTERNAL_PORT), _InternalESHandler).serve_forever()


# --- 公開 Web アプリ --------------------------------------------------
app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/")
def index():
    return jsonify(service="service-a", scenario="SSRF (profile image fetch)")


@app.post("/api/v1/profile/image")
def profile_image():
    data = request.get_json(silent=True) or {}
    image_url = data.get("image_url")
    if not image_url:
        return jsonify(error="image_url required"), 400
    # --- 脆弱点: SSRF フィルタ無しでサーバ側フェッチ ---
    try:
        resp = httpx.get(image_url, timeout=5.0)
        return jsonify(fetched_from=image_url, content=resp.text)
    except Exception as e:  # noqa: BLE001
        return jsonify(error=str(e)), 502


if __name__ == "__main__":
    threading.Thread(target=_run_internal_es, daemon=True).start()
    app.run(host="0.0.0.0", port=PUBLIC_PORT)
