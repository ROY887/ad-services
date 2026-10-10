# L3 実地スマグリング比較リグ（pingora vs Go net/http バックエンド）

in-process 差分では pingora の本物のスマグリングが出ない（pingora も比較相手の hyper も
`httparse` を使うため）ことが分かったので、**別パーサのバックエンド**との実地比較を行う。

```
攻撃クライアント ──raw socket──> pingora(:8898, httparse) ──> Go net/http バックエンド(:8899)
   driver.py                      l3proxy.rs                   backend.go
```

バックエンド(Go net/http、httparse とは別実装)が各リクエストを1行ログする。各ベクタには
隠し `GET /SMUGGLED` を仕込み、**バックエンドが `/SMUGGLED` を独立リクエストとして解釈したら
desync（スマグリング）成立**。

## ファイル
- `backend.go` — Go net/http バックエンド。`BACKEND_REQ #n method/path/cl/te/bodylen/body` をログ。
- `l3proxy.rs` — pingora プロキシ例。`127.0.0.1:8899` へ転送、`:8898` で待受。
  `L3_PIPELINING=1` で 0.9.0 の新機能パイプラインを有効化。`pingora-proxy/examples/` に置いて
  `cargo build --release --example l3proxy -p pingora-proxy`。
- `driver.py` — 8種のスマグリングベクタ（CL.TE / TE.CL / TE難読化 / 二重TE / tab / chunk-ext /
  CL先頭ゼロ / パイプライン制御）を送出。
- `run_l3.sh` — 起動→送出→集計→停止を一括実行。引数で pipelining 0/1。
- `sample-backend.log` — 実際の観測ログ（証跡）。

## 使い方
```bash
# Go と pingora(release, l3proxy例) をビルド済み前提
go build -o backend backend.go
bash run_l3.sh 0   # pipelining OFF
bash run_l3.sh 1   # pipelining ON
# 末尾の "SMUGGLED HITS" を確認
```

## 結果（2026-10-10 / pingora 0.9.0 / Go 1.24.7）

**desync / スマグリングは検出されず。** 内訳:

- スマグリング試行（CL.TE, TE.CL, TE難読化, 二重TE, tab, chunk-ext）:
  いずれも pingora が**正規化**し、SMUG 文字列はバックエンドに**本体データ**として届いた
  （`/SMUGGLED` はリクエストとして解釈されず）。`sample-backend.log` の #1〜#4 参照。
- `/SMUGGLED` がリクエストとして現れたのは、**クライアントが正当に2本パイプライン送信した**
  ベクタ（CL:00=空body / 制御ベクタ）のみ。pingora もバックエンドも「2リクエスト」で**一致**。
  これはリグが2本目を観測できることの確認であり、desync ではない。
- pipelining OFF では、2本目のパイプラインリクエストは pingora が破棄（CVE 修正の設計どおり）。

## 評価と限界

- pingora 0.9.0 は、ここで試した**古典的スマグリングベクタすべてに耐性**がある。
  要因は「pingora が上流へリクエストを**再シリアライズ**し、曖昧な CL/TE を自分の解釈で
  framing し直す」ため。生バイトを素通ししないので古典的 desync が成立しにくい。
- 本リグは**手選びの8ベクタ**のみ。網羅ではない。**次段**は driver をファザー化し、
  ヘッダ/チャンクを変異させて proxy 経由で送り、「pingora が解釈したリクエスト数」と
  「バックエンドが解釈したリクエスト数/パス」を自動 diff する（HTTP Garden 方式）。
  nginx / Apache / Node など**さらに別のパーサ**を増やすほど desync の芽を拾いやすい。

## 注意
- すべて自分のマシン上のプロセス同士。外部へは一切送らない。
- 本物の desync を見つけたら HackerOne の Cloudflare プログラムへ非公開報告（scope 要確認）。
