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

## 結果（第2ラウンド・2026-10-10 / pingora 0.9.0 `702f690` / Go net/http）

`server.rs` / `body.rs` / `common.rs` のソース監査で挙げた「厳密 RFC-9112 バックエンドと
食い違い得る」具体箇所を、的を絞った 6 ベクタとして追加（計14）。各ベクタの主リクエストパスを
`/<label>` に一意化し、`/SMUGGLED` を仕込んで**どのベクタが昇格させたか**を 1:1 で対応付けた。
`driver.py`（labeled 版）+ `run_ro.sh`（`wait` ハング回避・`timeout` 付き堅牢版）で実行。

追加ベクタと監査仮説:
- `bare_lf_end` / `bare_lf_cl_te` / `escape_retry_lf` — bare-LF 行終端（httparse は受理、pingora の
  URI エスケープ detach は `b"\r\n\r\n"` 直値を探す）の境界ズレ。
- `te_identity_first` — `is_chunked_encoding_from_headers` が**最後の TE 行**だけを見る点。
- `cl_plus` — `buf_to_content_length` が `i64::parse` で**先頭 `+` を受理**する点。
- `chunk_bare_cr` — chunk-size 行の bare-CR。

**判定: desync / スマグリングは検出されず（両パイプラインモード）。** 内訳:

| 挙動 | ベクタ | 判定 |
|---|---|---|
| **400 拒否**（バックエンド未到達） | `te_space`(`TE :`) / `te_double`(最終TE=cow) / **`cl_plus`(`CL: +54`)** | 正しく拒否 |
| コネクション close・overread 破棄 | `cl_te` / `bare_lf_cl_te`（CL+TE 併存） | 正しく close |
| SMUG を不活性な**本体**として転送 | `te_cl` / `te_tab` / `chunk_ext` / `te_identity_first` | 本体化、昇格せず |
| 空本体(CL:0/00)＋**正当な**2本目として転送 | `cl_zeros` / `pipelined_control` / `bare_lf_end` / `escape_retry_lf` | pingora と Go が**同一境界で一致** |
| bare-CR chunk を処理し空本体 | `chunk_bare_cr` | 昇格せず |

重要な確認: 監査で疑った **`i64::parse` の先頭 `+` 受理は到達不能**だった
（`validate_content_length`→`from_digits` が framing 前に `+` を弾く）。理論上の差分候補が
実測で否定された好例。素朴なオラクル（「ON で `/SMUGGLED` 4件 = desync」）は**誤り**で、
4件はすべて空本体後の正当なパイプライン 2本目であり、両パーサが境界を一致させている。

### 監査で見つけた「寛容だが悪用不能」な観察（防御的ハードニング候補・脆弱性ではない）
- `is_upgrade_req` は `Connection: upgrade` トークンを要求しない（`common.rs:190`）。
- `is_upgrade_resp` は 101 のみで応答の Upgrade/Connection を検証しない（`common.rs:206`、コメントで明言）。
- `is_chunked_encoding_from_headers` は最後の TE 行の最後のトークンのみ評価（`common.rs:168`）。
いずれも nginx 互換の設計判断で、上記の実地試験では desync に至らなかった。バウンティ対象の
脆弱性としては**報告しない**（偽陽性を避ける）。OSS 側で defense-in-depth 提案として触れる余地はある。

## 注意
- すべて自分のマシン上のプロセス同士。外部へは一切送らない。
- 本物の desync を見つけたら HackerOne の Cloudflare プログラムへ非公開報告（scope 要確認）。
