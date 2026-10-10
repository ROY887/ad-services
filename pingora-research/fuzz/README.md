# pingora HTTP/1 ファジングハーネス

Cloudflare Pingora の **HTTP/1 ダウンストリーム・リクエストパーサ**向けファジング。
pingora 本体は **ファジングターゲットを一つも同梱していない**ため、これ自体が新規の
OSS 貢献候補（PR）になる。狙いは CVE-2026-2833/2835 と同系統のフレーミング／スマグリング。

## ターゲット

- **`h1_request`** — 堅牢性。`HttpSession::read_request()` → `read_body_bytes()` を
  モックストリーム越しに駆動し、panic / overread / ハングを ASan + libFuzzer で検出。
- **`h1_differential`** — 差分。同一バイト列を pingora と独立実装 `httparse`
  （hyper が使うヘッダパーサ）に食わせ、**両者が受理したのに食い違う**危険ケースのみ検出:
  1. ヘッダ境界（本体開始オフセット）の不一致
  2. 本体長の不一致（no-TE / Content-Length 系。pingora が実際に消費したバイト数 vs
     httparse が読む Content-Length）。不一致＝プロキシとバックエンドで次リクエスト境界が
     ずれる＝スマグリングの原始。
  安全方向（pingora が拒否、参照が受理）は無視して誤検出を抑えている。

## 設計上の要点（ハマりどころ）

- **ストリームは `std::io::Cursor`** を使う。pingora はテスト外(`ext_io_impl`)で Cursor に
  IO トレイトを実装済み。`tokio_test::io::Mock` は **未消費 read が残ると drop で panic** し
  **ハーネス由来の偽陽性**を出すため使わない（実際に踏んだ）。
- **ビルドは `cargo +nightly fuzz build --dev`**。リリース(LTO)だと `__sancov_gen_` 未定義で
  リンク失敗する。
- 差分の本体長チェックは EOF 切り詰めを誤検出しないよう、ヘッダの後ろに十分な filler を足して
  pingora が意図した本体を必ず読み切れるようにしている。

## 使い方

```bash
# pingora を取得し、この fuzz ディレクトリを置く
git clone https://github.com/cloudflare/pingora && cd pingora
git checkout 0.9.0
cp -r /path/to/pingora-research/fuzz ./fuzz    # このディレクトリ

rustup toolchain install nightly
cargo install cargo-fuzz

cargo +nightly fuzz build --dev
cargo +nightly fuzz run --dev h1_differential -- -max_total_time=3600
cargo +nightly fuzz run --dev h1_request      -- -max_total_time=3600
```

`fuzz/Cargo.toml` は `pingora-core` を `path = "../pingora-core"` で参照し、`[workspace]` 空表で
pingora ワークスペースから切り離している。

## 結果と知見（2026-10-10 走行）

検証環境: nightly rustc 1.101 / cargo-fuzz 0.13.2 / pingora 0.9.0

| ターゲット | 実行回数 | 結果 |
|---|---|---|
| `h1_request`（堅牢性） | 累計 ~126万 runs | クラッシュ・ハング・overread **なし** |
| `h1_differential`（ヘッダ境界＋CL本体長） | 累計 ~430万 runs | 真の食い違い **なし**（偽陽性2件は下記のとおり切り分け済み） |

**切り分けた偽陽性（いずれも pingora のバグではない）:**
1. `tokio_test::io::Mock` が未消費 read で drop 時に panic → ストリームを `std::io::Cursor` に変更して解消。
2. 本体長オラクルで巨大 Content-Length（≈1.8e19）に filler を供給しきれず EOF → CL が供給可能サイズのときだけ検証するよう修正。
3. 試作した chunked 差分（`h1_chunked`、**撤去済み**）が `5;ex\r=1\r\n...`（chunk-ext 中の裸CR）で差分検出 → 調査の結果、**私の手書き参照デコーダが `httparse` 非準拠に寛容**だっただけ。`httparse::parse_chunk_size` はこの入力を `InvalidChunkSize` で拒否し、pingora も同様に拒否していた。

### 最重要の構造的知見: なぜ in-process 差分では当たらないか

pingora は **ヘッダもチャンクサイズも `httparse` で解析**している（`body.rs` の
`httparse::parse_chunk_size`、ヘッダは `httparse::Request`）。スマグリングの比較相手として
現実的なバックエンド実装（hyper）**も httparse を使う**。したがってプロセス内で独立参照と
比較しても:

- 参照が httparse と一致 → pingora とも一致 → **差分ゼロ（シグナルなし）**
- 参照が httparse と相違 → それは**参照側のバグ＝偽陽性**

**結論: pingora の本物の HTTP/1 スマグリングを探すなら、別パーサを使うバックエンド
（nginx / Go net/http / Apache）との「実地比較（L3）」が必須。** 単一プロセス内の差分や
素のファジングでは、pingora が httparse に委譲している限り新規バグは出にくい。
`h1_request`/`h1_differential` は OSS 貢献（pingora は fuzz 同梱ゼロ）としては有効だが、
報酬バグの発見器としては上限がある。次アクションは `../HANDOFF.md` の L3 docker 構成。

## 注意

- 検証は手元ビルドのみ。外部へ攻撃入力を送らない。
- 見つけたら HackerOne の Cloudflare プログラムへ非公開報告（scope/除外を事前確認）。
- バグが出なくても、このハーネスは pingora への PR として価値がある（同梱ゼロのため）。
