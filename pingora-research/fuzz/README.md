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

## これまでの結果（短時間走行）

検証環境: nightly rustc 1.101 / cargo-fuzz 0.13.2 / pingora 0.9.0

- `h1_request`: 212,901 runs / クラッシュなし
- `h1_differential`（ヘッダ境界のみ版）: 831,264 runs / 食い違いなし
- 本体長オラクル追加後も短時間では食い違いなし

→ pingora 0.9.0 の H1 パーサは短時間ファジングでは堅牢。**本命は長時間走行 + 差分対象の
拡張**（quiche/nginx との三者差分、パイプライン prefix をまたぐ状態、chunked の実装差）。
詳細な方向性は `../HANDOFF.md` 参照。

## 注意

- 検証は手元ビルドのみ。外部へ攻撃入力を送らない。
- 見つけたら HackerOne の Cloudflare プログラムへ非公開報告（scope/除外を事前確認）。
- バグが出なくても、このハーネスは pingora への PR として価値がある（同梱ゼロのため）。
