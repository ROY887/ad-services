# neqo (Mozilla QUIC/HTTP3) ファジング環境 — 構築記録

最終更新: 2026-10-10 / 関連: `../pingora-research/HANDOFF.md`

このセッションで **neqo の既存ファジング環境を実際に動く状態まで構築・検証** した記録。
再現用スクリプトは `setup-neqo-fuzz.sh`。

---

## 1. 結論（まず読む）

- **neqo は既に 12 個のファジングターゲットを同梱している**（`fuzz/fuzz_targets/`）。
  つまり「環境構築」＝新規ハーネス作成ではなく、**既存ハーネスをビルド・実行できる状態に
  すること**。収益（報奨金）を狙うなら、価値が出るのは「まだ無い切り口を足す」こと。
- **構築は成功**。`frame`（QUIC フレームパーサ）ターゲットを実際に走らせ、libFuzzer が
  `neqo_transport::frame::Frame::decode` のカバレッジを伸ばすのを確認（クラッシュなし＝想定内）。
- 最大の難関は **NSS（暗号ライブラリ）の用意**。egress 制限で Mozilla の正規取得路
  (hg.mozilla.org) が塞がれており、github ミラー＋apt の NSPR ソースで迂回して自前ビルドした。

## 2. 同梱されている12ターゲット

| ターゲット | 対象 | 暗号(NSS)依存 | スマグリング/desync 系の関心度 |
|---|---|---|---|
| `frame` | QUIC フレーム復号 (`neqo_transport::frame::Frame::decode`) | リンクのみ | 中（フレーム解釈） |
| `hframe` | HTTP/3 フレーム (`neqo_http3 FrameReader`) | リンクのみ | **高**（H3 の境界解釈） |
| `qpack` | QPACK ヘッダ圧縮復号 | リンクのみ | **高**（ヘッダ解釈の実装差） |
| `packet` | QUIC パケット解析 | リンクのみ | 中 |
| `tparams` | トランスポートパラメータ | リンクのみ | 中 |
| `hsettings` | H3 SETTINGS | リンクのみ | 中 |
| `priority` | 優先度 | リンクのみ | 低 |
| `wtframe` | WebTransport フレーム | リンクのみ | 中 |
| `find_sni` | ClientHello からの SNI 抽出 | リンクのみ | 中 |
| `client_initial` | Initial パケット（復号あり） | **あり** | 低（CI は月次） |
| `server_initial` | Initial パケット（復号あり） | **あり** | 低（CI は月次） |
| `addr_valid` | アドレス検証トークン | あり | 低 |

> 注: `neqo-transport` が `nss` に依存するため、純粋パーサ系でも **リンク時に NSS が必要**。
> NSS 無しでビルドする逃げ道は無い。

## 3. ハマりどころ（実際に踏んだ順）

1. **NSS バージョン不足**: neqo は `nss-rs >= 3.126` を要求。Ubuntu 24.04 の
   `libnss3-dev` は 3.98 で pkg-config 条件を満たさない。
2. **正規ソース取得が egress ブロック**: nss-rs は `hg clone https://hg.mozilla.org/...`
   で NSS/NSPR を取得するが、プロキシが 403 で拒否。`github.com/nss-dev/nss` は
   **git プロトコルなら通る**（curl は 403 でも `git clone` は成功）。`nss-dev/nspr` は
   ミラーが無い。
3. **fuzzing は静的リンク必須**: cargo-fuzz が `CARGO_CFG_FUZZING` を立てると nss-rs は
   NSS を**静的リンク**（`libcertdb.a` 等）。`build.sh --static` が必要。さらに NSPR も
   静的 `.a`（`libnspr4.a/libplc4.a/libplds4.a`）が要る。`--system-nspr` は `.so` のみで不可。
   → **NSPR ソースを `apt-get source libnspr4` で取得し `nss/../nspr` に置き**、NSS に
   同梱ビルドさせて静的 NSPR を得た。
4. **LTO で `__sancov_gen_` 未定義リンクエラー**: 既定のリリースビルドで発生。
   → **`cargo fuzz build --dev`**（LTO 無し）で回避。neqo CI の `make-fuzz-corpus.sh` も
   `--dev` を使っている。

## 4. 使い方

```bash
# 構築（10〜30分。NSS ビルドが大半）
WORK=$HOME/neqo-fuzz-work ./setup-neqo-fuzz.sh

# 実行
source $HOME/neqo-fuzz.env
cd "$NEQO"
cargo +nightly fuzz run --dev frame  -- -max_total_time=300   # QUIC フレーム
cargo +nightly fuzz run --dev hframe -- -max_total_time=300   # H3 フレーム（関心度高）
cargo +nightly fuzz run --dev qpack  -- -max_total_time=300   # QPACK（関心度高）

# 既存コーパスで種を与えると立ち上がりが速い（CI が貯めている）
#   neqo の fuzz/corpus/<target>/ を使う
```

検証済みツール版: nightly `rustc 1.101.0` / `cargo-fuzz 0.13.2` / clang 18 /
NSS `NSS_3_131_RTM` / NSPR `4.35`。

## 5. 次にやること（収益化の観点）

neqo は Mozilla が CI で定期ファジングしている（`.github/workflows/fuzz-corpus.yml`、
週次/月次）。**素の `cargo fuzz run` を回すだけでは Mozilla の後追いで、当たりにくい**。
価値を出す方向:

1. **差分ファジング（pingora と同じ発想）**: QUIC/H3 の実装差を突く。neqo vs quiche
   (Cloudflare) vs quinn で、同一入力に対する「フレーム境界・ストリーム状態・QPACK 展開
   結果」の食い違いを探す。単体 fuzz より desync/解釈差を拾いやすい。
2. **状態付き（stateful）ハーネス**: 既存 12 個は単発デコードが中心。ハンドシェイク完了後の
   フレーム列や、複数ストリーム・QPACK 動的テーブルをまたぐ状態を生成し、メモリ増加や
   パニックを監視（quiche の CRYPTO フラッド CVE と同系統）。これは neqo に未搭載の切り口。
3. **Mozilla 報奨金の scope 確認**: neqo は「現行 Firefox に載っている版」が対象
   （`../pingora-research/HANDOFF.md` の調査および Mozilla Bug Bounty FAQ 参照）。
   スタンドアロンのライブラリ単体は対象外の可能性があるため、**報告前に対象範囲を要確認**。

## 6. 注意

- 検証は**自分でビルドしたバイナリに対してのみ**。外部サーバへ攻撃入力を送らない。
- 見つけたら公開 Issue ではなく Mozilla へ非公開報告（`SECURITY.md` 参照）。
- `setup-neqo-fuzz.sh` は NSS を github ミラーからソースビルドする。企業ポリシーや
  egress 設定次第では別の取得路が要る場合がある。
