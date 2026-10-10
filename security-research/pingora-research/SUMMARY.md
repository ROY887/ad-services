# Rust OSS セキュリティ監査・ファジング 成果サマリ

対象: Cloudflare **pingora** 0.9.0（HTTP/1 ダウンストリーム framing）、Mozilla **neqo**（QUIC/HTTP3）
期間: 2026-10 / 手法: cargo-fuzz、ソース監査、実地差分（独立パーサ比較）

## 結論（先に）

- **悪用可能な脆弱性は発見されなかった。** 試したものはすべて偽陽性として切り分け済み。
- これは対象クレートが（特に pingora 0.8.0 の CVE 修正以降）**よく固められている**ことの裏返し。
- 確実に残る資産は 3 つ: ①pingora に無かった **HTTP/1 ファジングハーネス**（OSS 貢献候補、issue
  [cloudflare/pingora#1049](https://github.com/cloudflare/pingora/issues/1049) 起票済み）、②**L3 実地差分リグ**、
  ③**framing 監査レポート**（本書 + `l3/README.md`）。

## やったこと

### 1. neqo ファジング環境（`neqo-research/`）
- NSS 3.131 を github ミラー + apt の NSPR 4.35 で**静的ビルド**する再現手順を確立
  （`hg.mozilla.org` 遮断・docker 無しのクラウド環境での回避込み）。`setup-neqo-fuzz.sh` で再現可。
- neqo 同梱の 12 fuzz ターゲットをビルド・試走。
- **方針判断**: neqo の decoder 群は OSS-Fuzz 相当で継続ファジング済み。同じターゲットの再実行は
  Google の計算資源と競合し EV が低い → 深追いしない。

### 2. pingora in-process ファジング（`fuzz/` + `contribution/fuzz/`）
- pingora は fuzz ターゲットを**同梱していない**（CI は Semgrep のみ、OSS-Fuzz 未加入）。
- `h1_request`（堅牢性）/ `h1_differential`（vs httparse）を作成、約500万実行。クラッシュ・真の差分なし。
- **構造的知見**: pingora も比較相手の hyper も `httparse` を使うため、in-process 差分は
  ヘッダ/チャンク境界の食い違いを**原理的に観測できない**（層を間違えていた）。

### 3. pingora framing 手動監査 + L3 実地差分（`l3/`）
既知 CVE（2833 Upgrade / 2835 HTTP1.0+TE、いずれも手動バウンティで発見され 0.8.0 で修正）と
同型の desync を、**修正されていない経路**および **0.9.0 新規のダウンストリーム・パイプライン**で探索。

- `server.rs`/`body.rs`/`common.rs`（13K 行）を監査し、厳密 RFC-9112 バックエンドと食い違い得る
  具体箇所を 6 つ特定。
- それらを 14 の的を絞ったベクタに落とし、**独立パーサ（Go net/http）バックエンド**へ
  pingora 経由で送出。両パイプラインモードで実測。
- **結果: desync ゼロ。** 全ベクタが「400 拒否 / コネクション close で破棄 / 不活性な本体として転送 /
  空本体後の正当な2本目（両者が境界一致）」のいずれかに正しく収束。
- 監査で疑った `Content-Length: +N`（Rust `i64::parse` が先頭 `+` を受理）は、`validate_content_length`
  が framing 前に符号を弾くため**到達不能**と実測で確認。
- 素朴なオラクル（「ON で /SMUGGLED 4件 = desync」）は誤り。4件を一つずつ正当と切り分け、
  **バウンティで偽陽性を出すのを回避**した。

## OSS 貢献（`contribution/`）
pingora に欠けている fuzz ターゲットを本体へ寄贈する準備一式。pingora の CONTRIBUTING が
「非自明 PR は先に issue」を要求するため、issue [#1049](https://github.com/cloudflare/pingora/issues/1049)
を起票済み。**メンテナが方針 OK を返したら** fork → PR（`PR.md` は `Closes #1049.` 反映済み）。

## 学び / 次にやるなら
- 成熟した Rust プロキシの HTTP framing で短期に報酬バグを引く確率は低い（本件で2手法とも「無し」）。
- もし継続するなら EV が高い順に: ①L3 を HTTP Garden 方式のカバレッジ誘導ファザー化し nginx/Node など
  独立パーサを増やす、②HTTP framing を離れ、ネットワーク入力から到達する panic/リソース枯渇 DoS や
  `unsafe`/FFI 境界（neqo↔NSS）など**手付かずの層**を狙う。
