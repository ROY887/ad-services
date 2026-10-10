# pingora への OSS 貢献パッケージ（提出準備済み・未提出）

pingora には fuzz ターゲットが無いため、作成した HTTP/1 ファジングハーネスを
**pingora 本体への貢献**として提出する準備一式。**まだ提出していない**（提出は外部操作・
あなたの GitHub フォークが必要なため、実行前に確認する）。

## 中身
- `fuzz/` — pingora リポジトリのルートに置く cargo-fuzz クレート一式
  （`h1_request` / `h1_differential` + 種コーパス + Apache-2.0 ヘッダ付き、fmt 済み、ビルド確認済み）。
- `ISSUE.md` — 先に起票する issue の英語ドラフト（pingora は非自明 PR に issue 先行を要求）。
- `PR.md` — issue 合意後に出す PR の英語ドラフト。

## 提出手順（確認後に実行）
pingora の CONTRIBUTING は「**非自明な PR はまず issue**」と明記。順序:

1. `ISSUE.md` の内容で cloudflare/pingora に issue を起票。
   → **起票済み: https://github.com/cloudflare/pingora/issues/1049（2026-10-10）**
2. メンテナが方針 OK を返したら:
   - cloudflare/pingora を自分の GitHub にフォーク。
   - フォークに `fuzz/` を追加（この `contribution/fuzz/` をリポジトリ root の `fuzz/` へ）。
   - `PR.md` の `#<ISSUE_NUMBER>` を実番号に置換して PR 作成。

## 提出前の既知の確認事項
- **ライセンスヘッダ**: リポジトリ慣例に合わせ `Copyright 2026 Cloudflare, Inc.` の
  Apache-2.0 ヘッダを使用。貢献者表記の扱いはメンテナ指示に従う。
- **CLA/DCO**: CONTRIBUTING に明示なし。PR 時に bot が要求すれば従う。
- **受理は不確実**: 「内部貢献優先・全 PR 対応は約束しない」と明記されている。受理されなくても
  ハーネス自体は手元資産として有効。

## 現状
- ビルド: `cargo +nightly fuzz build --dev` 成功（両ターゲット）。
- 整形: `cargo +nightly fmt --check` クリーン。
- 走行実績: 0.9.0 で約500万実行、クラッシュ・真の差分なし（＝回帰防止インフラとしての貢献）。
