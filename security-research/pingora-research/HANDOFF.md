# Pingora 脆弱性リサーチ — 引き継ぎメモ

> 目的: Cloudflare Pingora（Rust製 HTTP プロキシ基盤）のバグバウンティ（HackerOne）を
> 短期の収益化ターゲットとして検討。HTTP/1.x のフレーミング／リクエストスマグリング系を狙う。
> このファイルは別セッション／Warp で続きをやるための引き継ぎ資料。

最終更新: 2026-10-09

---

## 0. 前提と心構え（過大評価しないための注記）

- **低確率・高単価**の活動。「必ず数週間で見つかる」ものではない。空振り前提で、見つけた
  ハーネスは OSS 貢献（PR）として出し、実績・評判に転化する二段構えで考える。
- **検証は必ず自分がビルドしたバイナリに対してのみ**。Cloudflare 本番や第三者サーバへ
  攻撃的な入力を送らない。
- 見つけたら公開 Issue ではなく **HackerOne 経由で非公開報告**。各プログラムの scope と
  除外条件（DoS 除外の有無、対象バージョン）を事前確認。
- **既知 CVE と同じパターンの再探索はほぼ無駄**（修正済み）。狙うのは「修正の隣」と
  「新機能の先」。

---

## 1. 既知 CVE（2025-12 報告 → 2026-03 公開、修正は v0.8.0）

報告者: Rajat Raghav 氏（HackerOne 経由で Cloudflare へ責任ある開示）。

| CVE | 種別 | 根本原因 | 影響 | 修正 |
|---|---|---|---|---|
| CVE-2026-2833 | リクエストスマグリング (CWE-444) | `Upgrade` ヘッダ付きリクエストで、バックエンドが upgrade を承認する前に残りバイトを素通し転送 | ACL/WAF 回避、キャッシュ/上流汚染、クロスユーザのセッション乗っ取り。critical。`<=0.7.0` | v0.8.0 |
| CVE-2026-2835 | リクエストスマグリング | ①HTTP/1.0 ボディを close-delimited 扱い（RFC 9112 違反）②複数 `Transfer-Encoding` 値の処理誤り | Pingora とバックエンドで境界 desync。信頼プロキシ IP 由来に偽装可 | v0.8.0 |
| CVE-2026-2836 | キャッシュポイズニング | 既定 CacheKey が URI パスのみで生成、`Host`(authority) を含まない。alpha キャッシュ機能 | マルチテナントでのクロスオリジン応答混入、情報漏えい。CVSS 8.4 | v0.8.0（危険な既定実装を削除） |

**注意**: 2836 はスマグリングではなく設計（キャッシュキー）の問題。コード精読向き。

暫定緩和（2833）: `request_filter` で `Upgrade` ヘッダ付きリクエストにエラーを返す。

出典:
- https://vulert.com/vuln-db/CVE-2026-2833
- https://advisories.gitlab.com/cargo/pingora-core/CVE-2026-2833/
- https://cvemon.intruder.io/cves/CVE-2026-2835
- https://vulert.com/vuln-db/CVE-2026-2836
- https://www.tenable.com/cve/CVE-2026-2836
- Cloudflare blog: https://blog.cloudflare.com/pingora-oss-smuggling-vulnerabilities （※この調査環境からは egress ブロックで未取得。別環境で確認推奨）

---

## 2. バージョン間調査の確定結果（git 履歴ベース）

手元で `cloudflare/pingora` をフルクローンして確認した事実（tag: 0.2.0〜0.9.0、commit 769個）。

### 「A: 修正 or B: 新機能」問題の決着 → **B（新機能）**

- **CVE 修正は 0.7.0→0.8.0 側**にある:
  - `2f59535 Prevent v1 reuse on body overread (pipeline)` ← overread desync 対策
  - `1e3469b Fix upgrade handling if body not init`
  - `87e2e2f Reject non-chunked transfer-encoding`
  - `fc904c0 Reject invalid content-length v1 requests`
  - `7f7166d transfer-encoding parsing robustness`
  - `d3d2cf5 Disable CONNECT method proxying by default`
  - `824bdee Upgrade body mode on 101`
- **0.8.0→0.9.0 の pipelining は新機能**（修正ではない）:
  - `4a9a34c Support HTTP/1.1 request pipelining on the downstream session`
  - `bd054ba Avoid copying buffered HTTP/1 pipelines`

→ 「報告されたパイプライン desync は修正済み。0.9.0 のパイプライン機能は別物の新規コードで日が浅い」。

### 見分け方のルール
コミット動詞で判別: `Prevent / Reject / Fix / Validate` = 修正、`Support / Add` = 新機能。

### 0.8.0→0.9.0 のフレーミング関連コミット（要精読リスト）
```
1ed40d4 Prevent reuse after incomplete H1 responses
baf4fe5 Parse non-origin-form request targets without mangling the URI
5bec405 Reconcile Content-Length per RFC 9110 §8.6 across H1 and H2   ← H2/H1 整合
ca23f16 pingora-proxy: reject malformed Connection nominations of protected headers
b90d420 Reject invalid H1 upgrade task streams
7142ad4 handle upstream task-pipe closure on early downstream finish
28c18e6 Sanitize hop-by-hop headers on HTTP upstream requests
b8aacad Reject request lines containing delimiter bytes
d248583 Explicitly prevent h1 upstream reuse when send fails
4a9a34c Support HTTP/1.1 request pipelining on the downstream session  ← 新機能本体
```

---

## 3. 新機能 `4a9a34c` の解剖（= 攻撃面の地図）

コミット本文（著者 Cody Carlsen, 2026-05-13）から読み取れる危険箇所:

- `set_pipelining_enabled()` で **opt-in**、既定 off。
  → 有効化した利用者のみ対象なので **重大度は下がりやすい**（報奨金が小さい/対象外の可能性）。
- ただし **「reuse を既定で pipelining-aware 化」= 既定経路のコードも全員分変わった**。
  → opt-in しなくても通る新コードに退行がないかが本命。
- `pipelined_prefix` を keep-alive の **再利用をまたいで持ち越す**。`read_request()` が
  最初に prefix を消費。→ 接続をまたぐ状態の持ち越し＝取り違えが起きやすい。
- 2つの波形:
  - **same-segment overread**（両リクエストが1回の read で到着）→ `reuse_pipelined()`
  - **two-segment overread**（応答書き込み中に次リクエスト到着）→ `read_body_or_idle()` の
    idle 分岐が非ゼロ read を stash
- 既定 off 時の挙動: 2本目は drop されるか 400（body-pump idle branch）。
- Resolves #377, #673。

---

## 4. 探索の方向（優先順位・確定版）

既知 h1 フレーミングは監査が濃い。**既定経路の reuse 退行 > opt-in pipelining 本体 > 隣接層**。

1. **既定経路の reuse 退行**（全利用者が対象）: CVE `2f59535`(overread 対策) を
   新機能が再び触って緩めていないか。`reuse` / `read_body_bytes` 系の関数差分を追う。
2. **`pipelined_prefix` の持ち越し**: リクエスト A の prefix がリクエスト B の解釈に
   正しくリセットされるか。接続再利用をまたいだ状態取り違え → スマグリング直結。
3. **two-segment overread のタイミング分岐**: 再現にタイミングが要り、人目/自動テストが手薄。
4. **レイヤーまたぎの不整合**（監査が薄い新天地）:
   - **H2→H1 ダウングレード変換**（`5bec405` で CL 整合を触っている）。h2 で受けて h1 で
     上流へ出す再構築は h1 単体ほど監査されていない。
   - **pingora-cache**（alpha、2836 の震源）。CacheKey/`Vary`/revalidation の不整合。
   - **hop-by-hop 除去/ヘッダ正規化の全経路一貫性**（`28c18e6` 等、0.9.0 で入ったばかり）。

---

## 5. 次にやる作業手順（コマンド付き）

```bash
# フルクローン（浅いと履歴を追えない）
git clone https://github.com/cloudflare/pingora && cd pingora
git fetch --unshallow   # 既に浅ければ

# バージョン間で関心語のコミット抽出
git log --oneline 0.8.0..0.9.0 -i --grep="pipelin"
git log --oneline 0.7.0..0.8.0 -i --grep="smuggl\|upgrade\|transfer\|content-length\|pipelin"

# 新機能の中身と変更ファイル
git show 4a9a34c
git grep -n "pipelined_prefix\|set_pipelining_enabled\|reuse_pipelined\|read_body_or_idle" \
  -- 'pingora-core/src/protocols/http/v1/*'

# CVE 修正関数を新機能が再び触っていないか（関数単位の履歴）
git log --oneline -L :read_body_bytes:pingora-core/src/protocols/http/v1/server.rs | head
git log --oneline -L :reuse:pingora-core/src/protocols/http/v1/server.rs | head
```

対象コードの入口（確認済みパス）:
- `pingora-core/src/protocols/http/v1/server.rs`
  - `HttpSession::new()` (L167), `read_request()` (L278), `read_body_bytes()` (L586),
    `is_body_done()` (L641), `reuse()` (L1450)
  - テストは `tokio_test::io::Builder` でモックソケットを作る（L1865〜）。ハーネスも同手法。
- モジュール公開状況: `pingora_core::protocols::http::v1::server`（pub）から `HttpSession` 使用可。

---

## 6. 差分ファジングの設計（当たりやすい本命手法）

**目的**: 同一バイト列を Pingora と独立実装（hyper / httparse 等）に解釈させ、
**フレーミング（区切り）の食い違い**を探す。値ではなく「何個のリクエストに、どこで区切ったか」。

### 比較する3つの観測値（オラクル）
1. リクエスト個数
2. 各リクエストのボディ長
3. 2本目の開始位置（1本目の終端オフセット）

いずれか不一致 = スマグリング候補。

### コーパスの種（既知の実装差ポイント。CRLF は実際には `\r\n`）
- CL と TE を両方付与
- TE 綴り崩し: `Transfer-Encoding :chunked`（コロン前空白）、`\tchunked`、大小混在
- TE 重複/リスト: 2行に分割、`gzip, chunked`
- CL 表記ゆれ: `+6`、先頭ゼロ、重複 `Content-Length`
- チャンク崩し: `0x` 接頭、サイズ前後空白、チャンク拡張 `5;ext=1`
- 行区切り: `\n` のみ、ヘッダ折り返し（次行を空白開始）
- `Upgrade` ヘッダ後に2本目（CVE-2026-2833 の形）
- **パイプライン連結（0.9.0 新機能狙い）: keep-alive 上に複数リクエストを連結、
  2本目の開始位置一致を見る。種を厚めに。**

### 判定ロジック（概念）
```
for input in fuzzer_inputs:
    a = pingora_parse(input)   # (count, body_lens, end_offsets)
    b = hyper_parse(input)     # 独立実装
    if a != b: save(input)     # 食い違い = 調査対象
```
- 比較対象は Pingora とコードを共有しない独立実装にする（同じ解析器だと差が出ない）。
- クラッシュ検知と違い「落ちないが解釈がずれる」ものを拾えるのが価値。

### レベル設計
- L1: 単体ハーネス（panic / 無限ループ / メモリ暴走を検知。`cargo-fuzz`）
- L2: 差分オラクル（上記。スマグリング候補を検知）← 本命
- L3: docker-compose 実証（送信 → Pingora プロキシ → 生バイト記録バックエンド。
  中継リクエスト数とバックエンド受信数のずれを再現。報告にはここまで必要）

### L1 ハーネス雛形
`fuzz/fuzz_targets/http1_server.rs`（`cargo +nightly fuzz init` 後）:
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use pingora_core::protocols::http::v1::server::HttpSession;
use std::sync::OnceLock;
use tokio_test::io::Builder;

static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 { return; }
    let input = &data[1..];
    let cut = (data[0] as usize % input.len()).max(1);
    let (a, b) = input.split_at(cut);   // TCP 分割到着を再現
    let rt = RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    });
    rt.block_on(async {
        let mut io = Builder::new();
        io.read(a);
        if !b.is_empty() { io.read(b); }
        let mut s = HttpSession::new(Box::new(io.build()));
        if let Ok(Some(_)) = s.read_request().await {
            while let Ok(Some(_)) = s.read_body_bytes().await {}
        }
    });
});
```
`fuzz/Cargo.toml` の依存: `pingora-core`(path), `tokio`, `tokio-test`。

実行:
```bash
rustup install nightly
cargo install cargo-fuzz
mkdir -p fuzz/corpus/http1_server
printf 'GET / HTTP/1.1\r\nHost: a\r\n\r\n' > fuzz/corpus/http1_server/get
printf 'POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n' \
  > fuzz/corpus/http1_server/chunked
cargo +nightly fuzz run http1_server -- -max_len=4096 -timeout=5 -rss_limit_mb=2048
```

---

## 7. 参考: 公開手法
- HTTP Garden / T-Reqs（差分ファジングによる HTTP スマグリング発見研究）。
  本調査の L2 はこの考え方に基づく。

---

## 8. TODO（別セッションでの着手順）
- [ ] `git show 2f59535` と `4a9a34c` の diff を突き合わせ、`reuse`/`read_body_bytes` の
      退行有無を確定（セクション5のコマンド）。
- [ ] L1 ハーネスを実ビルド（このリポジトリ外か新規リポジトリに pingora を置く）。
- [ ] L2 差分オラクル（Pingora vs hyper）を実装、パイプライン連結の種を投入。
- [ ] 食い違いが出たら L3 docker-compose で実証。
- [ ] HackerOne の Cloudflare プログラム scope / 除外を確認してから報告判断。
