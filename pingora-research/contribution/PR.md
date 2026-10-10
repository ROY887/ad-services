# (Draft) PR: Add fuzz targets for the HTTP/1 downstream request parser

> issue で方針合意が取れてから提出する PR 本文の英語ドラフト。
> 配置: `fuzz/` を pingora リポジトリのルートに追加（`pingora-core` を `path = "../pingora-core"`
> で参照、`[workspace]` 空表でメインワークスペースから分離）。

---

**Title:** Add cargo-fuzz targets for the HTTP/1 downstream request parser

**Body:**

Closes #<ISSUE_NUMBER>.

Adds a `fuzz/` cargo-fuzz crate with two targets for
`protocols::http::v1::server::HttpSession`, which currently has no fuzzing
coverage.

### Targets

- **`h1_request`** — robustness. Drives `read_request()` then drains
  `read_body_bytes()` over an in-memory `std::io::Cursor` stream so
  libFuzzer + ASan can surface panics, overreads, and hangs in the HTTP/1
  header and body-framing paths.
- **`h1_differential`** — differential against `httparse` (the parser hyper
  uses). For inputs both parsers accept, it flags a disagreement on:
  1. the header-section boundary (where the body starts), and
  2. the Content-Length body length pingora actually consumes vs. the
     reference CL (no-Transfer-Encoding case).
  A mismatch is a request-smuggling primitive. Only the "both accept but
  differ" direction is flagged; the safe direction (pingora rejects what the
  reference accepts) is intentionally ignored to keep false positives low.

### How to run

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz build --dev
cargo +nightly fuzz run --dev h1_request      -- -max_total_time=300
cargo +nightly fuzz run --dev h1_differential -- -max_total_time=300
```

### Notes / rationale

- Uses `std::io::Cursor` (not `tokio_test::io::Mock`) because Mock panics on
  drop when the parser stops reading early, which would be a harness-level
  false positive.
- `--dev` builds are used because the default release/LTO build fails to link
  with `undefined symbol: __sancov_gen_`.
- I ran ~5M executions across both targets on 0.9.0 with no crashes and no
  genuine framing divergence (two false positives were triaged out: a huge
  Content-Length that outran the supplied body, and a non-conforming
  hand-rolled chunked reference that was dropped). This PR is therefore
  regression/coverage infrastructure, not a bug fix.

### Testing

- `cargo +nightly fuzz build --dev` succeeds for both targets.
- `cargo +nightly fmt --check` clean.
- Seed corpora included under `fuzz/corpus/`.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_017dqDZaqh4kT5mRV8JCNExY
