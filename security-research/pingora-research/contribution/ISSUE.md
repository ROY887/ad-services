# (Draft) Proposal: add fuzz targets for the HTTP/1 downstream request parser

> pingora の CONTRIBUTING は「非自明な PR は先に issue で合意を」と求めているため、
> まずこの issue を起票して方針合意を取る。本文はそのまま GitHub issue に貼れる英語ドラフト。

---

**Title:** Add cargo-fuzz targets for the HTTP/1 downstream request parser

**Body:**

Pingora currently ships no fuzz targets. The HTTP/1 downstream request parser
(`pingora_core::protocols::http::v1::server::HttpSession`) is security-critical
and framing bugs there have recently produced request-smuggling CVEs
(CVE-2026-2833 / 2835). Continuous fuzzing of this parser would guard against
regressions in `read_request()` / `read_body_bytes()` and the CL/TE framing
logic.

I have a small `cargo-fuzz` setup with two targets and would like to contribute
it if the maintainers are open to it:

1. **`h1_request`** — robustness: drives `read_request()` then drains
   `read_body_bytes()` over an in-memory stream, surfacing panics, overreads,
   and hangs (ASan + libFuzzer).
2. **`h1_differential`** — differential vs `httparse`: flags the dangerous case
   where both pingora and an independent parser accept a request but disagree on
   the header boundary or Content-Length body length (a request-smuggling
   primitive). The safe direction (pingora rejects) is ignored to keep false
   positives low.

Notes:
- Uses `std::io::Cursor` as the client stream (relying on the existing
  `impl ... for Cursor` in `protocols::mod`) to avoid `tokio_test::io::Mock`'s
  drop-panic.
- Builds with `cargo +nightly fuzz build --dev` (release/LTO hits a
  `__sancov_gen_` link error).
- Ran ~5M executions on `main`/0.9.0 with no crash and no genuine divergence,
  so this is coverage/regression infrastructure, not a bug report.

Questions for maintainers:
- Do you want fuzz targets in-tree (a `fuzz/` crate), or would you prefer this
  as an external/OSS-Fuzz-style setup?
- Any preference on target naming / placement?

Happy to open the PR once you confirm the direction.
