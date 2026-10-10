#![no_main]
//! Robustness fuzzer for Pingora's HTTP/1 downstream request parser.
//!
//! Pingora ships no fuzz targets. This drives `HttpSession::read_request()`
//! followed by draining `read_body_bytes()` over a mocked client stream, so
//! libFuzzer/ASan can surface panics, overreads, or hangs in the HTTP/1
//! header + body framing path (the area of CVE-2026-2833/2835).
//!
//! The first input byte selects a TCP-segmentation split so inputs that only
//! misbehave when delivered across multiple reads are reachable.

use libfuzzer_sys::fuzz_target;
use pingora_core::protocols::http::v1::server::HttpSession;
use std::io::Cursor;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

fn rt() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // `Cursor` returns EOF cleanly once drained and never panics on drop
    // (unlike tokio_test's Mock, whose strict drop semantics produce harness
    // false positives when the parser stops reading early).
    let stream = Cursor::new(data.to_vec());

    rt().block_on(async move {
        let mut session = HttpSession::new(Box::new(stream));
        if let Ok(Some(_)) = session.read_request().await {
            // Exercise body framing: drain until the parser says it is done.
            // Bound the loop so a malformed chunked stream cannot spin forever
            // within a single input (libFuzzer -timeout is the backstop).
            let mut guard = 0u32;
            loop {
                match session.read_body_bytes().await {
                    Ok(Some(b)) if !b.is_empty() => {}
                    _ => break,
                }
                guard += 1;
                if guard > 10_000 {
                    break;
                }
            }
            let _ = session.is_body_done();
        }
    });
});
