// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]
//! Differential HTTP/1 request-framing fuzzer: Pingora vs. an independent
//! parser (`httparse`, the header parser hyper uses).
//!
//! Request smuggling arises when a proxy and its backend disagree on where one
//! request ends and the next begins. This target feeds one byte string to both
//! parsers and flags the *dangerous* disagreement only:
//!
//!   both accept the request  AND  they place the end of the header section
//!   at a different offset (so the body — and the next request — start in
//!   different places).
//!
//! The safe direction (Pingora rejects what the reference accepts) is ignored:
//! a proxy that refuses the message cannot smuggle it. This keeps the signal
//! high and false positives low. Any panic here is a divergence worth triaging
//! by hand before reporting.

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

/// What the independent reference (httparse + strict RFC-9112 framing) sees.
struct RefView {
    /// Byte length of the header section incl. the final CRLFCRLF.
    hdr_len: usize,
    /// Reference body framing for the no-Transfer-Encoding case:
    ///   Some(n) => body is exactly n bytes (Content-Length), or 0 if absent.
    ///   None    => Transfer-Encoding present (chunked): skip the CL oracle.
    cl_body: Option<u64>,
}

fn reference_view(input: &[u8]) -> Option<RefView> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    let hdr_len = match req.parse(input) {
        Ok(httparse::Status::Complete(n)) => n,
        _ => return None,
    };

    let mut has_te = false;
    let mut cls: Vec<&[u8]> = Vec::new();
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            has_te = true;
        } else if h.name.eq_ignore_ascii_case("content-length") {
            cls.push(h.value);
        }
    }

    let cl_body = if has_te {
        None // chunked framing handled elsewhere; keep this oracle clean
    } else {
        match cls.as_slice() {
            [] => Some(0), // request with no body framing => empty body
            [one] => {
                // strict: all ASCII digits, fits in u64
                let s = std::str::from_utf8(one).ok()?;
                match s.parse::<u64>() {
                    Ok(v) if s.bytes().all(|b| b.is_ascii_digit()) => Some(v),
                    // reference does not accept this CL: cannot assert a length,
                    // so skip (avoid false positives on the safe direction)
                    _ => return None,
                }
            }
            // multiple CL headers: ambiguous; a strict backend errors. Skip:
            // pingora also errors here, and asserting is noisy.
            _ => return None,
        }
    };

    Some(RefView { hdr_len, cl_body })
}

fuzz_target!(|input: &[u8]| {
    // Reference view first (cheap, no async).
    let Some(rv) = reference_view(input) else {
        return; // reference doesn't accept / is a skipped case
    };

    // The body-length oracle is only sound when we can actually supply the
    // whole body; for a huge Content-Length we cannot, and a premature EOF is
    // noise, not a desync. So only exercise it when CL fits this cap, and feed
    // exactly CL + a small sentinel so pingora must stop precisely at CL.
    const MAX_CL: u64 = 1 << 20; // 1 MiB
    let cl_oracle = rv.cl_body.filter(|&n| n <= MAX_CL);

    let mut pinput = input[..rv.hdr_len].to_vec();
    if let Some(n) = cl_oracle {
        pinput.resize(rv.hdr_len + n as usize + 16, b'A');
    }
    let stream = Cursor::new(pinput);

    rt().block_on(async move {
        let mut session = HttpSession::new(Box::new(stream));
        let parsed = session.read_request().await;
        let Ok(Some(_)) = parsed else {
            return; // pingora rejects / needs more: safe direction, skip
        };

        // (1) Header boundary agreement.
        let pingora_hdr_len = session.get_headers_raw_bytes().len();
        if pingora_hdr_len != rv.hdr_len {
            let raw = session.get_headers_raw_bytes();
            // Ignore legitimate request-line normalization (URI escaping).
            if raw.as_ref() == &input[..pingora_hdr_len.min(input.len())] {
                panic!(
                    "HEADER BOUNDARY DIVERGENCE: pingora={} httparse={} input={:?}",
                    pingora_hdr_len,
                    rv.hdr_len,
                    String::from_utf8_lossy(&input[..input.len().min(200)])
                );
            }
        }

        // (2) Body-length agreement for the no-TE / Content-Length case.
        // Count the body bytes pingora actually consumes and compare to the
        // reference Content-Length. A mismatch means proxy and backend place
        // the next request boundary differently -> request-smuggling primitive.
        if let Some(ref_cl) = cl_oracle {
            let mut consumed: u64 = 0;
            let mut guard = 0u32;
            loop {
                match session.read_body_bytes().await {
                    Ok(Some(b)) if !b.is_empty() => consumed += b.len() as u64,
                    Ok(Some(_)) => {}
                    _ => break,
                }
                guard += 1;
                if guard > 100_000 {
                    break;
                }
            }
            if session.is_body_done() && consumed != ref_cl {
                panic!(
                    "BODY LENGTH DIVERGENCE: pingora_consumed={} httparse_CL={} headers={:?}",
                    consumed,
                    ref_cl,
                    String::from_utf8_lossy(&input[..rv.hdr_len.min(300)])
                );
            }
        }
    });
});
