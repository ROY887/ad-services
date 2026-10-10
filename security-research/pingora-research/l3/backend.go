// Backend using Go net/http (parser independent of httparse/pingora).
// Logs one line per request it parses, so a smuggled (hidden) request shows
// up as an extra handler invocation.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
)

var seq int64

func main() {
	h := func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&seq, 1)
		body, _ := io.ReadAll(r.Body)
		// One structured line per request Go parsed.
		fmt.Fprintf(os.Stderr, "BACKEND_REQ #%d method=%q path=%q cl=%q te=%q bodylen=%d body=%q\n",
			n, r.Method, r.URL.Path, r.Header.Get("Content-Length"),
			r.Header.Get("Transfer-Encoding"), len(body), truncate(body, 64))
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	}
	srv := &http.Server{Addr: "127.0.0.1:8899", Handler: http.HandlerFunc(h)}
	fmt.Fprintln(os.Stderr, "BACKEND listening :8899")
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "backend error:", err)
	}
}

func truncate(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}
