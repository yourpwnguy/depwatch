package registry

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestGetJSONReusesConnections guards the shared-client change. Before it,
// getJSON built a fresh http.Client per call, so every request opened a new
// TCP connection (and a new TLS handshake in production). Reusing one client
// lets Transport pool keep-alive connections, which is what makes scanning a
// large inventory cheap.
//
// The test counts actual dials rather than relying on timing: three sequential
// requests through the same client must open exactly one connection.
func TestGetJSONReusesConnections(t *testing.T) {
	var dials atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport}
	var out struct {
		OK bool `json:"ok"`
	}
	for i := 0; i < 3; i++ {
		if err := getJSON(context.Background(), client, 0, nil, srv.URL, nil, &out); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if !out.OK {
			t.Fatalf("call %d decoded wrong body", i)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("3 requests should reuse 1 connection, got %d dials", got)
	}
}
