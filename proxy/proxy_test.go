package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func TestProxyForwardsRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hello" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("X-Forwarded-Host"); got == "" {
			t.Error("expected X-Forwarded-Host to be set")
		}
		w.Write([]byte("pong"))
	}))
	defer backend.Close()

	target, err := ParseTarget(backend.URL)
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}

	p := New(Config{Targets: []*Target{target}})
	front := httptest.NewServer(p)
	defer front.Close()

	resp, err := http.Get(front.URL + "/hello")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestProxyPathRewrite(t *testing.T) {
	var got string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
	}))
	defer backend.Close()

	target, _ := ParseTarget(backend.URL)
	p := New(Config{
		Targets:     []*Target{target},
		PathRewrite: StripPrefix("/api"),
	})
	front := httptest.NewServer(p)
	defer front.Close()

	if _, err := http.Get(front.URL + "/api/v1/users"); err != nil {
		t.Fatalf("GET: %v", err)
	}
	if got != "/v1/users" {
		t.Fatalf("rewritten path = %q, want /v1/users", got)
	}
}

func TestRoundRobin(t *testing.T) {
	var mu sync.Mutex
	var order []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		order = append(order, r.Host)
		mu.Unlock()
	}))
	defer backend.Close()

	// 同一个 backend 用不同 Host 头模拟多个后端。
	targets := []*Target{
		{URL: mustURL(backend.URL), Host: "a"},
		{URL: mustURL(backend.URL), Host: "b"},
		{URL: mustURL(backend.URL), Host: "c"},
	}
	p := New(Config{Resolver: RoundRobin(targets)})
	front := httptest.NewServer(p)
	defer front.Close()

	for i := 0; i < 6; i++ {
		resp, err := http.Get(front.URL + "/")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	got := strings.Join(order, ",")
	want := "a,b,c,a,b,c"
	if got != want {
		t.Fatalf("round-robin order = %q, want %q", got, want)
	}
}

func TestParseTargetErrors(t *testing.T) {
	cases := []string{
		"",
		"ftp://host:21",
		"http://",
	}
	for _, c := range cases {
		if _, err := ParseTarget(c); err == nil {
			t.Errorf("ParseTarget(%q) expected error, got nil", c)
		}
	}
}

func TestNoTargetReturns502(t *testing.T) {
	p := New(Config{})
	front := httptest.NewServer(p)
	defer front.Close()

	resp, err := http.Get(front.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}
