package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewGatewayRequiresEmail(t *testing.T) {
	if _, err := NewGateway(GatewayConfig{}); err == nil {
		t.Fatal("expected error when Email is empty")
	}
}

func TestNewGatewayDefaults(t *testing.T) {
	g, err := NewGateway(GatewayConfig{
		Email:  "ops@example.com",
		Config: Config{},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	if g.HTTPAddr != ":80" {
		t.Errorf("HTTPAddr = %q, want :80", g.HTTPAddr)
	}
	if g.HTTPSAddr != ":443" {
		t.Errorf("HTTPSAddr = %q, want :443", g.HTTPSAddr)
	}
	if g.Proxy() == nil {
		t.Error("Proxy() returned nil")
	}
	if g.CertManager() == nil {
		t.Error("CertManager() returned nil")
	}
}

func TestGatewayCustomAddrs(t *testing.T) {
	g, err := NewGateway(GatewayConfig{
		Email:     "ops@example.com",
		HTTPAddr:  ":8080",
		HTTPSAddr: ":8443",
		Config:    Config{},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	if g.HTTPAddr != ":8080" || g.HTTPSAddr != ":8443" {
		t.Errorf("addrs = %q/%q, want :8080/:8443", g.HTTPAddr, g.HTTPSAddr)
	}
}

func TestGatewayProxyForwards(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	target, _ := ParseTarget(backend.URL)
	g, err := NewGateway(GatewayConfig{
		Email: "ops@example.com",
		Config: Config{
			Targets: []*Target{target},
		},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	// 直接通过内部 Proxy 验证转发链路（避免真实 ACME 环境依赖）。
	front := httptest.NewServer(g.Proxy())
	defer front.Close()

	resp, err := http.Get(front.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestGatewayShutdown(t *testing.T) {
	g, err := NewGateway(GatewayConfig{
		Email:  "ops@example.com",
		Config: Config{},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	// 未启动时 Shutdown 应无错误（server 字段为 nil）。
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := g.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}
