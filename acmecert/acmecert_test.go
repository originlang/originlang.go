package acmecert

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDNS01RecordName(t *testing.T) {
	cases := map[string]string{
		"example.com":     "_acme-challenge.example.com",
		"a.b.example.com": "_acme-challenge.a.b.example.com",
		"example.com.":    "_acme-challenge.example.com",
	}
	for in, want := range cases {
		if got := dns01RecordName(in); got != want {
			t.Errorf("dns01RecordName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadOrCreateAccountKey(t *testing.T) {
	dir := t.TempDir()

	key1, err := loadOrCreateAccountKey(dir)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	// 再次加载应从缓存读取同一密钥。
	key2, err := loadOrCreateAccountKey(dir)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if key1.D.String() != key2.D.String() {
		t.Error("account key not persisted/reloaded consistently")
	}

	// 缓存文件应存在。
	path := filepath.Join(dir, accountKeyFileName)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	// 注意：文件权限位在 Windows 上不强制，故此处不校验 0600。
}

func TestNewDNS01IssuerRequiresSolver(t *testing.T) {
	if _, err := NewDNS01Issuer(DNS01Config{}); err == nil {
		t.Fatal("expected error when Solver is nil")
	}
}

func TestObtainRequiresDomains(t *testing.T) {
	issuer := &DNS01Issuer{cfg: DNS01Config{Solver: &CloudflareSolver{}}}
	if _, err := issuer.Obtain(context.Background(), nil); err == nil {
		t.Fatal("expected error when domains is empty")
	}
}

func TestManagerConfig(t *testing.T) {
	m := NewManager(ManagerConfig{
		Email:       "ops@example.com",
		CacheDir:    t.TempDir(),
		Hosts:       []string{"example.com"},
		RenewBefore: 10 * 24 * time.Hour,
	})
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.Raw() == nil {
		t.Fatal("underlying manager is nil")
	}
	// TLSConfig 应可正常构建。
	if cfg := m.TLSConfig(); cfg == nil {
		t.Fatal("TLSConfig returned nil")
	}
}
