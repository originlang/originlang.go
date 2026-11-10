package acmecert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme"
)

// Certificate 表示一张已签发的证书及其私钥。
type Certificate struct {
	// CertPEM 是证书链的 PEM 编码（含叶子证书及中间证书）。
	CertPEM []byte
	// KeyPEM 是私钥的 PEM 编码（PKCS#8）。
	KeyPEM []byte
	// NotAfter 是证书过期时间。
	NotAfter time.Time
	// Domains 是证书覆盖的域名。
	Domains []string
}

// DNS01Config 配置 DNS-01 方式的证书申请。
type DNS01Config struct {
	// Email 是 ACME 账户联系邮箱。
	Email string

	// Solver 是 DNS 提供商求解器，例如 *CloudflareSolver。
	Solver DNS01Solver

	// Directory 是 ACME 目录地址，空则使用 Let's Encrypt 生产环境。
	// 测试时可指向 ACME 测试环境
	// （如 https://acme-staging-v02.api.letsencrypt.org/directory）。
	Directory string

	// CacheDir 是账户密钥缓存目录，强烈建议指定以复用同一 ACME 账户。
	// 为空时每次创建新账户（不推荐，易触发 CA 限流）。
	CacheDir string

	// RenewBefore 到期前多久续期，0 使用默认值（30 天）。
	RenewBefore time.Duration
}

// DNS01Issuer 通过 DNS-01 挑战申请与续期证书。
type DNS01Issuer struct {
	cfg    DNS01Config
	client *acme.Client
}

// NewDNS01Issuer 创建一个 DNS-01 证书签发器。
func NewDNS01Issuer(cfg DNS01Config) (*DNS01Issuer, error) {
	if cfg.Solver == nil {
		return nil, fmt.Errorf("acmecert: DNS01Config.Solver is nil")
	}

	key, err := loadOrCreateAccountKey(cfg.CacheDir)
	if err != nil {
		return nil, err
	}

	c := &acme.Client{
		DirectoryURL: cfg.Directory,
		Key:          key,
	}

	if cfg.Email != "" {
		// 注册（或复用已注册的）账户。
		if _, err := c.Register(context.Background(), &acme.Account{
			Contact: []string{"mailto:" + cfg.Email},
		}, acceptTOS); err != nil {
			return nil, fmt.Errorf("acmecert: register account: %w", err)
		}
	}

	return &DNS01Issuer{cfg: cfg, client: c}, nil
}

func acceptTOS(string) bool { return true }

// Obtain 为指定域名申请一张新证书。
func (i *DNS01Issuer) Obtain(ctx context.Context, domains []string) (*Certificate, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("acmecert: no domains provided")
	}

	// 生成证书私钥。
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// 构造 CSR。
	csrTmpl := &x509.CertificateRequest{DNSNames: domains}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, privKey)
	if err != nil {
		return nil, err
	}

	// 发起授权（order），对每个域名执行 DNS-01 挑战。
	order, err := i.client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	if err != nil {
		return nil, err
	}

	for _, authzURL := range order.AuthzURLs {
		if err := i.solveAuthorization(ctx, authzURL); err != nil {
			return nil, err
		}
	}

	// 等待 order 就绪后签发。
	if _, err := i.client.WaitOrder(ctx, order.URI); err != nil {
		return nil, err
	}
	derChain, _, err := i.client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, err
	}

	certPEM := encodeChainPEM(derChain)
	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	notAfter, err := parseNotAfter(derChain[0])
	if err != nil {
		return nil, err
	}

	return &Certificate{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		NotAfter: notAfter,
		Domains:  domains,
	}, nil
}

// solveAuthorization 完成单个授权中所有 dns-01 挑战。
func (i *DNS01Issuer) solveAuthorization(ctx context.Context, authzURL string) error {
	authz, err := i.client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return err
	}

	for _, chal := range authz.Challenges {
		if chal.Type != "dns-01" {
			continue
		}
		domain := authz.Identifier.Value
		keyAuth, err := i.client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return err
		}
		if err := i.cfg.Solver.Present(ctx, domain, chal.Token, keyAuth); err != nil {
			return err
		}
		defer func() {
			_ = i.cfg.Solver.CleanUp(context.Background(), domain, chal.Token, keyAuth)
		}()

		if _, err := i.client.Accept(ctx, chal); err != nil {
			return err
		}
		if _, err := i.client.WaitAuthorization(ctx, authz.URI); err != nil {
			return err
		}
		return nil
	}
	return ErrNoChallenge
}

// encodeChainPEM 将 DER 证书链编码为 PEM。
func encodeChainPEM(derChain [][]byte) []byte {
	var out []byte
	for _, der := range derChain {
		out = append(out, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		})...)
	}
	return out
}

// parseNotAfter 解析 DER 编码证书的过期时间。
func parseNotAfter(der []byte) (time.Time, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

const accountKeyFileName = "account.key"

// loadOrCreateAccountKey 从缓存目录加载 ACME 账户私钥，不存在则生成并保存。
// CacheDir 为空时直接生成临时密钥（不持久化）。
func loadOrCreateAccountKey(cacheDir string) (*ecdsa.PrivateKey, error) {
	if cacheDir != "" {
		path := filepath.Join(cacheDir, accountKeyFileName)
		if data, err := os.ReadFile(path); err == nil {
			if key, err := decodeAccountKey(data); err == nil {
				return key, nil
			}
			// 损坏则重新生成。
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	if cacheDir != "" {
		if err := os.MkdirAll(cacheDir, 0o700); err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(filepath.Join(cacheDir, accountKeyFileName), pemData, 0o600); err != nil {
			return nil, err
		}
	}
	return key, nil
}

func decodeAccountKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("acmecert: invalid account key PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
