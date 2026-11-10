package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/originlang/originlang.go/acmecert"
)

// Gateway 是一个带自动 HTTPS（ACME/Let's Encrypt）的反向代理网关，
// 组合了 Proxy 转发能力与 acmecert 自动证书能力。
//
// 通过参数配置上游目标、监听地址、证书信息后，调用 Run 即可在
// 80/443 端口一键启动：80 端口响应 http-01 挑战并将流量重定向到
// HTTPS，443 端口通过自动签发的证书提供 TLS 转发。
type Gateway struct {
	proxy   *Proxy
	certMgr *acmecert.Manager

	// HTTPAddr 是 80 端口监听地址，例如 ":80"。
	HTTPAddr string
	// HTTPSAddr 是 443 端口监听地址，例如 ":443"。
	HTTPSAddr string

	// Handler 是可选的兜底处理器；nil 时使用默认行为。
	Handler http.Handler

	serverHTTP  *http.Server
	serverHTTPS *http.Server
}

// GatewayConfig 配置一个反向代理网关。
type GatewayConfig struct {
	// Config 是反向代理的转发配置（上游目标、负载均衡、路径重写等）。
	Config Config

	// HTTPAddr 是 HTTP（80）监听地址，空则默认 ":80"。
	HTTPAddr string
	// HTTPSAddr 是 HTTPS（443）监听地址，空则默认 ":443"。
	HTTPSAddr string

	// Email 是 ACME 账户联系邮箱，CA 用它通知证书问题。
	Email string
	// CacheDir 是证书缓存目录，强烈建议指定以持久化证书。
	CacheDir string
	// Hosts 是允许签发的域名白名单。为空则允许所有主机（不推荐）。
	Hosts []string
	// RenewBefore 指定证书到期前多久续期，0 使用默认值。
	RenewBefore time.Duration

	// Handler 是可选的兜底处理器；nil 时 80 端口对非挑战请求
	// 重定向到 HTTPS，443 端口直接走代理。
	Handler http.Handler
}

// NewGateway 依据配置创建一个反向代理网关。
func NewGateway(cfg GatewayConfig) (*Gateway, error) {
	if cfg.Email == "" {
		return nil, errors.New("proxy: GatewayConfig.Email is required")
	}

	certMgr := acmecert.NewManager(acmecert.ManagerConfig{
		Email:       cfg.Email,
		CacheDir:    cfg.CacheDir,
		Hosts:       cfg.Hosts,
		RenewBefore: cfg.RenewBefore,
	})

	httpAddr := cfg.HTTPAddr
	if httpAddr == "" {
		httpAddr = ":80"
	}
	httpsAddr := cfg.HTTPSAddr
	if httpsAddr == "" {
		httpsAddr = ":443"
	}

	return &Gateway{
		proxy:     New(cfg.Config),
		certMgr:   certMgr,
		HTTPAddr:  httpAddr,
		HTTPSAddr: httpsAddr,
		Handler:   cfg.Handler,
	}, nil
}

// Proxy 返回内部的反向代理实例，便于调用方自定义。
func (g *Gateway) Proxy() *Proxy {
	return g.proxy
}

// CertManager 返回内部的证书管理器，便于调用方访问底层能力。
func (g *Gateway) CertManager() *acmecert.Manager {
	return g.certMgr
}

// Run 阻塞运行网关：80 端口处理 http-01 挑战并重定向，443 端口
// 提供自动证书的 HTTPS 反向代理。任一服务出错即返回。
func (g *Gateway) Run() error {
	errCh := make(chan error, 2)

	// 443 端口：HTTPS 反向代理。
	handler := http.Handler(g.proxy)
	if g.Handler != nil {
		handler = g.Handler
	}
	g.serverHTTPS = &http.Server{
		Addr:      g.HTTPSAddr,
		Handler:   handler,
		TLSConfig: g.certMgr.TLSConfig(),
	}

	// 80 端口：http-01 挑战 + 重定向到 HTTPS。
	g.serverHTTP = &http.Server{
		Addr:    g.HTTPAddr,
		Handler: g.certMgr.HTTPHandler(g.Handler),
	}

	go func() {
		if err := g.serverHTTPS.ListenAndServeTLS("", ""); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("proxy: https server: %w", err)
		}
	}()
	go func() {
		if err := g.serverHTTP.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("proxy: http server: %w", err)
		}
	}()

	return <-errCh
}

// Shutdown 优雅关闭网关的两个服务。
func (g *Gateway) Shutdown(ctx context.Context) error {
	var errs []error
	if g.serverHTTPS != nil {
		if err := g.serverHTTPS.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if g.serverHTTP != nil {
		if err := g.serverHTTP.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("proxy: shutdown: %v", errs)
	}
	return nil
}
