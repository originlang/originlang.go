// Package acmecert 提供基于 ACME（Let's Encrypt）协议的自动 TLS 证书
// 申请与续期能力，供其他应用作为库调用。
//
// 支持两种证书验证方式：
//
//  1. HTTP-01 / TLS-ALPN-01（公网模式）：域名解析到本机且开放 80/443 端口，
//     基于 golang.org/x/crypto/acme/autocert 自动签发与续期。
//
//  2. DNS-01（内网模式）：通过 DNS 提供商 API（内置 Cloudflare）自动添加
//     与删除 _acme-challenge TXT 记录完成验证，无需开放端口。
package acmecert

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Manager 封装 autocert.Manager，提供简化的公网模式证书管理。
type Manager struct {
	m *autocert.Manager
}

// ManagerConfig 配置公网模式证书管理器。
type ManagerConfig struct {
	// Email 是联系邮箱，CA 用它通知证书问题。
	Email string

	// CacheDir 是证书缓存目录，强烈建议指定以持久化证书，
	// 避免每次重启重复签发。为空时仅内存缓存。
	CacheDir string

	// Hosts 是允许签发的域名白名单。为空则允许所有主机
	// （不推荐，可能导致 CA 限流）。
	Hosts []string

	// RenewBefore 指定证书到期前多久续期，0 使用默认值。
	RenewBefore time.Duration
}

// NewManager 创建一个公网模式证书管理器。
func NewManager(cfg ManagerConfig) *Manager {
	m := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Email:       cfg.Email,
		RenewBefore: cfg.RenewBefore,
	}
	if cfg.CacheDir != "" {
		m.Cache = autocert.DirCache(cfg.CacheDir)
	}
	if len(cfg.Hosts) > 0 {
		m.HostPolicy = autocert.HostWhitelist(cfg.Hosts...)
	}
	return &Manager{m: m}
}

// TLSConfig 返回一个配置了自动证书与 tls-alpn-01 挑战的 *tls.Config，
// 可直接赋给 http.Server.TLSConfig 或用于 tls.Listen。
func (m *Manager) TLSConfig() *tls.Config {
	return m.m.TLSConfig()
}

// HTTPHandler 返回处理 http-01 挑战的 Handler，应运行在 80 端口。
// fallback 为非挑战请求时的兜底处理器；nil 时将 GET/HEAD 重定向到 HTTPS。
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return m.m.HTTPHandler(fallback)
}

// GetCertificate 实现 tls.Config.GetCertificate，按需获取/续期证书。
// 主要用于自定义 tls.Config 的场景。
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.m.GetCertificate(hello)
}

// Raw 返回底层 *autocert.Manager，供需要完整能力的调用方使用。
func (m *Manager) Raw() *autocert.Manager {
	return m.m
}

// DNS01Solver 抽象 DNS 提供商接口，用于 DNS-01 挑战时管理 TXT 记录。
type DNS01Solver interface {
	// Present 添加一条 _acme-challenge TXT 记录，返回清理函数或错误。
	Present(ctx context.Context, domain, token, keyAuth string) error
	// CleanUp 删除之前添加的 TXT 记录。
	CleanUp(ctx context.Context, domain, token, keyAuth string) error
}

// ErrNoChallenge 表示 ACME 授权中未找到指定类型的挑战。
var ErrNoChallenge = errors.New("acmecert: no challenge of the required type found")
