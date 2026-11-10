// Package proxy 提供基于 net/http/httputil.ReverseProxy 封装的
// HTTP 反向代理能力，供其他应用作为库调用。
//
// 典型用法：
//
//	target, err := proxy.ParseTarget("http://127.0.0.1:8080")
//	if err != nil {
//		// handle error
//	}
//	p := proxy.New(proxy.Config{
//		Targets: []*proxy.Target{target},
//	})
//	http.ListenAndServe(":80", p)
package proxy

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
)

// Config 描述一个反向代理实例的配置。
type Config struct {
	// Targets 是后端目标列表。可以为空，此时必须在请求期通过
	// Resolver 动态解析目标；否则代理将返回 502。
	Targets []*Target

	// Resolver 用于按请求动态决定后端目标，优先级高于 Targets。
	// 返回 nil 表示本次请求没有可用后端。
	Resolver func(*http.Request) *Target

	// PathRewrite 用于按请求改写转发到后端的路径。
	// 例如将 "/api/foo" 改写为 "/foo"。
	PathRewrite func(*http.Request) string

	// Transport 用于执行转发请求，nil 时使用 http.DefaultTransport。
	Transport http.RoundTripper

	// ErrorHandler 在后端不可达或无法建立转发时调用，
	// 用于返回自定义错误响应。默认返回 502 Bad Gateway。
	ErrorHandler func(http.ResponseWriter, *http.Request, error)

	// ModifyResponse 允许在上游返回后、写回客户端前修改响应。
	ModifyResponse func(*http.Response) error
}

// Proxy 是一个 HTTP Handler，实现反向代理转发。
type Proxy struct {
	config    Config
	transport http.RoundTripper
	next      uint64
}

// New 依据配置创建一个反向代理实例。
func New(cfg Config) *Proxy {
	transport := cfg.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &Proxy{
		config:    cfg,
		transport: transport,
	}
}

// ServeHTTP 实现 http.Handler。
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := p.selectTarget(r)
	if target == nil {
		p.respondError(w, r, ErrNoTarget)
		return
	}

	rp := &httputil.ReverseProxy{
		Transport:      p.transport,
		ModifyResponse: p.config.ModifyResponse,
		ErrorHandler:   p.wrapErrorHandler(),
		Rewrite:        p.rewrite(target, r),
		FlushInterval:  -1,
		ErrorLog:       nil, // 保持默认 logger 行为
	}
	rp.ServeHTTP(w, r)
}

// selectTarget 选择后端目标，Resolver 优先，其次在 Targets 中轮询。
func (p *Proxy) selectTarget(r *http.Request) *Target {
	if p.config.Resolver != nil {
		return p.config.Resolver(r)
	}
	n := len(p.config.Targets)
	if n == 0 {
		return nil
	}
	if n == 1 {
		return p.config.Targets[0]
	}
	i := atomic.AddUint64(&p.next, 1) - 1
	return p.config.Targets[i%uint64(n)]
}

// rewrite 构造 ReverseProxy 的 Rewrite 闭包，完成目标改写。
func (p *Proxy) rewrite(target *Target, inbound *http.Request) func(*httputil.ProxyRequest) {
	return func(pr *httputil.ProxyRequest) {
		pr.SetURL(target.URL)
		if target.Host != "" {
			pr.Out.Host = target.Host
		}
		pr.SetXForwarded()
		pr.Out.Header.Set("X-Forwarded-Host", inbound.Host)

		if p.config.PathRewrite != nil {
			if pth := p.config.PathRewrite(inbound); pth != "" {
				pr.Out.URL.Path = pth
			}
		}
	}
}

// wrapErrorHandler 返回错误处理器：优先使用用户提供的，
// 否则使用默认 502 响应。
func (p *Proxy) wrapErrorHandler() func(http.ResponseWriter, *http.Request, error) {
	if p.config.ErrorHandler != nil {
		return p.config.ErrorHandler
	}
	return func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
	}
}

// respondError 在无法选择后端时直接返回错误。
func (p *Proxy) respondError(w http.ResponseWriter, r *http.Request, err error) {
	if p.config.ErrorHandler != nil {
		p.config.ErrorHandler(w, r, err)
		return
	}
	http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
}

// Target 描述一个后端目标。
type Target struct {
	// URL 是后端基础地址，例如 "http://127.0.0.1:8080"。
	// 可包含基础路径，转发时请求路径会拼接到其后。
	URL *url.URL

	// Host 可选，覆盖转发请求的 Host 头。为空时保留原始 Host。
	Host string
}

// ParseTarget 解析并校验一个后端目标地址。
// 要求 scheme 为 http 或 https，且 host 非空。
func ParseTarget(raw string) (*Target, error) {
	if raw == "" {
		return nil, errors.New("proxy: empty target")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("proxy: target scheme must be http or https")
	}
	if u.Host == "" {
		return nil, errors.New("proxy: target host is empty")
	}
	return &Target{URL: u}, nil
}

// ParseTargets 批量解析后端目标地址。
func ParseTargets(raw ...string) ([]*Target, error) {
	targets := make([]*Target, 0, len(raw))
	for _, r := range raw {
		t, err := ParseTarget(r)
		if err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, nil
}

// RoundRobin 返回一个按轮询方式选择后端的 Resolver。
// 传入 nil 或空切片时，Resolver 恒返回 nil。
func RoundRobin(targets []*Target) func(*http.Request) *Target {
	var next uint64
	return func(*http.Request) *Target {
		n := len(targets)
		if n == 0 {
			return nil
		}
		i := atomic.AddUint64(&next, 1) - 1
		return targets[i%uint64(n)]
	}
}

// StripPrefix 返回一个 PathRewrite，用于剥离请求路径中的指定前缀。
// 例如 StripPrefix("/api") 会将 "/api/foo" 改写为 "/foo"。
func StripPrefix(prefix string) func(*http.Request) string {
	prefix = strings.TrimRight(prefix, "/")
	return func(r *http.Request) string {
		p := r.URL.Path
		if prefix != "" && strings.HasPrefix(p, prefix) {
			p = strings.TrimPrefix(p, prefix)
		}
		if p == "" {
			p = "/"
		}
		return p
	}
}

// ErrNoTarget 表示没有可用的后端目标。
var ErrNoTarget = errors.New("proxy: no target available")
