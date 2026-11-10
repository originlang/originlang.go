# originlang.go

使用 Go 实现和封装通用功能的类库。

## 项目结构

- `go.mod`：模块 `github.com/originlang/originlang.go`
- `go.work`：Go workspace，当前引用根模块
- `originlang.go`：`originlang` 根包
- `proxy/`：HTTP 反向代理子包
- `acmecert/`：ACME 自动 TLS 证书子包（Let's Encrypt）

功能按领域组织为子包，项目不提供命令行入口。

## proxy 反向代理

`proxy` 包基于标准库 `net/http/httputil.ReverseProxy` 封装，提供类 Nginx 的反向代理能力，供其他应用作为库调用：

- 单/多后端转发
- 轮询（RoundRobin）负载均衡
- 请求路径重写（StripPrefix 等）
- 转发请求头（X-Forwarded-*）与自定义 Host
- 自定义错误处理与响应修改

### 基本用法

```go
import "github.com/originlang/originlang.go/proxy"

// 单个后端
target, _ := proxy.ParseTarget("http://127.0.0.1:8080")
p := proxy.New(proxy.Config{
    Targets: []*proxy.Target{target},
})

// 多后端轮询
targets, _ := proxy.ParseTargets("http://127.0.0.1:8080", "http://127.0.0.1:8081")
p = proxy.New(proxy.Config{
    Resolver: proxy.RoundRobin(targets),
})

// 路径前缀剥离：/api/foo -> /foo
p = proxy.New(proxy.Config{
    Targets:     []*proxy.Target{target},
    PathRewrite: proxy.StripPrefix("/api"),
})

http.ListenAndServe(":80", p)
```

### 自定义错误处理与响应修改

```go
p := proxy.New(proxy.Config{
    Targets: []*proxy.Target{target},
    ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
        http.Error(w, "upstream unavailable", http.StatusBadGateway)
    },
    ModifyResponse: func(resp *http.Response) error {
        resp.Header.Set("X-Proxied-By", "originlang")
        return nil
    },
})
```

### 带自动 HTTPS 的反向代理网关

`proxy.Gateway` 组合了反向代理与 `acmecert` 自动证书，通过参数配置后调用 `Run` 一键启动：80 端口处理 http-01 挑战并重定向到 HTTPS，443 端口通过自动签发的证书提供 TLS 转发。

```go
g, err := proxy.NewGateway(proxy.GatewayConfig{
    Config: proxy.Config{
        Targets: []*proxy.Target{target},       // 上游目标（或 Resolver 负载均衡）
        // PathRewrite, ModifyResponse 等同 Config 字段均可用
    },
    Email:    "ops@example.com",                // ACME 联系邮箱（必填）
    CacheDir: "/var/lib/certs",                 // 证书缓存目录，持久化避免重复签发
    Hosts:    []string{"example.com", "www.example.com"}, // 允许签发的域名白名单
    HTTPAddr: ":80",                            // 可选，默认 :80
    HTTPSAddr: ":443",                          // 可选，默认 :443
})
if err != nil {
    // handle error
}
if err := g.Run(); err != nil {                 // 阻塞运行
    // handle error
}
```

网关可优雅关闭：

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
_ = g.Shutdown(ctx)
```

## acmecert 自动 SSL 证书

`acmecert` 包基于 ACME 协议（Let's Encrypt）自动申请与续期 TLS 证书，支持两种验证方式。

### 公网模式（HTTP-01 / TLS-ALPN-01）

适用于域名解析到本机、开放 80/443 端口的场景，基于 `autocert.Manager` 全自动签发与续期：

```go
import "github.com/originlang/originlang.go/acmecert"

m := acmecert.NewManager(acmecert.ManagerConfig{
    Email:    "ops@example.com",      // CA 通知邮箱
    CacheDir: "/var/lib/certs",       // 证书缓存目录，持久化避免重复签发
    Hosts:    []string{"example.com", "www.example.com"},
})

srv := &http.Server{
    Addr:      ":443",
    Handler:   handler,
    TLSConfig: m.TLSConfig(),          // 自动证书 + tls-alpn-01
}

// 80 端口跑 http-01 挑战
go http.ListenAndServe(":80", m.HTTPHandler(nil))

srv.ListenAndServeTLS("", "") // 证书由 TLSConfig 自动管理
```

### 内网模式（DNS-01，Cloudflare）

适用于无法开放端口、或域名不解析到本机的场景，通过 Cloudflare API 自动添加/删除 `_acme-challenge` TXT 记录：

```go
solver := acmecert.NewCloudflareSolver(
    "your-cloudflare-api-token", // 需 Zone.DNS Edit 权限
    "",                          // ZoneID 为空时按域名自动查询
)

issuer, err := acmecert.NewDNS01Issuer(acmecert.DNS01Config{
    Email:    "ops@example.com",
    Solver:   solver,
    CacheDir: "/var/lib/acme",   // 持久化账户密钥，复用同一 ACME 账户
})
if err != nil {
    // handle error
}

cert, err := issuer.Obtain(context.Background(), []string{"example.com", "www.example.com"})
if err != nil {
    // handle error
}

// cert.CertPEM / cert.KeyPEM 可直接用于 tls.X509KeyPair 或写入文件
tlsCert, err := tls.X509KeyPair(cert.CertPEM, cert.KeyPEM)
```

### 自定义 DNS 提供商

如需接入其他 DNS 提供商（阿里云、DNSPod 等），实现 `acmecert.DNS01Solver` 接口即可：

```go
type DNS01Solver interface {
    Present(ctx context.Context, domain, token, keyAuth string) error
    CleanUp(ctx context.Context, domain, token, keyAuth string) error
}
```

## 开发

```sh
go test ./...
go vet ./...
```
