# originlang.go

使用 Go 实现和封装通用功能的类库。

## 项目结构

- `go.mod`：模块 `github.com/originlang/originlang.go`
- `go.work`：Go workspace，当前引用根模块
- `originlang.go`：`originlang` 根包

功能按领域组织为子包，项目不提供命令行入口。

## 开发

```sh
go test ./...
go vet ./...
```
