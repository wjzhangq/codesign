# codesign

远程 PE 代码签名服务。客户端 CLI 在本地计算 Authenticode Digest，通过 HTTP API 发送给服务端，由服务端通过 signtool + eToken USB Key (SafeNet CSP) 完成签名，返回 Certificate Table，客户端将签名注入回本地文件。**全程不传输完整 PE 文件**（Digest 模式下网络传输约 9 KB）。

## 签名模式

| 模式 | 触发条件 | 上行 | 下行 |
|------|---------|------|------|
| **Digest 模式** (优先) | signtool `/ds` + CSP 验证通过 | ~4 KB (digest + unsigned PKCS#7) | ~5 KB (Certificate Table) |
| **全量 Fallback** | Digest 模式不可用或服务端返回 501 | 完整文件 (zstd 压缩) | ~5 KB (Certificate Table) |

两种模式均只回传 Certificate Table，客户端本地完成签名注入。

## 架构

```
客户端 (Go CLI, 跨平台)                    服务端 (Go, Windows + eToken)
──────────────────────                    ─────────────────────────────
PE 解析 → Authenticode Digest 计算
→ 构造 unsigned PKCS#7 (.p7u)
  POST /api/sign  { dig, p7u }  ────────► JWT 验证
  ~4 KB                                   signtool /ds + eToken CSP
                                          signtool /di (stub PE)
  { certificate_table }  ◄────────────    返回 Certificate Table
  ~5 KB
← 签名注入到本地 PE 文件
  (更新 Security Dir + CheckSum, 原子替换)
```

## 仓库结构

```
codesign/
├── cmd/
│   ├── codesign-server/main.go    # 服务端入口
│   └── codesign/main.go           # 客户端 CLI 入口
├── internal/
│   ├── pe/                        # [共享] PE 文件操作
│   │   ├── parser.go              # PE Header 解析
│   │   ├── digest.go              # Authenticode SHA-256 摘要
│   │   ├── checksum.go            # PE CheckSum 计算
│   │   ├── inject.go              # 签名注入
│   │   ├── extract.go             # 从已签名 PE 提取 cert table
│   │   ├── p7u.go                 # 构造 unsigned PKCS#7
│   │   ├── stub.go                # 构造最小 stub PE (供 signtool /di)
│   │   └── pe_test.go
│   ├── server/
│   │   ├── config/config.go       # INI 配置解析
│   │   ├── handler/               # HTTP handlers
│   │   ├── middleware/jwt.go      # JWT 验证中间件
│   │   ├── signer/                # signtool 封装 (digest + full)
│   │   ├── token/manager.go       # JWT 签发 / 撤销 / 持久化
│   │   └── preflight/check.go    # 启动前置检查
│   └── client/
│       ├── cli/                   # sign / config / info 命令
│       ├── api/client.go          # HTTP 客户端
│       └── config/config.go       # ~/.codesign/config.json
├── config.example.ini
└── go.mod
```

## 环境要求

### 服务端 (Windows)

| 项目 | 要求 |
|------|------|
| OS | Windows 10/11 或 Windows Server 2019+ |
| Go | 1.22+ |
| signtool | Windows SDK 10.0.22621.0+ |
| SafeNet 驱动 | SafeNet Authentication Client 10.x |
| eToken | 已插入 USB，已初始化，已导入代码签名证书 |
| 证书文件 | `.cer` 格式 DER 编码公钥证书 |

### 客户端

Go 1.22+，支持 Windows / macOS / Linux。

## 快速开始

### 构建

```bash
# 服务端 (在 Windows 上执行)
go build -o bin/codesign-server.exe ./cmd/codesign-server/

# 客户端 (各平台)
go build -o bin/codesign ./cmd/codesign/

# 交叉编译客户端
GOOS=windows GOARCH=amd64 go build -o bin/codesign.exe      ./cmd/codesign/
GOOS=darwin  GOARCH=arm64 go build -o bin/codesign-darwin   ./cmd/codesign/
GOOS=linux   GOARCH=amd64 go build -o bin/codesign-linux    ./cmd/codesign/
```

### 服务端部署

**1. 配置文件**

复制 `config.example.ini` 为 `config.ini`，按实际环境填写：

```ini
[server]
listen = :8443

[auth]
jwt_secret = <至少 32 字符的随机字符串>
token_db   = tokens.json

[sign]
signtool_path = C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe
cert_path     = C:\certs\code-signing.cer
csp_name      = eToken Base Cryptographic Provider
csp_key       = [<etoken-password>]=<container-name>
timestamp_url = http://timestamp.digicert.com
sign_timeout  = 120
temp_dir      = C:\codesign-tmp
digest_mode   = false    # 首次部署先设为 false，验证后再改为 true
```

> **安全提示**: `config.ini` 含 eToken 密码，文件权限应设为仅 owner 可读。

**2. 验证 Digest 模式可用性**

```powershell
codesign-server verify-ds
# ✅ Digest mode works! → 将 digest_mode = true 写入 config.ini
# ❌ Not supported     → 保持 digest_mode = false，使用全量模式
```

**3. 创建用户 Token**

```powershell
codesign-server token create --user zhangsan
# → eyJhbGciOiJIUzI1NiIs...

codesign-server token list
codesign-server token revoke --user zhangsan
```

**4. 启动服务**

```powershell
codesign-server serve
codesign-server serve --config D:\sign\config.ini   # 指定配置文件路径
```

### 客户端使用

**配置**

```bash
codesign config --server https://sign.corp.com:8443 --token eyJhbGciOiJIUzI1NiIs...
# 配置保存至 ~/.codesign/config.json
```

**签名**

```bash
# 自动选择模式 (Digest 优先，失败自动降级 Full)
codesign sign app.exe

# 批量签名
codesign sign app.exe helper.dll driver.sys

# 指定模式
codesign sign --mode digest app.exe
codesign sign --mode full   app.exe

# 覆盖服务器配置
codesign sign --server http://localhost:8443 --token xxx app.exe
```

签名过程输出示例：

```
app.exe (314.5 MB, PE32+/AMD64)

[1/4] Parsing PE...
      ChecksumOffset: 0x98  SecurityDirOffset: 0xE8  Overlay: 0x12BFA800
[2/4] Computing Authenticode digest...
      SHA-256: 7a3f...c9d1
[3/4] Remote signing (digest mode)...
[4/4] Injecting signature...

app.exe signed successfully
```

**查看 PE 信息**

```bash
codesign info app.exe
```

## API 参考

所有签名接口需携带 `Authorization: Bearer <token>` 头。

### GET /api/health

无需认证。返回服务状态。

```json
{
  "status": "ok",
  "mode": "digest",
  "cert_subject": "CN=My Company",
  "cert_expires": "2027-01-01"
}
```

### GET /api/cert

返回 DER 编码的公钥证书（`application/x-x509-ca-cert`），用于客户端构造 `.p7u`。

### POST /api/sign — Digest 模式

```
Content-Type: application/json
Body 限制: 64 KB
```

请求：

```json
{
  "filename": "app.exe",
  "dig": "<base64 of SHA-256 digest>",
  "p7u": "<base64 of unsigned PKCS#7>",
  "pe_info": {
    "checksum_offset":    264,
    "security_dir_offset": 360,
    "cert_table_offset":  0,
    "overlay_offset":     314572800,
    "is_pe32_plus":       true
  }
}
```

响应 200：

```json
{
  "certificate_table": "<base64 of WIN_CERTIFICATE>",
  "checksum": 0
}
```

响应 501（Digest 模式未启用）：

```json
{
  "error": "digest mode not supported, use /api/sign/full",
  "fallback": true
}
```

### POST /api/sign/full — 全量 Fallback 模式

```
Content-Type: application/octet-stream
Content-Encoding: zstd   (推荐，也可不压缩)
X-Filename: app.exe
Body 限制: 2 GB (压缩后)；解压后最大 400 MB
```

响应 200：

```json
{
  "certificate_table": "<base64>",
  "checksum":          1234567,
  "security_dir_va":   314572800,
  "security_dir_size": 4688
}
```

### 通用错误码

| 状态码 | 含义 |
|--------|------|
| 400 | 请求格式错误 / 缺少必填字段 |
| 401 | Token 无效或已撤销 |
| 413 | 请求体超过大小限制 |
| 500 | signtool 执行失败或内部错误 |
| 501 | Digest 模式不可用（客户端应自动降级） |
| 503 | 签名排队超时 |

## 测试

```bash
go test ./...
```

单元测试覆盖 PE 解析、Authenticode Digest 计算、CheckSum、签名注入/提取、JWT 创建/验证/撤销/持久化，无需 Windows 环境即可运行。

## 安全设计

- **JWT**：HMAC-SHA256 自实现，含 `jti` 随机字段；重新颁发 Token 时旧 Token 立即失效
- **eToken 串行化**：channel 信号量替代 `sync.Mutex`，等待期间响应 `context` 取消
- **文件名净化**：仅保留 `[a-zA-Z0-9._-]`，防止路径穿越与命令注入
- **解压炸弹防护**：解压后文件大小限制 400 MB（`io.LimitReader`）
- **签名原子替换**：写入临时文件后 `os.Rename`，避免半写状态
- **临时文件**：`defer os.RemoveAll(tmpDir)` 覆盖所有退出路径

## 依赖

| 模块 | 用途 |
|------|------|
| `gopkg.in/ini.v1` | 服务端 INI 配置解析 |
| `github.com/klauspost/compress/zstd` | Full 模式 zstd 压缩/解压 |
| `github.com/urfave/cli/v2` | 客户端 CLI 框架 |
| 标准库 | HTTP、crypto、PE 解析、日志 (slog) |
