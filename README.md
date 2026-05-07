# codesign

远程代码签名服务，支持 **PE 文件签名**（Authenticode）和 **XML 文档签名**（XMLDSIG）。

- **PE 签名**：客户端在本地计算 Authenticode Digest，通过 HTTP API 发送给服务端，由服务端通过 eToken USB Key (SafeNet CSP) 完成签名，返回 Certificate Table，客户端将签名注入回本地文件。支持三种模式：**Raw 模式**（仅需 raw-sign.exe，传输约 200 字节）、**Digest 模式**（需 signtool /ds，传输约 9 KB）、**Full 模式**（上传完整文件）。
- **XML 签名**：客户端在本地执行 XMLDSIG Enveloped 签名流程，仅将 SHA-256 Digest（64 字节 hex）发送给服务端，由服务端通过 [raw-sign.exe](https://github.com/wjzhangq/win-etoken-raw-sign) + eToken CSP 完成 RSA 签名，客户端将签名嵌入 XML 文档。**全程不传输私钥或原始文档**。

## 签名模式

### PE 签名

| 模式 | 触发条件 | 上行 | 下行 | 服务端依赖 |
|------|---------|------|------|-----------|
| **Raw 模式** (推荐) | `raw_sign_path` 已配置 | ~200 bytes (digest) | ~5 KB (Certificate Table) | raw-sign.exe |
| **Digest 模式** | signtool `/ds` + CSP 验证通过 | ~4 KB (digest + unsigned PKCS#7) | ~5 KB (Certificate Table) | signtool.exe |
| **全量 Fallback** | 以上模式不可用或服务端返回 501 | 完整文件 (zstd 压缩) | ~5 KB (Certificate Table) | signtool.exe |

三种模式均只回传 Certificate Table，客户端本地完成签名注入。

**Raw 模式** 与 Digest 模式的区别：Raw 模式完全不依赖 signtool，由服务端 Go 代码自行构造 PKCS#7 SignedData（通过 raw-sign.exe 获取 RSA 签名），无需 stub PE、无需 `/ds` + `/di`，请求体也更小（只传 32 字节 digest 的 base64）。

### XML 签名 (XMLDSIG)

| 步骤 | 执行方 | 内容 |
|------|--------|------|
| Inclusive C14N + SHA-256 (Reference Digest) | 客户端 | 计算 XML 内容摘要 |
| 构造 SignedInfo + C14N + SHA-256 | 客户端 | 计算待签名摘要 |
| RSA 签名 | 服务端 (raw-sign.exe + eToken) | 接收 64 字节 hex digest，返回 base64 签名 |
| 组装 `<Signature>` 嵌入文档 | 客户端 | 生成符合 W3C XMLDSIG 规范的签名 XML |
| 获取证书链 | 客户端 | 自动从 AIA 扩展下载中间 CA 证书（带缓存） |

网络传输：64 字节 hex digest（上行）+ base64 RSA 签名（下行），原始文档不离开客户端。

## 架构

### PE 签名 — Raw 模式 (推荐)

```
客户端 (Go CLI, 跨平台)                    服务端 (Go, Windows + eToken)
──────────────────────                    ─────────────────────────────
PE 解析 → Authenticode Digest 计算
  POST /api/sign/raw                ────► JWT 验证
  { filename, dig(base64) }               AuthAttrsDigest() → SHA-256
  ~200 bytes                              raw-sign.exe → RSA 签名
                                          BuildSignedPKCS7() → PKCS#7
                                          BuildWinCertificate()
  { certificate_table }  ◄────────────    返回 Certificate Table
  ~5 KB
← 签名注入到本地 PE 文件
  (更新 Security Dir + CheckSum, 原子替换)
```

### PE 签名 — Digest 模式

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

### XML 签名

```
客户端 (Go CLI, 跨平台)                    服务端 (Go, Windows + eToken)
──────────────────────                    ─────────────────────────────
解析 XML → Inclusive C14N → SHA-256
→ 构造 SignedInfo → C14N → SHA-256
  GET /api/cert-chain               ────► 返回证书链 (自动从 AIA 下载)
  POST /api/raw-sign                ────► JWT 验证
  { digest: "<64-char hex>",              raw-sign.exe --cspkey ... --digest ...
    algorithm: "sha256" }                 eToken CSP RSA 签名
  ~200 bytes                        ◄──── { signature: "<base64>" }
← 组装 <Signature> 嵌入 XML 文档
  (XMLDSIG Enveloped, Inclusive C14N, W3C 规范)
  含 KeyInfo (RSAKeyValue + X509Data) + Object (issuerCertificate)
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
│   ├── xmldsig/                   # XMLDSIG 签名模块 (客户端)
│   │   ├── sign.go                # SignXML 核心函数
│   │   ├── verify.go              # VerifyXML 验签函数
│   │   ├── c14n.go                # Inclusive/Exclusive C14N 封装
│   │   ├── elements.go            # XML 元素构造辅助函数
│   │   └── sign_test.go
│   ├── certchain/                 # 证书链自动获取模块
│   │   └── certchain.go           # AIA 递归下载 + PEM 缓存
│   ├── server/
│   │   ├── config/config.go       # INI 配置解析
│   │   ├── handler/               # HTTP handlers
│   │   │   ├── raw_sign.go        # POST /api/raw-sign
│   │   │   ├── sign_raw.go        # POST /api/sign/raw (Raw 模式 PE 签名)
│   │   │   ├── health.go          # GET /api/health
│   │   │   ├── sign_digest.go     # POST /api/sign
│   │   │   ├── sign_full.go       # POST /api/sign/full
│   │   │   ├── cert.go            # GET /api/cert
│   │   │   └── cert_chain.go      # GET /api/cert-chain
│   │   ├── middleware/jwt.go      # JWT 验证中间件
│   │   ├── signer/                # signtool + raw-sign 封装
│   │   │   ├── signer.go          # eToken 互斥锁
│   │   │   ├── rawsign.go         # RawSign 方法
│   │   │   ├── raw_digest.go      # RawDigestSign 方法 (Raw 模式 PE 签名)
│   │   │   ├── digest.go          # DigestSign 方法
│   │   │   └── full.go            # FullSign 方法
│   │   ├── token/manager.go       # JWT 签发 / 撤销 / 持久化
│   │   └── preflight/check.go    # 启动前置检查
│   └── client/
│       ├── cli/                   # sign / xmlsign / raw-sign / config / info 命令
│       ├── api/client.go          # HTTP 客户端
│       └── config/config.go       # ~/.codesign/config.json
├── testdata/
│   ├── sample.xml                 # 测试用 XML 文档
│   └── sample-with-ns.xml        # 带 namespace 的测试 XML
├── config.example.ini
└── go.mod
```

## 环境要求

### 服务端 (Windows)

| 项目 | 要求 |
|------|------|
| OS | Windows 10/11 或 Windows Server 2019+ |
| Go | 1.22+ |
| signtool | Windows SDK 10.0.22621.0+（PE 签名） |
| raw-sign.exe | [wjzhangq/win-etoken-raw-sign](https://github.com/wjzhangq/win-etoken-raw-sign)（Raw 模式 PE 签名 + XML 签名） |
| SafeNet 驱动 | SafeNet Authentication Client 10.x |
| eToken | 已插入 USB，已初始化，已导入代码签名证书 |
| 证书文件 | `.cer` 格式 DER 编码公钥证书 |

> **提示**: 如果只使用 Raw 模式签名 PE 文件 + XML 签名，可以不安装 signtool / Windows SDK，只需部署 `raw-sign.exe`。

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
# raw-sign.exe 路径（Raw 模式 PE 签名 + XML 签名时必填）
raw_sign_path = C:\raw-sign.exe
cert_path     = C:\certs\code-signing.cer
csp_name      = eToken Base Cryptographic Provider
csp_key       = [<etoken-password>]=<container-name>
timestamp_url = http://timestamp.digicert.com
sign_timeout  = 120
temp_dir      = C:\codesign-tmp
digest_mode   = false    # 首次部署先设为 false，验证后再改为 true
```

> **安全提示**: `config.ini` 含 eToken 密码，文件权限应设为仅 owner 可读。

**1.1 证书链（自动获取）**

证书链（中间 CA 证书）由服务端自动从签名证书的 AIA (Authority Information Access) 扩展中递归下载，无需手动配置。

- 自动排除根 CA（自签名证书不嵌入）
- 下载结果缓存为 PEM 文件，存放在 `temp_dir` 目录，7 天过期自动刷新
- PE Raw 模式签名和 XML 签名均使用此机制

如果网络环境无法访问 CA 的 AIA URL（如 `http://cacerts.digicert.com/...`），需确保服务端可访问外网或配置代理。

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
codesign sign --mode raw    app.exe   # Raw 模式 (推荐，仅需 raw-sign.exe)
codesign sign --mode digest app.exe   # Digest 模式 (需 signtool /ds)
codesign sign --mode full   app.exe   # 全量上传模式

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

**XML 文档签名**

```bash
# 签名单个文件（覆盖原文件）
codesign xmlsign document.xml

# 签名并输出到指定文件
codesign xmlsign document.xml -o signed.xml

# 批量签名到目录
codesign xmlsign *.xml -o signed/

# 覆盖服务器配置
codesign xmlsign --server http://localhost:8443 --token xxx document.xml
```

签名过程输出示例：

```
  document.xml
  [1/3] Computing document digest...
        input: 312 bytes
  [2/3] Remote signing...
        remote: 1.2s
  [3/3] Writing output...
        output: document.xml (1842 bytes)
  Done in 1.3s
```

**raw-sign 调试命令**（直接对任意 digest 签名，仅供调试）

```bash
codesign raw-sign --digest e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 --algo sha256
# Algorithm: sha256
# Signature: <base64>
```

**提取 PKCS#7 签名**（从已签名 PE 文件导出 .p7b）

```bash
# 提取签名
codesign extract app.exe                # → app.exe.p7b
codesign extract -o sig.p7b app.exe     # 指定输出文件名
codesign extract a.exe b.exe c.exe      # 批量提取

# 用 openssl 验证/查看提取的签名
openssl pkcs7 -in app.exe.p7b -inform DER -print_certs -noout   # 查看证书链
openssl asn1parse -in app.exe.p7b -inform DER                    # 查看 ASN.1 结构
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
  "cert_expires": "2027-01-01",
  "time": "2026-04-05T10:00:00Z",
  "capabilities": ["pe-sign", "pe-digest", "raw-sign", "xmldsig", "pe-raw"]
}
```

`capabilities` 字段说明：

| 值 | 含义 |
|----|------|
| `pe-sign` | 始终存在，支持 PE 全量签名 |
| `pe-digest` | `digest_mode = true` 时存在 |
| `pe-raw` | `raw_sign_path` 已配置时存在，支持 Raw 模式 PE 签名 |
| `raw-sign` | `raw_sign_path` 已配置时存在 |
| `xmldsig` | 同上（`raw-sign` 是 XMLDSIG 的前提）|
| `cert-chain` | 同上，支持自动获取证书链 |

### GET /api/cert

返回 DER 编码的公钥证书（`application/x-x509-ca-cert`），用于客户端构造 `.p7u`。

### GET /api/cert-chain

返回证书链（中间 CA 证书），自动从签名证书的 AIA 扩展递归下载并缓存。

响应 200：

```json
{
  "chain": ["<base64 DER of intermediate CA 1>", "<base64 DER of intermediate CA 2>"]
}
```

不包含根 CA（自签名证书）。如果无法获取证书链，返回空数组。

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

### POST /api/sign/raw — Raw 模式 PE 签名

使用 raw-sign.exe 完成 Authenticode 签名，不依赖 signtool。服务端自行构造 PKCS#7 SignedData。

```
Content-Type: application/json
Body 限制: 16 KB
```

请求：

```json
{
  "filename": "app.exe",
  "dig": "<base64 of SHA-256 Authenticode digest, 32 bytes>"
}
```

响应 200：

```json
{
  "certificate_table": "<base64 of WIN_CERTIFICATE>"
}
```

响应 501（`raw_sign_path` 未配置）：

```json
{
  "error": "raw sign mode not available: raw_sign_path not configured"
}
```

与 Digest 模式对比：Raw 模式只需传 digest（32 字节的 base64），不需要传 `.p7u` 和 `pe_info`，因为 PKCS#7 在服务端构造。

### POST /api/raw-sign — 原始摘要签名

供 XMLDSIG 流程使用。接受 hex 编码的摘要，返回 RSA 签名（base64）。

```
Content-Type: application/json
Body 限制: 4 KB
```

请求：

```json
{
  "digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "algorithm": "sha256"
}
```

字段说明：

| 字段 | 说明 |
|------|------|
| `digest` | 小写 hex 编码的摘要，sha256 为 64 字符，sha1 为 40 字符 |
| `algorithm` | `sha256` 或 `sha1` |

响应 200：

```json
{
  "signature": "<base64 of RSA PKCS#1 v1.5 signature>",
  "algorithm": "sha256"
}
```

> **注意**：该接口允许对任意内容签名，需妥善保管 JWT Token，避免滥用。需在配置文件中设置 `raw_sign_path` 才可用。底层签名工具：[wjzhangq/win-etoken-raw-sign](https://github.com/wjzhangq/win-etoken-raw-sign)。

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

单元测试覆盖：PE 解析、Authenticode Digest 计算、CheckSum、签名注入/提取、JWT 创建/验证/撤销/持久化、XMLDSIG 签名结构验证（含重签名、namespace 处理），无需 Windows 环境即可运行。

## 已知问题修复

### 大文件签名无效 (Certificate Table 8 字节对齐)

**现象**：对文件大小不是 8 字节倍数的 PE 文件签名后，Windows 报告签名无效。例如 76,918,043 字节的 EXE 文件（`76918043 % 8 = 3`）。

**根因**：`signtool` 签名时会先将文件填充（pad）到 8 字节边界再追加 WIN_CERTIFICATE，Authenticode 摘要中包含了这些填充零字节。但客户端 `InjectSignature` 直接将 Certificate Table 写入原始文件末尾（不对齐），导致验证时重新计算的摘要与签名内的摘要不匹配。

**修复**：
- `pe/inject.go`：注入签名前将文件填充到 8 字节对齐边界
- `pe/digest.go`：Authenticode 摘要计算时将哈希区域扩展到 8 字节对齐边界（填充零字节参与哈希），保证 digest/raw 模式下客户端计算的摘要与 signtool 一致

此修复影响所有三种签名模式（Raw / Digest / Full），对文件大小已是 8 字节倍数的文件无影响。

### Raw 模式签名后 Windows 提示"主题中没有签名"

**现象**：使用 Raw 模式（`--mode raw`）签名后，Windows 属性中可以看到时间戳，但提示"主题中没有签名"。`Get-AuthenticodeSignature` 返回 `Status: NotSigned`。

**根因**（多个问题叠加）：

1. **SpcPeImageData 编码不一致**：`BIT_STRING` 多了一个零字节（`03 02 00 00` → 应为 `03 01 00`），`SpcString` 多了两个零字节（`80 02 00 00` → 应为 `80 00`），与 signtool 生成的编码不一致。
2. **缺少证书链**：PKCS#7 中只包含签名证书，缺少中间 CA 证书，Windows 无法构建完整的证书信任链。
3. **digestEncryptionAlgorithm 错误**：使用了 `sha256WithRSAEncryption` (1.2.840.113549.1.1.11)，signtool 使用 `rsaEncryption` (1.2.840.113549.1.1.1)。
4. **多余的 signingTime 属性**：authenticatedAttributes 中包含了 `signingTime`，signtool 不在主签名中包含此属性（仅在时间戳反签名中），导致 authAttrs 哈希不一致。
5. **缺少 SPC_STATEMENT_TYPE 属性**：signtool 在 authenticatedAttributes 中包含 `SpcStatementType` (OID 1.3.6.1.4.1.311.2.1.11 = Microsoft Individual Code Signing)。
6. **dwLength 未对齐**：WIN_CERTIFICATE 的 `dwLength` 应为 8 字节对齐后的大小。

**修复**：
- `pe/p7u.go`：修正 `BitString` 编码（`Bytes: nil`）和 `spcLinkFileContent`（`{0xa2, 0x02, 0x80, 0x00}`），与 signtool 输出一致
- `pe/p7u.go`：`BuildSignedPKCS7` 新增 `chainDERs` 参数，支持在 PKCS#7 中嵌入多个证书
- `pe/p7u.go`：`digestEncryptionAlgorithm` 改为 `rsaEncryption`，与 signtool 一致
- `pe/p7u.go`：移除 `signingTime` 属性，新增 `SpcStatementType` 属性
- `pe/p7u.go`：`BuildWinCertificate` 的 `dwLength` 改为 8 字节对齐后的大小
- `internal/certchain`：自动从签名证书 AIA 扩展递归下载中间 CA 证书，带 PEM 缓存（7 天 TTL）
- `server/handler/sign_raw.go`：调用 `certchain.FetchChain` 自动获取证书链并传递给签名流程

## 安全设计

- **JWT**：HMAC-SHA256 自实现，含 `jti` 随机字段；重新颁发 Token 时旧 Token 立即失效
- **eToken 串行化**：channel 信号量替代 `sync.Mutex`，等待期间响应 `context` 取消；PE 签名与 XML 签名共享同一把锁，防止 eToken 冲突
- **文件名净化**：仅保留 `[a-zA-Z0-9._-]`，防止路径穿越与命令注入
- **解压炸弹防护**：解压后文件大小限制 400 MB（`io.LimitReader`）
- **签名原子替换**：写入临时文件后 `os.Rename`，避免半写状态
- **临时文件**：`defer os.RemoveAll(tmpDir)` 覆盖所有退出路径
- **raw-sign 输入校验**：algorithm 白名单（sha256/sha1）+ digest 长度 + hex 格式三重校验，服务端拒绝无效输入

## 依赖

| 模块 | 用途 |
|------|------|
| `gopkg.in/ini.v1` | 服务端 INI 配置解析 |
| `github.com/klauspost/compress/zstd` | Full 模式 zstd 压缩/解压 |
| `github.com/urfave/cli/v2` | 客户端 CLI 框架 |
| `github.com/beevik/etree` | XML 树解析/构造（XMLDSIG 客户端） |
| `github.com/russellhaering/goxmldsig` | Inclusive/Exclusive C14N 序列化（XMLDSIG） |
| 标准库 | HTTP、crypto、PE 解析、日志 (slog) |

外部工具依赖：

| 工具 | 用途 | 仓库 |
|------|------|------|
| `signtool.exe` | PE Authenticode 签名 (Digest / Full 模式) | Windows SDK |
| `raw-sign.exe` | eToken RSA 原始签名（Raw 模式 PE 签名 + XMLDSIG）| [wjzhangq/win-etoken-raw-sign](https://github.com/wjzhangq/win-etoken-raw-sign) |
