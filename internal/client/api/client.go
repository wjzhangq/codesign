package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"codesign/internal/pe"
	"codesign/internal/server/handler"

	"github.com/klauspost/compress/zstd"
)

// ErrFallbackRequired 表示服务端要求使用 Fallback 模式 (501)
var ErrFallbackRequired = fmt.Errorf("digest mode not available, fallback required")

// ErrUnauthorized 表示认证失败 (401)
var ErrUnauthorized = fmt.Errorf("unauthorized: invalid or revoked token")

// Client HTTP 客户端
type Client struct {
	server     string
	token      string
	httpClient *http.Client
}

// New 创建 API 客户端
func New(server, token string) *Client {
	return &Client{
		server: server,
		token:  token,
		httpClient: &http.Client{
			// 不设全局 Timeout，由各请求通过 context 单独控制超时。
			// 全局 Timeout 会导致大文件上传（SignFull）被提前截断。
		},
	}
}

// HealthResponse /api/health 响应
type HealthResponse struct {
	Status      string `json:"status"`
	Mode        string `json:"mode"`
	CertSubject string `json:"cert_subject"`
	CertExpires string `json:"cert_expires"`
}

// defaultTimeout 轻量请求的默认超时
const defaultTimeout = 30 * time.Second

// Health 检查服务端健康状态
func (c *Client) Health() (*HealthResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", c.server+"/api/health", nil)
	if err != nil {
		return nil, fmt.Errorf("health check: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("health check: %w", err)
	}
	defer resp.Body.Close()

	var result HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode health response: %w", err)
	}
	return &result, nil
}

// GetPublicCert 获取服务端公钥证书 (DER 格式)
func (c *Client) GetPublicCert() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", c.server+"/api/cert", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get cert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get cert: server returned %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// SignDigestRequest Digest 签名请求
type SignDigestRequest struct {
	Filename string              `json:"filename"`
	Dig      string              `json:"dig"`
	P7U      string              `json:"p7u"`
	PEInfo   handler.PEInfoJSON  `json:"pe_info"`
}

// SignResponse 签名响应（两种模式共用）
type SignResponse struct {
	CertificateTable string `json:"certificate_table"`
	Checksum         uint32 `json:"checksum"`
	SecurityDirVA    uint32 `json:"security_dir_va"`
	SecurityDirSize  uint32 `json:"security_dir_size"`
}

// SignDigest 发送 Digest 签名请求
func (c *Client) SignDigest(filename, digB64, p7uB64 string, info *pe.PEInfo) (*SignResponse, error) {
	reqBody := SignDigestRequest{
		Filename: filename,
		Dig:      digB64,
		P7U:      p7uB64,
		PEInfo: handler.PEInfoJSON{
			ChecksumOffset:    info.ChecksumOffset,
			SecurityDirOffset: info.SecurityDirOffset,
			CertTableOffset:   info.CertTableOffset,
			OverlayOffset:     info.OverlayOffset,
			IsPE32Plus:        info.IsPE32Plus,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.server+"/api/sign", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	// SignDigest 请求体为内存 buffer，可安全重试
	// 超时由 doWithRetry 内部 defaultTimeout 控制
	resp, err := c.doWithRetry(req, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("sign digest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode == http.StatusNotImplemented {
		return nil, ErrFallbackRequired
	}
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]any
		json.NewDecoder(resp.Body).Decode(&errResp) //nolint:errcheck
		msg, _ := errResp["error"].(string)
		return nil, fmt.Errorf("sign digest failed (%d): %s", resp.StatusCode, msg)
	}

	var result SignResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode sign response: %w", err)
	}
	return &result, nil
}

// doWithRetry 执行 HTTP 请求，在网络级错误时最多重试 1 次（Gap-4）
// bodyBuf 是可重放的请求体（bytes.Reader 支持 Seek）
// 如果请求没有关联 context 超时，会自动加上 defaultTimeout
func (c *Client) doWithRetry(req *http.Request, bodyBuf *bytes.Reader) (*http.Response, error) {
	// 如果请求没有设置 deadline，自动加上默认超时
	if _, ok := req.Context().Deadline(); !ok {
		ctx, cancel := context.WithTimeout(req.Context(), defaultTimeout)
		defer cancel()
		req = req.WithContext(ctx)
	}

	resp, err := c.httpClient.Do(req)
	if err == nil {
		return resp, nil
	}
	// ctx 已取消/超时则不重试
	if req.Context().Err() != nil {
		return nil, err
	}
	// 重置请求体并等待短暂时间后重试
	bodyBuf.Seek(0, io.SeekStart) //nolint:errcheck
	req.Body = io.NopCloser(bodyBuf)
	time.Sleep(500 * time.Millisecond)
	return c.httpClient.Do(req)
}

// RawSignResponse raw-sign 响应
type RawSignResponse struct {
	Signature string `json:"signature"`
	Algorithm string `json:"algorithm"`
}

// RawSign 发送 raw-sign 请求
func (c *Client) RawSign(digestHex, algo string) (*RawSignResponse, error) {
	reqBody := map[string]string{
		"digest":    digestHex,
		"algorithm": algo,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.server+"/api/raw-sign", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doWithRetry(req, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("raw-sign: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]any
		json.NewDecoder(resp.Body).Decode(&errResp) //nolint:errcheck
		msg, _ := errResp["error"].(string)
		return nil, fmt.Errorf("raw-sign failed (%d): %s", resp.StatusCode, msg)
	}

	var result RawSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode raw-sign response: %w", err)
	}
	return &result, nil
}

// SignFull 上传完整文件进行全量签名（zstd 压缩）
func (c *Client) SignFull(filePath string) (*SignResponse, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	// 使用 pipe 进行 zstd 流式压缩
	pr, pw := io.Pipe()
	go func() {
		enc, err := zstd.NewWriter(pw)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(enc, f); err != nil {
			enc.Close()
			pw.CloseWithError(err)
			return
		}
		enc.Close()
		pw.Close()
	}()

	// 动态超时: 基础 60s + 每 10MB 增加 10s
	// 使用 context 而非修改 httpClient.Timeout，以保证并发安全
	timeoutSecs := 60 + int(stat.Size()/(10*1024*1024))*10
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	// 使用 filepath.Base 提取文件名，兼容所有平台路径分隔符
	filename := filepath.Base(filePath)

	req, err := http.NewRequestWithContext(ctx, "POST", c.server+"/api/sign/full", pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "zstd")
	req.Header.Set("X-Filename", filename)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sign full: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]any
		json.NewDecoder(resp.Body).Decode(&errResp) //nolint:errcheck
		msg, _ := errResp["error"].(string)
		return nil, fmt.Errorf("sign full failed (%d): %s", resp.StatusCode, msg)
	}

	var result SignResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode sign response: %w", err)
	}
	return &result, nil
}
