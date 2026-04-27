package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", c.server+"/api/sign", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

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
// 调用方必须通过 req 的 context 设置超时，doWithRetry 不再自行添加超时，
// 避免 defer cancel() 在返回后关闭连接导致调用方读取 resp.Body 时 context canceled。
func (c *Client) doWithRetry(req *http.Request, bodyBuf *bytes.Reader) (*http.Response, error) {
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

// SignRawDigestRequest Raw 模式签名请求
type SignRawDigestRequest struct {
	Filename string `json:"filename"`
	Dig      string `json:"dig"` // base64 of Authenticode digest (32 bytes)
}

// SignRawDigest 发送 Raw 模式签名请求（使用 raw-sign 完成 Authenticode 签名）
func (c *Client) SignRawDigest(filename, digB64 string) (*SignResponse, error) {
	reqBody := SignRawDigestRequest{
		Filename: filename,
		Dig:      digB64,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", c.server+"/api/sign/raw", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doWithRetry(req, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("sign raw: %w", err)
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
		return nil, fmt.Errorf("sign raw failed (%d): %s", resp.StatusCode, msg)
	}

	var result SignResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode sign response: %w", err)
	}
	return &result, nil
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

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", c.server+"/api/raw-sign", bytes.NewReader(body))
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

// signFullMaxRetries 大文件上传最大重试次数
const signFullMaxRetries = 2

// ErrChecksumMismatch 表示服务端校验 SHA-256 不匹配 (409)
var ErrChecksumMismatch = fmt.Errorf("checksum mismatch: file corrupted during transfer")

// SignFull 上传完整文件进行全量签名（zstd 压缩 + SHA-256 完整性校验 + 重试）
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
	fileSize := stat.Size()

	// 1. 计算原始文件的 SHA-256
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return nil, fmt.Errorf("compute file hash: %w", err)
	}
	fileHash := hex.EncodeToString(hasher.Sum(nil))

	// 2. 压缩到临时文件（使上传可重试；seek 回起点重传即可）
	tmpFile, err := os.CreateTemp("", "codesign-upload-*.zst")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	// 回到文件开头进行压缩
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("seek file: %w", err)
	}

	enc, err := zstd.NewWriter(tmpFile)
	if err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("create zstd encoder: %w", err)
	}
	if _, err := io.Copy(enc, f); err != nil {
		enc.Close()
		tmpFile.Close()
		return nil, fmt.Errorf("compress file: %w", err)
	}
	if err := enc.Close(); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("finalize compression: %w", err)
	}
	tmpFile.Close()

	// 3. 打开压缩后的临时文件用于上传
	compressedFile, err := os.Open(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("open compressed file: %w", err)
	}
	defer compressedFile.Close()

	// 动态超时: 基础 60s + 每 10MB 增加 10s（基于原始文件大小）
	timeoutSecs := 60 + int(fileSize/(10*1024*1024))*10
	filename := filepath.Base(filePath)

	// 4. 带重试的上传
	var lastErr error
	for attempt := 0; attempt <= signFullMaxRetries; attempt++ {
		if attempt > 0 {
			fmt.Printf("        retry %d/%d...\n", attempt, signFullMaxRetries)
			time.Sleep(time.Duration(attempt) * time.Second) // 递增退避
			// seek 回压缩文件开头
			if _, err := compressedFile.Seek(0, io.SeekStart); err != nil {
				return nil, fmt.Errorf("seek compressed file: %w", err)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSecs)*time.Second)

		req, err := http.NewRequestWithContext(ctx, "POST", c.server+"/api/sign/full", compressedFile)
		if err != nil {
			cancel()
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Encoding", "zstd")
		req.Header.Set("X-Filename", filename)
		req.Header.Set("X-Content-SHA256", fileHash)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("sign full: %w", err)
			continue // 网络错误，重试
		}

		result, retryable, err := c.handleSignFullResponse(resp)
		resp.Body.Close()
		cancel()

		if err == nil {
			return result, nil
		}
		lastErr = err
		if !retryable {
			return nil, err // 不可重试的错误（认证失败等）直接返回
		}
	}

	return nil, fmt.Errorf("sign full failed after %d retries: %w", signFullMaxRetries, lastErr)
}

// handleSignFullResponse 解析 SignFull 响应，返回 (result, retryable, error)
func (c *Client) handleSignFullResponse(resp *http.Response) (*SignResponse, bool, error) {
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, false, ErrUnauthorized
	}
	// 409 Conflict = 完整性校验失败，可重试
	if resp.StatusCode == http.StatusConflict {
		return nil, true, ErrChecksumMismatch
	}
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]any
		json.NewDecoder(resp.Body).Decode(&errResp) //nolint:errcheck
		msg, _ := errResp["error"].(string)
		// 5xx 可重试，4xx（除 409）不可重试
		retryable := resp.StatusCode >= 500
		return nil, retryable, fmt.Errorf("sign full failed (%d): %s", resp.StatusCode, msg)
	}

	var result SignResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, false, fmt.Errorf("decode sign response: %w", err)
	}
	return &result, false, nil
}
