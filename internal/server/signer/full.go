package signer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"codesign/internal/pe"
)

// maxDecompressedSize 限制解压后文件大小（防 zip bomb）：400 MB
const maxDecompressedSize = 400 * 1024 * 1024

// ErrChecksumMismatch 表示文件 SHA-256 校验失败（传输损坏）
var ErrChecksumMismatch = fmt.Errorf("checksum mismatch")

// FullSignResult 全量签名结果
type FullSignResult struct {
	CertificateTable []byte
	Checksum         uint32
	SecurityDirVA    uint32
	SecurityDirSize  uint32
}

// FullSign 对完整 PE 文件进行全量签名
// fileData: 文件内容（可能已被 zstd 解压）
// filename: 原始文件名（用于 sanitize 后命名临时文件）
// expectedHash: 客户端提供的原始文件 SHA-256 hex（空字符串表示跳过校验，兼容旧客户端）
func (s *Signer) FullSign(ctx context.Context, fileData io.Reader, filename string, expectedHash string) (*FullSignResult, error) {
	var result *FullSignResult
	err := s.withLock(ctx, func() error {
		var innerErr error
		result, innerErr = s.doFullSign(ctx, fileData, filename, expectedHash)
		return innerErr
	})
	return result, err
}

func (s *Signer) doFullSign(ctx context.Context, fileData io.Reader, filename string, expectedHash string) (*FullSignResult, error) {
	// 创建临时目录
	tmpDir, err := os.MkdirTemp(s.cfg.TempDir, "codesign-full-")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir) // 确保清理

	safeName := sanitize(filename)
	tmpFile := filepath.Join(tmpDir, safeName)

	// 将文件写入临时目录，同时计算 SHA-256（限制解压后大小，防 zip bomb）
	f, err := os.Create(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	limited := io.LimitReader(fileData, maxDecompressedSize+1)

	// 使用 TeeReader 在写入的同时计算 hash
	hasher := sha256.New()
	tee := io.TeeReader(limited, hasher)

	n, err := io.Copy(f, tee)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("write temp file: %w", err)
	}
	if n > maxDecompressedSize {
		return nil, fmt.Errorf("decompressed file exceeds maximum allowed size (%d MB)", maxDecompressedSize/(1024*1024))
	}

	// SHA-256 完整性校验（仅当客户端提供了 hash 时）
	if expectedHash != "" {
		actualHash := hex.EncodeToString(hasher.Sum(nil))
		if actualHash != expectedHash {
			return nil, fmt.Errorf("%w: expected %s, got %s", ErrChecksumMismatch, expectedHash, actualHash)
		}
	}

	// 构造 signtool sign 命令
	timeout := time.Duration(s.cfg.SignTimeout) * time.Second
	signCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{
		"sign",
		"/v",
		"/fd", "SHA256",
		"/td", "SHA256",
		"/f", s.cfg.CertPath,
		"/csp", s.cfg.CSPName,
		"/k", s.cfg.CSPKey,
		"/tr", s.cfg.TimestampURL,
		tmpFile,
	}

	cmd := exec.CommandContext(signCtx, s.cfg.SigntoolPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("signtool sign failed: %w\noutput:\n%s", err, string(output))
	}

	// 从签名后文件提取 Certificate Table + CheckSum
	certTable, checksum, secDirVA, secDirSize, err := pe.ExtractSignatureData(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("extract signature data: %w", err)
	}

	return &FullSignResult{
		CertificateTable: certTable,
		Checksum:         checksum,
		SecurityDirVA:    secDirVA,
		SecurityDirSize:  secDirSize,
	}, nil
}
