package signer

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"codesign/internal/pe"
)

// DigestSignRequest Digest 模式签名请求
type DigestSignRequest struct {
	Filename string
	DigBytes []byte // .dig 文件内容（原始 digest bytes）
	P7UBytes []byte // .p7u 文件内容（unsigned PKCS#7 DER）
	PEInfo   *pe.PEInfo
}

// DigestSign 使用 signtool /ds 对 digest 进行签名，返回 Certificate Table
// 使用 /dg → /ds → /di 三步法（通过 stub PE）
func (s *Signer) DigestSign(ctx context.Context, req *DigestSignRequest) ([]byte, error) {
	var certTable []byte
	err := s.withLock(ctx, func() error {
		var innerErr error
		certTable, innerErr = s.doDigestSign(ctx, req)
		return innerErr
	})
	return certTable, err
}

// DigestSignFromBase64 从 base64 编码的 dig/p7u 进行签名
func (s *Signer) DigestSignFromBase64(ctx context.Context, filename, digB64, p7uB64 string, peInfo *pe.PEInfo) ([]byte, error) {
	digBytes, err := base64.StdEncoding.DecodeString(digB64)
	if err != nil {
		return nil, fmt.Errorf("decode dig base64: %w", err)
	}
	p7uBytes, err := base64.StdEncoding.DecodeString(p7uB64)
	if err != nil {
		return nil, fmt.Errorf("decode p7u base64: %w", err)
	}
	return s.DigestSign(ctx, &DigestSignRequest{
		Filename: filename,
		DigBytes: digBytes,
		P7UBytes: p7uBytes,
		PEInfo:   peInfo,
	})
}

func (s *Signer) doDigestSign(ctx context.Context, req *DigestSignRequest) ([]byte, error) {
	tmpDir, err := os.MkdirTemp(s.cfg.TempDir, "codesign-ds-")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	baseName := sanitize(req.Filename)

	// Step 1: 写入 .dig 和 .p7u
	digPath := filepath.Join(tmpDir, baseName+".dig")
	p7uPath := filepath.Join(tmpDir, baseName+".p7u")

	if err := os.WriteFile(digPath, req.DigBytes, 0600); err != nil {
		return nil, fmt.Errorf("write .dig: %w", err)
	}
	if err := os.WriteFile(p7uPath, req.P7UBytes, 0600); err != nil {
		return nil, fmt.Errorf("write .p7u: %w", err)
	}

	// Step 2: 构造最小 stub PE
	stubPath := filepath.Join(tmpDir, baseName)
	if err := pe.WriteMinimalStubPE(stubPath, req.PEInfo); err != nil {
		return nil, fmt.Errorf("write stub PE: %w", err)
	}

	timeout := time.Duration(s.cfg.SignTimeout) * time.Second

	// Step 3: signtool /ds (签名 digest)
	dsCtx, dsCancel := context.WithTimeout(ctx, timeout)
	defer dsCancel()

	dsArgs := []string{
		"sign", "/ds",
		"/f", s.cfg.CertPath,
		"/csp", s.cfg.CSPName,
		"/k", s.cfg.CSPKey,
		"/fd", "sha256",
		digPath,
	}
	dsCmd := exec.CommandContext(dsCtx, s.cfg.SigntoolPath, dsArgs...)
	dsOutput, err := dsCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("signtool /ds failed: %w\noutput:\n%s", err, string(dsOutput))
	}

	// Step 4: signtool /di (将签名注入 stub PE)
	diCtx, diCancel := context.WithTimeout(ctx, timeout)
	defer diCancel()

	diArgs := []string{
		"sign", "/di", tmpDir,
		stubPath,
	}
	diCmd := exec.CommandContext(diCtx, s.cfg.SigntoolPath, diArgs...)
	diOutput, err := diCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("signtool /di failed: %w\noutput:\n%s", err, string(diOutput))
	}

	// Step 5: 从签名后 stub PE 提取 Certificate Table
	certTable, _, _, _, err := pe.ExtractSignatureData(stubPath)
	if err != nil {
		return nil, fmt.Errorf("extract from stub PE: %w", err)
	}

	return certTable, nil
}
