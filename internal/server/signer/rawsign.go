package signer

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// RawSignResult raw-sign 签名结果
type RawSignResult struct {
	Signature string `json:"signature"` // base64 编码的 RSA 签名值 (big-endian)
	Algorithm string `json:"algorithm"`
}

// allowedAlgorithms 允许的签名算法及对应 digest hex 长度
var allowedAlgorithms = map[string]int{
	"sha256": 64, // SHA-256 = 32 bytes = 64 hex chars
	"sha1":   40, // SHA-1   = 20 bytes = 40 hex chars
}

// validateRawSignInput 校验 raw-sign 输入参数
func validateRawSignInput(digestHex, algo string) error {
	expectedLen, ok := allowedAlgorithms[algo]
	if !ok {
		return fmt.Errorf("unsupported algorithm %q, allowed: sha256, sha1", algo)
	}
	if len(digestHex) != expectedLen {
		return fmt.Errorf("invalid digest length for %s: expected %d hex chars, got %d",
			algo, expectedLen, len(digestHex))
	}
	if _, err := hex.DecodeString(digestHex); err != nil {
		return fmt.Errorf("invalid hex in digest: %w", err)
	}
	return nil
}

// RawSign 使用 raw-sign.exe 对 digest 执行 RSA 签名
func (s *Signer) RawSign(ctx context.Context, digestHex, algo string) (*RawSignResult, error) {
	if err := validateRawSignInput(digestHex, algo); err != nil {
		return nil, err
	}

	var result *RawSignResult
	err := s.withLock(ctx, func() error {
		var innerErr error
		result, innerErr = s.doRawSign(ctx, digestHex, algo)
		return innerErr
	})
	return result, err
}

func (s *Signer) doRawSign(ctx context.Context, digestHex, algo string) (*RawSignResult, error) {
	timeout := time.Duration(s.cfg.SignTimeout) * time.Second
	signCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{
		"--cspkey", s.cfg.CSPKey,
		"--digest", digestHex,
		"--algo", algo,
	}

	cmd := exec.CommandContext(signCtx, s.cfg.RawSignPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("raw-sign failed: %w\nstderr: %s", err, stderr.String())
	}

	sig := strings.TrimSpace(stdout.String())
	if sig == "" {
		return nil, fmt.Errorf("raw-sign returned empty signature")
	}

	return &RawSignResult{
		Signature: sig,
		Algorithm: algo,
	}, nil
}
