package signer

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"codesign/internal/pe"
)

// RawDigestSignRequest Raw 模式签名请求
type RawDigestSignRequest struct {
	Filename  string
	DigBytes  []byte   // Authenticode digest (32 bytes SHA-256)
	CertDER   []byte   // 签名证书 DER 编码
	ChainDERs [][]byte // 证书链 DER 编码列表（中间 CA 等）
}

// RawDigestSign 使用 raw-sign.exe 完成 Authenticode 签名，不依赖 signtool
//
// 流程:
//  1. 从 Authenticode digest 和证书构造 authenticatedAttributes
//  2. 计算 authAttrs 的 SHA-256 摘要
//  3. 调用 raw-sign.exe 对该摘要执行 RSA-PKCS1v15-SHA256 签名
//  4. 用签名值构造完整的 PKCS#7 SignedData
//  5. 包装为 WIN_CERTIFICATE 返回
func (s *Signer) RawDigestSign(ctx context.Context, req *RawDigestSignRequest) ([]byte, error) {
	var certTable []byte
	err := s.withLock(ctx, func() error {
		var innerErr error
		certTable, innerErr = s.doRawDigestSign(ctx, req)
		return innerErr
	})
	return certTable, err
}

// RawDigestSignFromBase64 从 base64 编码的 digest 进行签名
func (s *Signer) RawDigestSignFromBase64(ctx context.Context, filename, digB64 string, certDER []byte, chainDERs [][]byte) ([]byte, error) {
	digBytes, err := base64.StdEncoding.DecodeString(digB64)
	if err != nil {
		return nil, fmt.Errorf("decode dig base64: %w", err)
	}
	if len(digBytes) != 32 {
		return nil, fmt.Errorf("invalid digest length: expected 32 bytes, got %d", len(digBytes))
	}
	return s.RawDigestSign(ctx, &RawDigestSignRequest{
		Filename:  filename,
		DigBytes:  digBytes,
		CertDER:   certDER,
		ChainDERs: chainDERs,
	})
}

func (s *Signer) doRawDigestSign(ctx context.Context, req *RawDigestSignRequest) ([]byte, error) {
	signingTime := time.Now().UTC()

	// Step 1: 计算 authenticatedAttributes 的 SHA-256 摘要（含 signingTime）
	authAttrsDigestHex, err := pe.AuthAttrsDigest(req.DigBytes, req.CertDER, signingTime)
	if err != nil {
		return nil, fmt.Errorf("compute authAttrs digest: %w", err)
	}

	// Step 2: 调用 raw-sign.exe 对 authAttrs digest 执行 RSA 签名
	rawResult, err := s.doRawSign(ctx, authAttrsDigestHex, "sha256")
	if err != nil {
		return nil, fmt.Errorf("raw-sign authAttrs: %w", err)
	}

	// Step 3: 解码 RSA 签名值 (base64 → bytes)
	rsaSignature, err := base64.StdEncoding.DecodeString(rawResult.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode RSA signature: %w", err)
	}

	// Step 4: 请求 RFC 3161 时间戳
	var tsToken []byte
	if s.cfg.TimestampURL != "" {
		tsToken, err = pe.RequestTimestamp(ctx, rsaSignature, s.cfg.TimestampURL)
		if err != nil {
			return nil, fmt.Errorf("timestamp: %w", err)
		}
	}

	// Step 5: 构造完整的已签名 PKCS#7（含 signingTime 和时间戳）
	pkcs7DER, err := pe.BuildSignedPKCS7(req.DigBytes, req.CertDER, req.ChainDERs, rsaSignature, signingTime, tsToken)
	if err != nil {
		return nil, fmt.Errorf("build signed PKCS7: %w", err)
	}

	// Step 6: 包装为 WIN_CERTIFICATE
	certTable := pe.BuildWinCertificate(pkcs7DER)

	return certTable, nil
}

// loadCertDER 从配置的证书路径加载 DER 编码的证书
func (s *Signer) loadCertDER() ([]byte, error) {
	return os.ReadFile(s.cfg.CertPath)
}
