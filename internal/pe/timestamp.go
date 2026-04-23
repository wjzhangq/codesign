package pe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

const tsaMaxRetries = 2

// tsRequest RFC 3161 TimeStampReq
type tsRequest struct {
	Version        int
	MessageImprint tsMessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          asn1.RawValue         `asn1:"optional"`
	CertReq        bool                  `asn1:"optional"`
}

type tsMessageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

// tsResponse RFC 3161 TimeStampResp
type tsResponse struct {
	Status         tsPKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type tsPKIStatusInfo struct {
	Status int
}

// RequestTimestamp 向 TSA 服务器请求 RFC 3161 时间戳
// signature: SignerInfo.EncryptedDigest (RSA 签名值)
// tsaURL: 时间戳服务器地址
// 返回 TimeStampToken 的完整 DER 编码
func RequestTimestamp(ctx context.Context, signature []byte, tsaURL string) ([]byte, error) {
	digest := sha256.Sum256(signature)

	req := tsRequest{
		Version: 1,
		MessageImprint: tsMessageImprint{
			HashAlgorithm: algorithmIdentifier{
				Algorithm:  oidSHA256,
				Parameters: asn1.RawValue{Tag: asn1.TagNull},
			},
			HashedMessage: digest[:],
		},
		CertReq: true,
	}

	reqDER, err := asn1.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal timestamp request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= tsaMaxRetries; attempt++ {
		if attempt > 0 {
			slog.Warn("timestamp retry", "attempt", attempt, "prev_error", lastErr)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		token, err := doTimestampRequest(ctx, reqDER, tsaURL)
		if err == nil {
			return token, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("timestamp failed after %d retries: %w", tsaMaxRetries, lastErr)
}

func doTimestampRequest(ctx context.Context, reqDER []byte, tsaURL string) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, "POST", tsaURL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("timestamp request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, fmt.Errorf("read timestamp response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("timestamp server returned HTTP %d", resp.StatusCode)
	}

	var tsResp tsResponse
	rest, err := asn1.Unmarshal(body, &tsResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal timestamp response: %w", err)
	}
	if len(rest) > 0 {
		slog.Warn("timestamp response has trailing data", "bytes", len(rest))
	}

	// status 0 = granted, 1 = grantedWithMods
	if tsResp.Status.Status > 1 {
		return nil, fmt.Errorf("timestamp server rejected request, status=%d", tsResp.Status.Status)
	}

	if len(tsResp.TimeStampToken.FullBytes) == 0 {
		return nil, fmt.Errorf("timestamp response contains no token")
	}

	return tsResp.TimeStampToken.FullBytes, nil
}
