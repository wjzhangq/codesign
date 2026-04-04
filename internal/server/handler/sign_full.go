package handler

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"codesign/internal/server/middleware"
	"codesign/internal/server/signer"
)

const maxUploadSize = 2 * 1024 * 1024 * 1024 // 2 GB

// SignFullResponse POST /api/sign/full 响应体
type SignFullResponse struct {
	CertificateTable string `json:"certificate_table"`
	Checksum         uint32 `json:"checksum"`
	SecurityDirVA    uint32 `json:"security_dir_va"`
	SecurityDirSize  uint32 `json:"security_dir_size"`
}

// SignFullHandler 处理全量签名（Fallback 模式）
func SignFullHandler(s *signer.Signer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		user := middleware.UserFromContext(r.Context())

		// 获取文件名
		filename := r.Header.Get("X-Filename")
		if filename == "" {
			writeError(w, http.StatusBadRequest, "X-Filename header is required")
			return
		}

		// 限制上传大小 2 GB
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

		// 处理 zstd 解压
		var bodyReader io.Reader
		var err error
		bodyReader, err = getBodyReader(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to prepare body reader: "+err.Error())
			return
		}
		// 如果是 zstd decoder，需要在结束时关闭
		if closer, ok := bodyReader.(io.Closer); ok {
			defer closer.Close()
		}

		// 执行全量签名
		result, err := s.FullSign(r.Context(), bodyReader, filename)
		if err != nil {
			// 签名超时或客户端断开连接 → 503 Service Unavailable
			if isTimeoutOrCanceled(err) || r.Context().Err() != nil {
				slog.Info("sign/full timeout",
					"user", user, "file", filename,
					"duration_ms", time.Since(start).Milliseconds())
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{
					"error": "signing queue timeout",
				})
				return
			}
			// 请求体超过大小限制 → 413
			if isBodyTooLarge(err) {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			slog.Error("sign/full failed",
				"user", user, "file", filename,
				"error", err, "duration_ms", time.Since(start).Milliseconds())
			writeError(w, http.StatusInternalServerError, "signing failed: "+err.Error())
			return
		}

		// Gap-2: 审计日志
		slog.Info("sign/full ok",
			"user", user, "file", filename,
			"duration_ms", time.Since(start).Milliseconds())

		writeJSON(w, http.StatusOK, SignFullResponse{
			CertificateTable: base64.StdEncoding.EncodeToString(result.CertificateTable),
			Checksum:         result.Checksum,
			SecurityDirVA:    result.SecurityDirVA,
			SecurityDirSize:  result.SecurityDirSize,
		})
	}
}

// getBodyReader 根据 Content-Encoding 决定是否解压
func getBodyReader(r *http.Request) (io.Reader, error) {
	if r.Header.Get("Content-Encoding") == "zstd" {
		return newZstdReader(r.Body)
	}
	return r.Body, nil
}

// isTimeoutOrCanceled 检查错误是否包含 context 超时或取消
func isTimeoutOrCanceled(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// isBodyTooLarge 检查是否为请求体过大错误（来自 MaxBytesReader）
func isBodyTooLarge(err error) bool {
	return strings.Contains(err.Error(), "http: request body too large")
}
