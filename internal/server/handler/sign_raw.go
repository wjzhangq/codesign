package handler

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"codesign/internal/certchain"
	"codesign/internal/server/config"
	"codesign/internal/server/middleware"
	"codesign/internal/server/signer"
)

// SignRawDigestRequest POST /api/sign/raw 请求体
type SignRawDigestRequest struct {
	Filename string `json:"filename"`
	Dig      string `json:"dig"` // base64 of Authenticode digest (32 bytes)
}

// SignRawDigestResponse POST /api/sign/raw 响应体
type SignRawDigestResponse struct {
	CertificateTable string `json:"certificate_table"` // base64
}

// SignRawDigestHandler 处理 Raw 模式签名请求
// 使用 raw-sign.exe 完成 Authenticode 签名，不依赖 signtool /ds
func SignRawDigestHandler(cfg *config.Config, s *signer.Signer) http.HandlerFunc {
	// 预加载证书 DER（与 CertHandler 相同策略）
	certDER, certErr := os.ReadFile(cfg.CertPath)
	if certErr != nil {
		return func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusInternalServerError, "failed to read certificate: "+certErr.Error())
		}
	}

	chainDERs := certchain.FetchChain(certDER, cfg.TempDir)

	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		user := middleware.UserFromContext(r.Context())

		// 检查 raw_sign_path 是否配置
		if cfg.RawSignPath == "" {
			writeJSON(w, http.StatusNotImplemented, map[string]any{
				"error": "raw sign mode not available: raw_sign_path not configured",
			})
			return
		}

		// 限制请求体大小 16 KB
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)

		var req SignRawDigestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			if isBodyTooLarge(err) {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		if req.Filename == "" {
			writeError(w, http.StatusBadRequest, "filename is required")
			return
		}
		if req.Dig == "" {
			writeError(w, http.StatusBadRequest, "dig is required")
			return
		}

		// 调用 RawDigestSign
		certTable, err := s.RawDigestSignFromBase64(r.Context(), req.Filename, req.Dig, certDER, chainDERs)
		if err != nil {
			if isTimeoutOrCanceled(err) || r.Context().Err() != nil {
				slog.Info("sign/raw timeout",
					"user", user, "file", req.Filename,
					"duration_ms", time.Since(start).Milliseconds())
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{
					"error": "signing queue timeout",
				})
				return
			}
			slog.Error("sign/raw failed",
				"user", user, "file", req.Filename,
				"error", err, "duration_ms", time.Since(start).Milliseconds())
			writeError(w, http.StatusInternalServerError, "signing failed: "+err.Error())
			return
		}

		slog.Info("sign/raw ok",
			"user", user, "file", req.Filename,
			"duration_ms", time.Since(start).Milliseconds())

		writeJSON(w, http.StatusOK, SignRawDigestResponse{
			CertificateTable: base64.StdEncoding.EncodeToString(certTable),
		})
	}
}
