package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"codesign/internal/server/middleware"
	"codesign/internal/server/signer"
)

// RawSignRequest POST /api/raw-sign 请求体
type RawSignRequest struct {
	Digest    string `json:"digest"`
	Algorithm string `json:"algorithm"`
}

// RawSignResponse POST /api/raw-sign 响应体
type RawSignResponse struct {
	Signature string `json:"signature"`
	Algorithm string `json:"algorithm"`
}

// RawSignHandler 处理 raw-sign 请求
func RawSignHandler(s *signer.Signer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		user := middleware.UserFromContext(r.Context())

		// 限制请求体 4KB
		r.Body = http.MaxBytesReader(w, r.Body, 4*1024)

		var req RawSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			if isBodyTooLarge(err) {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		if req.Digest == "" {
			writeError(w, http.StatusBadRequest, "digest is required")
			return
		}
		if req.Algorithm == "" {
			writeError(w, http.StatusBadRequest, "algorithm is required")
			return
		}

		result, err := s.RawSign(r.Context(), req.Digest, req.Algorithm)
		if err != nil {
			if isTimeoutOrCanceled(err) || r.Context().Err() != nil {
				slog.Info("raw-sign timeout",
					"user", user, "algo", req.Algorithm,
					"duration_ms", time.Since(start).Milliseconds())
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{
					"error": "signing queue timeout",
				})
				return
			}
			slog.Error("raw-sign failed",
				"user", user, "algo", req.Algorithm,
				"error", err, "duration_ms", time.Since(start).Milliseconds())
			writeError(w, http.StatusInternalServerError, "raw-sign failed: "+err.Error())
			return
		}

		slog.Info("raw-sign ok",
			"user", user, "algo", req.Algorithm,
			"duration_ms", time.Since(start).Milliseconds())

		writeJSON(w, http.StatusOK, RawSignResponse{
			Signature: result.Signature,
			Algorithm: result.Algorithm,
		})
	}
}
