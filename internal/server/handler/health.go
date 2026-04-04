package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"codesign/internal/server/config"
)

// HealthHandler 返回服务状态
func HealthHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mode := "full_only"
		if cfg.DigestMode {
			mode = "digest"
		}

		certExpires := ""
		if !cfg.CertExpires.IsZero() {
			certExpires = cfg.CertExpires.Format("2006-01-02")
		}

		capabilities := []string{"pe-sign"}
		if cfg.DigestMode {
			capabilities = append(capabilities, "pe-digest")
		}
		if cfg.RawSignPath != "" {
			capabilities = append(capabilities, "raw-sign", "xmldsig")
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "ok",
			"mode":         mode,
			"cert_subject": cfg.CertSubject,
			"cert_expires": certExpires,
			"time":         time.Now().UTC().Format(time.RFC3339),
			"capabilities": capabilities,
		})
	}
}

// writeJSON 将对象序列化为 JSON 并写入响应
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "")
	if err := enc.Encode(v); err != nil {
		// 响应已开始写入，无法改变状态码
		return
	}
}

// writeError 写入 JSON 错误响应
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
