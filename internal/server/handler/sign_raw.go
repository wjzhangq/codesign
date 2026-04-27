package handler

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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

	chainDERs := append(cfg.CertChainDERs, loadChainCerts(cfg.CertChainDir)...)

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

// loadChainCerts 从目录加载证书链（.cer / .crt / .pem 文件，DER 或 PEM 格式）
func loadChainCerts(dir string) [][]byte {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Warn("load cert chain dir failed", "dir", dir, "error", err)
		return nil
	}
	var certs [][]byte
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".cer" && ext != ".crt" && ext != ".pem" && ext != ".der" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			slog.Warn("load chain cert failed", "file", e.Name(), "error", err)
			continue
		}
		// PEM 格式检测：尝试提取 DER
		if len(data) > 0 && data[0] != 0x30 {
			// 可能是 PEM，尝试解码
			if derBytes := decodePEM(data); derBytes != nil {
				certs = append(certs, derBytes)
				slog.Info("loaded chain cert (PEM)", "file", e.Name())
				continue
			}
		}
		certs = append(certs, data)
		slog.Info("loaded chain cert (DER)", "file", e.Name())
	}
	return certs
}

// decodePEM 从 PEM 数据中提取第一个 CERTIFICATE block 的 DER 字节
func decodePEM(data []byte) []byte {
	// 简单查找 -----BEGIN CERTIFICATE-----
	const begin = "-----BEGIN CERTIFICATE-----"
	const end = "-----END CERTIFICATE-----"
	s := string(data)
	idx := strings.Index(s, begin)
	if idx < 0 {
		return nil
	}
	s = s[idx+len(begin):]
	idx = strings.Index(s, end)
	if idx < 0 {
		return nil
	}
	b64 := strings.ReplaceAll(s[:idx], "\n", "")
	b64 = strings.ReplaceAll(b64, "\r", "")
	b64 = strings.TrimSpace(b64)
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil
	}
	return der
}
