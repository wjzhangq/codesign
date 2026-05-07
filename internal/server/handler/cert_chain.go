package handler

import (
	"encoding/base64"
	"net/http"
	"os"

	"codesign/internal/certchain"
	"codesign/internal/server/config"
)

// CertChainHandler 返回证书链 DER 编码列表（JSON base64 数组）
// 自动从签名证书的 AIA 扩展下载并缓存
func CertChainHandler(cfg *config.Config) http.HandlerFunc {
	var chainB64 []string

	certDER, err := os.ReadFile(cfg.CertPath)
	if err == nil {
		chainDERs := certchain.FetchChain(certDER, cfg.TempDir)
		for _, der := range chainDERs {
			chainB64 = append(chainB64, base64.StdEncoding.EncodeToString(der))
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"chain": chainB64,
		})
	}
}
