package handler

import (
	"net/http"
	"os"

	"codesign/internal/server/config"
)

// CertHandler 返回 DER 编码的公钥证书
func CertHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(cfg.CertPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to read certificate: "+err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.WriteHeader(http.StatusOK)
		w.Write(data) //nolint:errcheck
	}
}
