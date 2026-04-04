package handler

import (
	"net/http"
	"os"

	"codesign/internal/server/config"
)

// CertHandler 返回 DER 编码的公钥证书
// certDER 在服务启动时从磁盘读取并缓存，避免每次请求都读磁盘（N-5）
func CertHandler(cfg *config.Config) http.HandlerFunc {
	// 预加载：启动时读取一次，错误在 preflight 阶段已处理
	certDER, err := os.ReadFile(cfg.CertPath)
	if err != nil {
		// preflight 已确保文件存在；此处作为保险返回 500
		return func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusInternalServerError, "failed to read certificate: "+err.Error())
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.WriteHeader(http.StatusOK)
		w.Write(certDER) //nolint:errcheck
	}
}
