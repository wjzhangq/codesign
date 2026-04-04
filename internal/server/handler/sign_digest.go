package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"codesign/internal/pe"
	"codesign/internal/server/config"
	"codesign/internal/server/signer"
)

// SignDigestRequest POST /api/sign 请求体
type SignDigestRequest struct {
	Filename string     `json:"filename"`
	Dig      string     `json:"dig"` // base64 of digest bytes
	P7U      string     `json:"p7u"` // base64 of unsigned PKCS#7
	PEInfo   PEInfoJSON `json:"pe_info"`
}

// PEInfoJSON JSON 格式的 PE 信息
type PEInfoJSON struct {
	ChecksumOffset    uint32 `json:"checksum_offset"`
	SecurityDirOffset uint32 `json:"security_dir_offset"`
	CertTableOffset   uint32 `json:"cert_table_offset"`
	OverlayOffset     uint32 `json:"overlay_offset"`
	IsPE32Plus        bool   `json:"is_pe32_plus"`
}

// SignDigestResponse POST /api/sign 响应体
type SignDigestResponse struct {
	CertificateTable string `json:"certificate_table"` // base64
	Checksum         uint32 `json:"checksum"`           // 0 = 客户端自行计算
}

// SignDigestHandler 处理 Digest 模式签名请求
func SignDigestHandler(cfg *config.Config, s *signer.Signer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 如果 Digest 模式未启用，返回 501
		if !cfg.DigestMode {
			writeJSON(w, http.StatusNotImplemented, map[string]any{
				"error":    "digest mode not supported, use /api/sign/full",
				"fallback": true,
			})
			return
		}

		// 限制请求体大小 64 KB
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

		var req SignDigestRequest
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil {
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
		if req.P7U == "" {
			writeError(w, http.StatusBadRequest, "p7u is required")
			return
		}

		// 转换 PEInfo
		peInfo := &pe.PEInfo{
			ChecksumOffset:    req.PEInfo.ChecksumOffset,
			SecurityDirOffset: req.PEInfo.SecurityDirOffset,
			CertTableOffset:   req.PEInfo.CertTableOffset,
			OverlayOffset:     req.PEInfo.OverlayOffset,
			IsPE32Plus:        req.PEInfo.IsPE32Plus,
		}

		// 调用 DigestSign
		certTable, err := s.DigestSignFromBase64(r.Context(), req.Filename, req.Dig, req.P7U, peInfo)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "signing failed: "+err.Error())
			return
		}

		writeJSON(w, http.StatusOK, SignDigestResponse{
			CertificateTable: base64.StdEncoding.EncodeToString(certTable),
			Checksum:         0, // 客户端自行计算
		})
	}
}


