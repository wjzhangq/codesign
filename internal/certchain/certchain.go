package certchain

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	httpClient     *http.Client
	httpClientOnce sync.Once
)

func getHTTPClient() *http.Client {
	httpClientOnce.Do(func() {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	})
	return httpClient
}

// FetchChain 从签名证书 DER 自动获取完整证书链（中间 CA）
// cacheDir 为缓存目录，为空则不缓存
func FetchChain(certDER []byte, cacheDir string) [][]byte {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil
	}

	// 尝试从缓存加载
	if cacheDir != "" {
		if cached := loadCache(cacheDir, cert); len(cached) > 0 {
			return cached
		}
	}

	// 从 AIA 递归下载
	chain := fetchFromAIA(certDER)

	// 写入缓存
	if cacheDir != "" && len(chain) > 0 {
		saveCache(cacheDir, cert, chain)
	}

	return chain
}

// fetchFromAIA 从证书的 AIA 扩展递归下载证书链
func fetchFromAIA(certDER []byte) [][]byte {
	var chain [][]byte
	current := certDER

	for i := 0; i < 5; i++ {
		cert, err := x509.ParseCertificate(current)
		if err != nil {
			break
		}

		if cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
			break
		}

		if len(cert.IssuingCertificateURL) == 0 {
			break
		}

		issuerURL := cert.IssuingCertificateURL[0]
		slog.Info("fetching issuer cert from AIA", "url", issuerURL)

		issuerDER, err := downloadCert(issuerURL)
		if err != nil {
			slog.Warn("failed to download issuer cert", "url", issuerURL, "error", err)
			break
		}

		// 不包含根 CA（自签名证书：Issuer == Subject）
		issuerCert, err := x509.ParseCertificate(issuerDER)
		if err != nil {
			break
		}
		if issuerCert.IsCA && issuerCert.Issuer.CommonName == issuerCert.Subject.CommonName {
			break
		}

		chain = append(chain, issuerDER)
		current = issuerDER
	}

	return chain
}

func downloadCert(url string) ([]byte, error) {
	resp, err := getHTTPClient().Get(url)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if _, err := x509.ParseCertificate(data); err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}

	return data, nil
}

// cacheFileName 根据证书指纹生成缓存文件名
func cacheFileName(cert *x509.Certificate) string {
	serial := cert.SerialNumber.Text(16)
	return fmt.Sprintf("chain_%s.pem", serial)
}

func loadCache(dir string, cert *x509.Certificate) [][]byte {
	path := filepath.Join(dir, cacheFileName(cert))
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	// 缓存 7 天过期
	if time.Since(info.ModTime()) > 7*24*time.Hour {
		os.Remove(path) //nolint:errcheck
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var chain [][]byte
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			if _, err := x509.ParseCertificate(block.Bytes); err == nil {
				chain = append(chain, block.Bytes)
			}
		}
		data = rest
	}

	if len(chain) > 0 {
		slog.Info("loaded cert chain from cache", "path", path, "count", len(chain))
	}
	return chain
}

func saveCache(dir string, cert *x509.Certificate, chain [][]byte) {
	os.MkdirAll(dir, 0755) //nolint:errcheck
	path := filepath.Join(dir, cacheFileName(cert))

	var pemData []byte
	for _, der := range chain {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
		pemData = append(pemData, pem.EncodeToMemory(block)...)
	}

	if err := os.WriteFile(path, pemData, 0644); err != nil {
		slog.Warn("failed to cache cert chain", "path", path, "error", err)
	} else {
		slog.Info("cached cert chain", "path", path, "count", len(chain))
	}
}
