package preflight

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"codesign/internal/server/config"
)

// CheckSigntool 验证 signtool 是否可用
func CheckSigntool(path string) error {
	cmd := exec.Command(path, "/?")
	if err := cmd.Run(); err != nil {
		// signtool /? 在某些版本返回 exit code 1（帮助文本输出后退出）
		// 只接受 exit code 0 或 1 作为"工具存在且可执行"的凭证
		exitErr, ok := err.(*exec.ExitError)
		if ok && (exitErr.ExitCode() == 0 || exitErr.ExitCode() == 1) {
			return nil
		}
		return fmt.Errorf("signtool not found or not executable at %q: %w", path, err)
	}
	return nil
}

// CheckCert 验证证书文件是否存在且未过期，返回解析后的证书
func CheckCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cert file %q: %w", path, err)
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse cert DER: %w", err)
	}

	now := time.Now()
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate expired at %s (subject: %s)", cert.NotAfter.Format("2006-01-02"), cert.Subject.CommonName)
	}
	if now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("certificate not yet valid, valid from %s", cert.NotBefore.Format("2006-01-02"))
	}

	return cert, nil
}

// CheckRawSign 验证 raw-sign.exe 是否存在
func CheckRawSign(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("raw-sign.exe not found at %q: %w", path, err)
	}
	return nil
}

// CheckAll 执行所有启动前置检查，任何检查失败都记录 Fatal 并退出
func CheckAll(cfg *config.Config) *x509.Certificate {
	// 检查 signtool
	slog.Info("checking signtool", "path", cfg.SigntoolPath)
	if err := CheckSigntool(cfg.SigntoolPath); err != nil {
		slog.Error("signtool check failed", "error", err)
		fmt.Fprintf(os.Stderr, "FATAL: signtool check failed: %v\n", err)
		os.Exit(1)
	}
	slog.Info("signtool OK")

	// 检查证书
	slog.Info("checking certificate", "path", cfg.CertPath)
	cert, err := CheckCert(cfg.CertPath)
	if err != nil {
		slog.Error("certificate check failed", "error", err)
		fmt.Fprintf(os.Stderr, "FATAL: certificate check failed: %v\n", err)
		os.Exit(1)
	}
	slog.Info("certificate OK",
		"subject", cert.Subject.CommonName,
		"expires", cert.NotAfter.Format("2006-01-02"),
	)

	// 检查 raw-sign.exe（可选）
	if cfg.RawSignPath != "" {
		slog.Info("checking raw-sign", "path", cfg.RawSignPath)
		if err := CheckRawSign(cfg.RawSignPath); err != nil {
			slog.Error("raw-sign check failed", "error", err)
			fmt.Fprintf(os.Stderr, "FATAL: raw-sign check failed: %v\n", err)
			os.Exit(1)
		}
		slog.Info("raw-sign OK")
	}

	return cert
}
