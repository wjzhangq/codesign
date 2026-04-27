package config

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"gopkg.in/ini.v1"
)

// Config 服务端配置
type Config struct {
	// [server]
	Listen string

	// [auth]
	JWTSecret string
	TokenDB   string

	// [sign]
	SigntoolPath  string
	RawSignPath   string
	CertPath      string
	CertChainDir  string   // 可选：包含中间 CA 证书的目录
	CertChainDERs [][]byte // 可选：内嵌的证书链 DER（从 cert_chain 解析）
	CSPName       string
	CSPKey        string
	TimestampURL  string
	SignTimeout   int
	TempDir       string
	DigestMode    bool

	// 从证书中解析（启动时填充）
	CertSubject string
	CertExpires time.Time
}

// Load 从 INI 文件加载配置，缺少必填项时 panic
func Load(path string) *Config {
	f, err := ini.Load(path)
	if err != nil {
		panic(fmt.Sprintf("failed to load config %q: %v", path, err))
	}

	cfg := &Config{}

	// [server]
	serverSec := f.Section("server")
	cfg.Listen = mustString(serverSec, "listen")

	// [auth]
	authSec := f.Section("auth")
	cfg.JWTSecret = mustString(authSec, "jwt_secret")
	if len(cfg.JWTSecret) < 32 {
		panic("auth.jwt_secret must be at least 32 characters")
	}
	cfg.TokenDB = mustString(authSec, "token_db")

	// [sign]
	signSec := f.Section("sign")
	cfg.SigntoolPath = mustString(signSec, "signtool_path")
	cfg.RawSignPath = signSec.Key("raw_sign_path").String()
	cfg.CertPath = mustString(signSec, "cert_path")
	cfg.CertChainDir = signSec.Key("cert_chain_dir").String()
	cfg.CertChainDERs = parseCertChain(signSec.Key("cert_chain").String())
	cfg.CSPName = mustString(signSec, "csp_name")
	cfg.CSPKey = mustString(signSec, "csp_key")
	cfg.TimestampURL = mustString(signSec, "timestamp_url")
	cfg.SignTimeout = signSec.Key("sign_timeout").MustInt(120)
	cfg.TempDir = mustString(signSec, "temp_dir")
	cfg.DigestMode = signSec.Key("digest_mode").MustBool(false)

	return cfg
}

// parseCertChain 解析分号分隔的 base64 DER 证书列表
func parseCertChain(raw string) [][]byte {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var certs [][]byte
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(part)
		if err != nil {
			panic(fmt.Sprintf("invalid base64 in cert_chain: %v", err))
		}
		certs = append(certs, der)
	}
	return certs
}

func mustString(sec *ini.Section, key string) string {
	v := sec.Key(key).String()
	if v == "" {
		panic(fmt.Sprintf("required config key [%s] %s is missing or empty", sec.Name(), key))
	}
	return v
}
