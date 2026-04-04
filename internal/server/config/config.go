package config

import (
	"fmt"
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
	SigntoolPath string
	CertPath     string
	CSPName      string
	CSPKey       string
	TimestampURL string
	SignTimeout  int
	TempDir      string
	DigestMode   bool

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
	cfg.CertPath = mustString(signSec, "cert_path")
	cfg.CSPName = mustString(signSec, "csp_name")
	cfg.CSPKey = mustString(signSec, "csp_key")
	cfg.TimestampURL = mustString(signSec, "timestamp_url")
	cfg.SignTimeout = signSec.Key("sign_timeout").MustInt(120)
	cfg.TempDir = mustString(signSec, "temp_dir")
	cfg.DigestMode = signSec.Key("digest_mode").MustBool(false)

	return cfg
}

func mustString(sec *ini.Section, key string) string {
	v := sec.Key(key).String()
	if v == "" {
		panic(fmt.Sprintf("required config key [%s] %s is missing or empty", sec.Name(), key))
	}
	return v
}
