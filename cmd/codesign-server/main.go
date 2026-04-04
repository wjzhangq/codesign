package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"codesign/internal/server/config"
	"codesign/internal/server/handler"
	"codesign/internal/server/middleware"
	"codesign/internal/server/preflight"
	"codesign/internal/server/signer"
	"codesign/internal/server/token"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// 加载配置（除 token 子命令外都需要）
	cfgPath := "config.ini"
	if len(os.Args) > 2 {
		for i, arg := range os.Args {
			if arg == "--config" && i+1 < len(os.Args) {
				cfgPath = os.Args[i+1]
			}
		}
	}

	subCmd := os.Args[1]

	switch subCmd {
	case "serve":
		cmdServe(cfgPath)
	case "token":
		if len(os.Args) < 3 {
			fmt.Println("Usage: codesign-server token <create|list|revoke> [--user <username>]")
			os.Exit(1)
		}
		cmdToken(cfgPath, os.Args[2:])
	case "verify-ds":
		cmdVerifyDS(cfgPath)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", subCmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`codesign-server - Code Signing Service

Usage:
  codesign-server serve                      Start HTTP server
  codesign-server token create --user <u>   Create a JWT token
  codesign-server token list                 List all tokens
  codesign-server token revoke --user <u>   Revoke a token
  codesign-server verify-ds                  Verify digest mode works

Flags:
  --config <path>   Config file path (default: config.ini)`)
}

func cmdServe(cfgPath string) {
	cfg := config.Load(cfgPath)

	// 启动前置检查
	cert := preflight.CheckAll(cfg)
	cfg.CertSubject = cert.Subject.CommonName
	cfg.CertExpires = cert.NotAfter

	// 创建 token manager
	tm, err := token.NewManager(cfg.JWTSecret, cfg.TokenDB)
	if err != nil {
		slog.Error("failed to create token manager", "error", err)
		os.Exit(1)
	}

	// 创建 signer
	s := signer.New(cfg)

	// JWT 中间件
	jwtMw := middleware.JWT(tm)

	// 注册路由
	mux := http.NewServeMux()
	mux.Handle("GET /api/health", handler.HealthHandler(cfg))
	mux.Handle("GET /api/cert", jwtMw(handler.CertHandler(cfg)))
	mux.Handle("POST /api/sign", jwtMw(handler.SignDigestHandler(cfg, s)))
	mux.Handle("POST /api/sign/full", jwtMw(handler.SignFullHandler(s)))

	slog.Info("starting codesign server",
		"listen", cfg.Listen,
		"mode", func() string {
			if cfg.DigestMode {
				return "digest"
			}
			return "full_only"
		}(),
	)

	if err := http.ListenAndServe(cfg.Listen, mux); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

func cmdToken(cfgPath string, args []string) {
	cfg := config.Load(cfgPath)
	tm, err := token.NewManager(cfg.JWTSecret, cfg.TokenDB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create token manager: %v\n", err)
		os.Exit(1)
	}

	if len(args) == 0 {
		fmt.Println("Usage: token <create|list|revoke>")
		os.Exit(1)
	}

	switch args[0] {
	case "create":
		user := parseFlag(args[1:], "--user")
		if user == "" {
			fmt.Fprintln(os.Stderr, "error: --user is required")
			os.Exit(1)
		}
		tok, err := tm.Create(user)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create token: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Token for user %q:\n%s\n", user, tok)

	case "list":
		infos := tm.List()
		if len(infos) == 0 {
			fmt.Println("No tokens.")
			return
		}
		fmt.Printf("%-20s  %-25s  %s\n", "USER", "CREATED_AT", "STATUS")
		for _, info := range infos {
			status := "active"
			if info.Revoked {
				status = "revoked"
			}
			fmt.Printf("%-20s  %-25s  %s\n",
				info.User,
				info.CreatedAt.Format("2006-01-02 15:04:05"),
				status,
			)
		}

	case "revoke":
		user := parseFlag(args[1:], "--user")
		if user == "" {
			fmt.Fprintln(os.Stderr, "error: --user is required")
			os.Exit(1)
		}
		if err := tm.Revoke(user); err != nil {
			fmt.Fprintf(os.Stderr, "failed to revoke: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Token for user %q has been revoked.\n", user)

	default:
		fmt.Fprintf(os.Stderr, "unknown token subcommand %q\n", args[0])
		os.Exit(1)
	}
}

func cmdVerifyDS(cfgPath string) {
	cfg := config.Load(cfgPath)

	// 不运行完整的启动前置检查（eToken 可能不可用）
	s := signer.New(cfg)
	ok := s.VerifyDigestMode(context.Background())
	if ok {
		fmt.Println("✅ Digest mode (signtool /ds + CSP) works!")
		fmt.Println("   Set digest_mode = true in config.ini")
	} else {
		fmt.Println("❌ Digest mode not supported with current CSP")
		fmt.Println("   Keep digest_mode = false, will use full upload mode")
		os.Exit(1)
	}
}

// parseFlag 从参数列表中解析 --flag value 形式的参数
func parseFlag(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
