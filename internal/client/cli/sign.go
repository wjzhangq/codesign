package cli

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"codesign/internal/client/api"
	clientconfig "codesign/internal/client/config"
	"codesign/internal/pe"

	"github.com/urfave/cli/v2"
)

// SignCommand 返回 sign 命令定义
func SignCommand() *cli.Command {
	return &cli.Command{
		Name:      "sign",
		Usage:     "Sign one or more PE files",
		ArgsUsage: "<file> [file...]",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "mode",
				Usage: "Signing mode: auto, digest, full (default: auto)",
				Value: "auto",
			},
			&cli.StringFlag{
				Name:  "server",
				Usage: "Override server URL",
			},
			&cli.StringFlag{
				Name:  "token",
				Usage: "Override JWT token",
			},
		},
		Action: func(c *cli.Context) error {
			if c.NArg() == 0 {
				return cli.ShowCommandHelp(c, "sign")
			}

			cfg := clientconfig.MustLoad()
			if s := c.String("server"); s != "" {
				cfg.Server = s
			}
			if t := c.String("token"); t != "" {
				cfg.Token = t
			}

			if cfg.Server == "" {
				return fmt.Errorf("server not configured. Run: codesign config --server <url> --token <jwt>")
			}
			if cfg.Token == "" {
				return fmt.Errorf("token not configured. Run: codesign config --server <url> --token <jwt>")
			}

			client := api.New(cfg.Server, cfg.Token)
			mode := c.String("mode")

			// 确定签名模式（auto 时查询服务端）
			if mode == "auto" {
				health, err := client.Health()
				if err != nil {
					return fmt.Errorf("cannot reach server: %w", err)
				}
				mode = health.Mode
			}

			// 批量处理文件
			files := c.Args().Slice()
			hasError := false
			for _, filePath := range files {
				if err := signFile(client, filePath, mode); err != nil {
					if len(files) > 1 {
						fmt.Fprintf(os.Stderr, "  ERROR %s: %v\n", filePath, err)
						hasError = true
					} else {
						return err
					}
				}
			}
			if hasError {
				return fmt.Errorf("some files failed to sign")
			}
			return nil
		},
	}
}

func signFile(client *api.Client, filePath, mode string) error {
	// 检查文件存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", filePath)
	}

	fmt.Printf("\n  %s\n", filepath.Base(filePath))

	// [1/4] 解析 PE
	fmt.Printf("  [1/4] Parsing PE...\n")
	info, err := pe.ParsePE(filePath)
	if err != nil {
		return fmt.Errorf("not a valid PE file: %w", err)
	}
	arch := "PE32"
	if info.IsPE32Plus {
		arch = "PE32+"
	}
	fmt.Printf("        %s, size=%d bytes\n", arch, info.FileSize)
	fmt.Printf("        ChecksumOff=0x%X  SecDirOff=0x%X  Overlay=0x%X\n",
		info.ChecksumOffset, info.SecurityDirOffset, info.OverlayOffset)

	// 根据模式选择签名方式
	switch mode {
	case "digest":
		if err := signDigestMode(client, filePath, info); err != nil {
			if errors.Is(err, api.ErrFallbackRequired) {
				fmt.Printf("  ⚠ Digest mode unavailable, falling back to full upload\n")
				return signFullMode(client, filePath, info)
			}
			return err
		}
	case "full", "full_only":
		return signFullMode(client, filePath, info)
	default:
		return fmt.Errorf("unknown mode: %s", mode)
	}

	return nil
}

func signDigestMode(client *api.Client, filePath string, info *pe.PEInfo) error {
	start := time.Now()

	// [2/4] 计算 Authenticode Digest
	fmt.Printf("  [2/4] Computing Authenticode digest...\n")
	digestStart := time.Now()
	digest, err := pe.ComputeAuthenticodeDigest(filePath, info)
	if err != nil {
		return err
	}
	fmt.Printf("        SHA-256: %x (%.1fs)\n", digest, time.Since(digestStart).Seconds())

	// 获取公钥证书
	certDER, err := client.GetPublicCert()
	if err != nil {
		return fmt.Errorf("get server cert: %w", err)
	}

	// 构造 .p7u
	p7uBytes, err := pe.BuildUnsignedPKCS7(digest, certDER)
	if err != nil {
		return fmt.Errorf("build unsigned PKCS7: %w", err)
	}

	// [3/4] 远程签名
	fmt.Printf("  [3/4] Remote signing (digest mode)...\n")
	remoteStart := time.Now()
	digB64 := base64.StdEncoding.EncodeToString(digest)
	p7uB64 := base64.StdEncoding.EncodeToString(p7uBytes)

	resp, err := client.SignDigest(filepath.Base(filePath), digB64, p7uB64, info)
	if err != nil {
		return err
	}
	fmt.Printf("        remote: %.1fs\n", time.Since(remoteStart).Seconds())

	// [4/4] 注入签名
	fmt.Printf("  [4/4] Injecting signature...\n")
	certTable, err := base64.StdEncoding.DecodeString(resp.CertificateTable)
	if err != nil {
		return fmt.Errorf("decode certificate table: %w", err)
	}

	if err := pe.InjectSignature(filePath, info, certTable); err != nil {
		return fmt.Errorf("inject signature: %w", err)
	}

	fmt.Printf("        Certificate Table: %d bytes\n", len(certTable))
	fmt.Printf("  ✓ Signed in %.1fs\n", time.Since(start).Seconds())
	return nil
}

func signFullMode(client *api.Client, filePath string, info *pe.PEInfo) error {
	start := time.Now()

	// [2/3] 上传并签名
	fmt.Printf("  [2/3] Uploading & signing (full mode)...\n")
	uploadStart := time.Now()

	resp, err := client.SignFull(filePath)
	if err != nil {
		return err
	}
	fmt.Printf("        upload+sign: %.1fs\n", time.Since(uploadStart).Seconds())

	// [3/3] 注入签名
	fmt.Printf("  [3/3] Injecting signature...\n")
	certTable, err := base64.StdEncoding.DecodeString(resp.CertificateTable)
	if err != nil {
		return fmt.Errorf("decode certificate table: %w", err)
	}

	if err := pe.InjectSignature(filePath, info, certTable); err != nil {
		return fmt.Errorf("inject signature: %w", err)
	}

	fmt.Printf("        Certificate Table: %d bytes, CheckSum: 0x%X\n",
		len(certTable), resp.Checksum)
	fmt.Printf("  ✓ Signed in %.1fs\n", time.Since(start).Seconds())
	return nil
}
