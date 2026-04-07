package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"codesign/internal/client/api"
	clientconfig "codesign/internal/client/config"
	"codesign/internal/xmldsig"

	urfavecli "github.com/urfave/cli/v2"
)

// XmlVerifyCommand 返回 xmlverify 命令定义
func XmlVerifyCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:      "xmlverify",
		Usage:     "Verify XMLDSIG enveloped signature in signed XML documents",
		ArgsUsage: "<file> [file...]",
		Action: func(c *urfavecli.Context) error {
			if c.NArg() == 0 {
				return urfavecli.ShowCommandHelp(c, "xmlverify")
			}

			files := c.Args().Slice()
			hasError := false
			for _, filePath := range files {
				ok := xmlVerifyFile(filePath)
				if !ok {
					hasError = true
				}
			}
			if hasError {
				return fmt.Errorf("some files failed verification")
			}
			return nil
		},
	}
}

// xmlVerifyFile 验证单个 XML 文件的签名，返回 true 表示验证通过
func xmlVerifyFile(filePath string) bool {
	fmt.Printf("\n  %s\n", filepath.Base(filePath))

	xmlBytes, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("  ERROR: read file: %v\n", err)
		return false
	}

	result, err := xmldsig.VerifyXML(xmlBytes)
	if err != nil {
		fmt.Printf("  INVALID: %v\n", err)
		return false
	}

	if !result.Valid {
		fmt.Printf("  INVALID: signature verification failed\n")
		return false
	}

	fmt.Printf("  VALID\n")
	if result.SubjectCN != "" {
		fmt.Printf("  Signer  : %s\n", result.SubjectCN)
	}
	if result.Certificate != nil {
		fmt.Printf("  Issuer  : %s\n", result.Certificate.Issuer.CommonName)
		fmt.Printf("  Valid   : %s → %s\n", result.NotBefore, result.NotAfter)
	}
	return true
}

// XmlSignCommand 返回 xmlsign 命令定义
func XmlSignCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:      "xmlsign",
		Usage:     "Sign XML documents with XMLDSIG enveloped signature",
		ArgsUsage: "<file> [file...]",
		Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "Output file path (default: overwrite input)",
			},
			&urfavecli.StringFlag{
				Name:  "server",
				Usage: "Override server URL",
			},
			&urfavecli.StringFlag{
				Name:  "token",
				Usage: "Override JWT token",
			},
		},
		Action: func(c *urfavecli.Context) error {
			if c.NArg() == 0 {
				return urfavecli.ShowCommandHelp(c, "xmlsign")
			}

			cfg := clientconfig.MustLoad()
			if s := c.String("server"); s != "" {
				cfg.Server = s
			}
			if t := c.String("token"); t != "" {
				cfg.Token = t
			}
			if cfg.Server == "" || cfg.Token == "" {
				return fmt.Errorf("server/token not configured. Run: codesign config --server <url> --token <jwt>")
			}

			client := api.New(cfg.Server, cfg.Token)
			outputPath := c.String("output")
			files := c.Args().Slice()

			// 多文件 + 指定单个输出文件 → 错误
			if len(files) > 1 && outputPath != "" {
				info, err := os.Stat(outputPath)
				if err == nil && !info.IsDir() {
					return fmt.Errorf("cannot output multiple files to a single file path; use a directory with -o")
				}
			}

			// 获取公钥证书（批量签名时只获取一次）
			certDER, err := client.GetPublicCert()
			if err != nil {
				return fmt.Errorf("get server cert: %w", err)
			}

			hasError := false
			for _, filePath := range files {
				outPath := resolveOutputPath(filePath, outputPath)
				if err := xmlSignFile(client, filePath, outPath, certDER); err != nil {
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

// resolveOutputPath 根据 outputPath 参数和 inputPath 计算最终输出路径
func resolveOutputPath(inputPath, outputPath string) string {
	if outputPath == "" {
		return inputPath // 覆盖原文件
	}
	info, err := os.Stat(outputPath)
	if err == nil && info.IsDir() {
		return filepath.Join(outputPath, filepath.Base(inputPath))
	}
	return outputPath
}

func xmlSignFile(client *api.Client, inputPath, outputPath string, certDER []byte) error {
	start := time.Now()

	fmt.Printf("\n  %s\n", filepath.Base(inputPath))

	// 读取 XML
	xmlBytes, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	fmt.Printf("  [1/3] Computing document digest...\n")
	fmt.Printf("        input: %d bytes\n", len(xmlBytes))

	// 签名回调: 通过 API 调用服务端 raw-sign
	signFunc := func(digestHex string) (string, error) {
		fmt.Printf("  [2/3] Remote signing...\n")
		remoteStart := time.Now()
		resp, err := client.RawSign(digestHex, "sha256")
		if err != nil {
			return "", err
		}
		fmt.Printf("        remote: %.1fs\n", time.Since(remoteStart).Seconds())
		return resp.Signature, nil
	}

	// 执行 XMLDSIG 签名
	signedXML, err := xmldsig.SignXML(xmlBytes, certDER, signFunc)
	if err != nil {
		return fmt.Errorf("xmldsig sign: %w", err)
	}

	// 写入输出（先写临时文件再 rename，保证原子性）
	fmt.Printf("  [3/3] Writing output...\n")
	tmpPath := outputPath + ".tmp"
	if err := os.WriteFile(tmpPath, signedXML, 0644); err != nil {
		return fmt.Errorf("write temp output: %w", err)
	}
	if err := os.Rename(tmpPath, outputPath); err != nil {
		os.Remove(tmpPath) //nolint:errcheck
		return fmt.Errorf("rename output: %w", err)
	}

	fmt.Printf("        output: %s (%d bytes)\n", filepath.Base(outputPath), len(signedXML))
	fmt.Printf("  Done in %.1fs\n", time.Since(start).Seconds())
	return nil
}
