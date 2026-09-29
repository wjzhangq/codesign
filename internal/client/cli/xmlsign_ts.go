package cli

import (
	"fmt"
	"os"

	"codesign/internal/client/api"
	clientconfig "codesign/internal/client/config"

	urfavecli "github.com/urfave/cli/v2"
)

// DefaultTimestampURL 是 xmlsign-ts 命令默认使用的 RFC 3161 时间戳服务器
const DefaultTimestampURL = "http://timestamp.digicert.com"

// XmlSignTsCommand 返回 xmlsign-ts 命令定义
// 等同于 xmlsign，但默认附加 DigiCert 时间戳，可用 -t 覆盖
func XmlSignTsCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:      "xmlsign-ts",
		Usage:     "Sign XML documents with XMLDSIG enveloped signature + RFC 3161 timestamp",
		ArgsUsage: "<file> [file...]",
		Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{
				Name:      "output",
				Aliases:   []string{"o"},
				Usage:     "Output file path (default: overwrite input)",
				TakesFile: false,
			},
			&urfavecli.StringFlag{
				Name:    "timestamp",
				Aliases: []string{"t"},
				Usage:   "Timestamp server URL (RFC 3161 TSA)",
				Value:   DefaultTimestampURL,
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
			// 手动解析 -o 和 -t flags（urfave/cli 在位置参数后跟 flag 时解析有问题）
			rawArgs := parseArgsAfterCommand()
			outputPath, remainingArgs := extractOutputFlag(rawArgs)
			tsaURL, remainingArgs := extractTimestampFlag(remainingArgs)

			// 未显式指定 -t 时使用默认时间戳服务器
			if tsaURL == "" {
				tsaURL = DefaultTimestampURL
			}

			if len(remainingArgs) == 0 {
				return urfavecli.ShowCommandHelp(c, "xmlsign-ts")
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
			files := remainingArgs

			// 多文件 + 指定单个输出文件 → 错误
			if len(files) > 1 && outputPath != "" {
				info, err := os.Stat(outputPath)
				if err == nil && !info.IsDir() {
					return fmt.Errorf("cannot output multiple files to a single file path; use a directory with -o")
				}
			}

			certDER, err := client.GetPublicCert()
			if err != nil {
				return fmt.Errorf("get server cert: %w", err)
			}

			chainDERs, _ := client.GetCertChain()

			hasError := false
			for _, filePath := range files {
				outPath := resolveOutputPath(filePath, outputPath)
				if err := xmlSignFile(client, filePath, outPath, certDER, chainDERs, tsaURL); err != nil {
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
