package cli

import (
	"fmt"

	"codesign/internal/client/api"
	clientconfig "codesign/internal/client/config"

	urfavecli "github.com/urfave/cli/v2"
)

// RawSignCommand 返回 raw-sign 调试命令定义
func RawSignCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "raw-sign",
		Usage: "Send raw digest to server for signing (debug)",
		Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{
				Name:     "digest",
				Usage:    "Hex-encoded digest to sign",
				Required: true,
			},
			&urfavecli.StringFlag{
				Name:  "algo",
				Usage: "Hash algorithm (sha256 | sha1)",
				Value: "sha256",
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
			resp, err := client.RawSign(c.String("digest"), c.String("algo"))
			if err != nil {
				return fmt.Errorf("raw-sign: %w", err)
			}

			fmt.Printf("Algorithm: %s\n", resp.Algorithm)
			fmt.Printf("Signature: %s\n", resp.Signature)
			return nil
		},
	}
}
