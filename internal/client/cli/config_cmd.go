package cli

import (
	"fmt"

	clientconfig "codesign/internal/client/config"

	"github.com/urfave/cli/v2"
)

// ConfigCommand 返回 config 命令定义
func ConfigCommand() *cli.Command {
	return &cli.Command{
		Name:  "config",
		Usage: "Configure codesign client",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "server",
				Usage:    "Code signing server URL (e.g. https://sign.corp.com:8443)",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "token",
				Usage:    "JWT authentication token",
				Required: false,
			},
		},
		Action: func(c *cli.Context) error {
			cfg, err := clientconfig.Load()
			if err != nil {
				cfg = &clientconfig.Config{}
			}

			updated := false
			if s := c.String("server"); s != "" {
				cfg.Server = s
				updated = true
			}
			if t := c.String("token"); t != "" {
				cfg.Token = t
				updated = true
			}

			if !updated {
				// 显示当前配置
				fmt.Printf("Current configuration:\n")
				fmt.Printf("  server: %s\n", cfg.Server)
				if cfg.Token != "" {
					// 只显示 token 前 20 个字符
					preview := cfg.Token
					if len(preview) > 20 {
						preview = preview[:20] + "..."
					}
					fmt.Printf("  token:  %s\n", preview)
				} else {
					fmt.Printf("  token:  (not set)\n")
				}
				fmt.Printf("  config: %s\n", clientconfig.ConfigPath())
				return nil
			}

			if err := clientconfig.Save(cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			fmt.Printf("Configuration saved to %s\n", clientconfig.ConfigPath())
			if cfg.Server != "" {
				fmt.Printf("  server: %s\n", cfg.Server)
			}
			if cfg.Token != "" {
				preview := cfg.Token
				if len(preview) > 20 {
					preview = preview[:20] + "..."
				}
				fmt.Printf("  token:  %s\n", preview)
			}
			return nil
		},
	}
}
