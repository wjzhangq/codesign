package cli

import (
	"fmt"
	"os"

	"codesign/internal/pe"

	"github.com/urfave/cli/v2"
)

// InfoCommand 返回 info 命令定义
func InfoCommand() *cli.Command {
	return &cli.Command{
		Name:      "info",
		Usage:     "Display PE file information",
		ArgsUsage: "<file>",
		Action: func(c *cli.Context) error {
			if c.NArg() == 0 {
				return cli.ShowCommandHelp(c, "info")
			}

			filePath := c.Args().First()
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				return fmt.Errorf("file not found: %s", filePath)
			}

			info, err := pe.ParsePE(filePath)
			if err != nil {
				return fmt.Errorf("parse PE: %w", err)
			}

			arch := "PE32 (x86)"
			if info.IsPE32Plus {
				arch = "PE32+ (x64)"
			}

			signed := "no"
			if info.CertTableOffset > 0 && info.CertTableSize > 0 {
				signed = fmt.Sprintf("yes (CertTable: offset=0x%X, size=%d)", info.CertTableOffset, info.CertTableSize)
			}

			fmt.Printf("PE Info: %s\n", filePath)
			fmt.Printf("  Architecture:        %s\n", arch)
			fmt.Printf("  File size:           %d bytes\n", info.FileSize)
			fmt.Printf("  Sections:            %d\n", info.NumSections)
			fmt.Printf("  ChecksumOffset:      0x%08X\n", info.ChecksumOffset)
			fmt.Printf("  SecurityDirOffset:   0x%08X\n", info.SecurityDirOffset)
			fmt.Printf("  CertTableOffset:     0x%08X\n", info.CertTableOffset)
			fmt.Printf("  CertTableSize:       %d\n", info.CertTableSize)
			fmt.Printf("  OverlayOffset:       0x%08X\n", info.OverlayOffset)
			fmt.Printf("  Signed:              %s\n", signed)

			return nil
		},
	}
}
