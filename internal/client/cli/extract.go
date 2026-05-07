package cli

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"codesign/internal/pe"

	"github.com/urfave/cli/v2"
)

func ExtractCommand() *cli.Command {
	return &cli.Command{
		Name:      "extract",
		Usage:     "Extract PKCS#7 signature from signed PE file (.p7b)",
		ArgsUsage: "<file> [file...]",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "Output file path (only for single file input)",
			},
		},
		Action: func(c *cli.Context) error {
			if c.NArg() == 0 {
				return cli.ShowCommandHelp(c, "extract")
			}

			output := c.String("output")
			if output != "" && c.NArg() > 1 {
				return fmt.Errorf("-o flag can only be used with a single input file")
			}

			for i := 0; i < c.NArg(); i++ {
				filePath := c.Args().Get(i)
				outPath := output
				if outPath == "" {
					outPath = filePath + ".p7b"
				}

				if err := extractP7B(filePath, outPath); err != nil {
					fmt.Fprintf(os.Stderr, "  %s: %v\n", filePath, err)
					continue
				}

				info, _ := os.Stat(outPath)
				fmt.Printf("  %s → %s (%d bytes)\n", filePath, outPath, info.Size())
			}
			return nil
		},
	}
}

func extractP7B(inputPath, outputPath string) error {
	certTable, err := pe.ExtractCertTable(inputPath)
	if err != nil {
		return err
	}

	if len(certTable) < 8 {
		return fmt.Errorf("certificate table too small")
	}

	dwLength := binary.LittleEndian.Uint32(certTable[0:4])
	pkcs7End := int(dwLength)
	if pkcs7End > len(certTable) {
		pkcs7End = len(certTable)
	}
	pkcs7Data := certTable[8:pkcs7End]

	dir := filepath.Dir(outputPath)
	if dir != "." && dir != "" {
		os.MkdirAll(dir, 0755)
	}

	return os.WriteFile(outputPath, pkcs7Data, 0644)
}
