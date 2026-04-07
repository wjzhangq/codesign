package main

import (
	"fmt"
	"os"

	"codesign/internal/client/cli"

	urfavecli "github.com/urfave/cli/v2"
)

func main() {
	app := &urfavecli.App{
		Name:    "codesign",
		Usage:   "Remote PE code signing client",
		Version: "1.0.0",
		Commands: []*urfavecli.Command{
			cli.SignCommand(),
			cli.ConfigCommand(),
			cli.InfoCommand(),
			cli.XmlSignCommand(),
			cli.XmlVerifyCommand(),
			cli.RawSignCommand(),
		},
		ExitErrHandler: func(c *urfavecli.Context, err error) {
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
