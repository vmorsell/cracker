// Package main holds logic for Cracker Command Line tool.
// Refer to the subpackages for more details about how the tool works.
package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	cli.HelpFlag = &cli.BoolFlag{
		Name:    "help",
		Aliases: []string{"h"},
		Usage:   "Show help",
	}

	app := &cli.App{
		Name: "cracker",
		Authors: []*cli.Author{
			&cli.Author{
				Name:  "Viktor Mörsell",
				Email: "viktor.morsell@protonmail.ch",
			},
		},
		Usage:           "Brute force cracking of hashes",
		UsageText:       "cracker <command> [command options]",
		HideHelpCommand: true,
		Commands: []*cli.Command{
			bfCrack,
			dictCrack,
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
