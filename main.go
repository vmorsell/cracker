package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name: "cracker",
		Authors: []*cli.Author{
			&cli.Author{
				Name:  "Viktor Mörsell",
				Email: "viktor.morsell@protonmail.ch",
			},
		},
		Usage:                "crack password hashes",
		EnableBashCompletion: true,
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
