package main

import (
	"fmt"

	"github.com/urfave/cli/v2"
	"github.com/vmorsell/cracker/bruteforce"
	"github.com/vmorsell/cracker/cipherlib"
	"github.com/vmorsell/cracker/dataset"
)

var bfCrack = &cli.Command{
	Name:      "bruteforce",
	Aliases:   []string{"bf"},
	Usage:     "Perform a cracking attempt using brute force",
	UsageText: "cracker bruteforce --hash-file FILE [options]",

	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "hash-file",
			Aliases:  []string{"hf"},
			Usage:    "Load hashes from `FILE` (required)",
			Required: true,
		},
		&cli.IntFlag{
			Name:    "max-length",
			Aliases: []string{"max"},
			Usage:   "Max length of password candidate",
			Value:   4,
		},
		&cli.IntFlag{
			Name:    "min-length",
			Aliases: []string{"min"},
			Usage:   "Min length of password candidate",
			Value:   1,
		},
		&cli.StringFlag{
			Name:    "cipher",
			Aliases: []string{"c"},
			Usage:   "Use cipher `NAME`",
			Value:   "sha256",
		},
		&cli.BoolFlag{
			Name:    "lowercase",
			Usage:   "Use lowercase letters",
			Aliases: []string{"lc"},
		},
		&cli.BoolFlag{
			Name:    "uppercase",
			Usage:   "Use uppercase letters",
			Aliases: []string{"uc"},
		},
		&cli.BoolFlag{
			Name:    "numbers",
			Usage:   "Use numbers",
			Aliases: []string{"n"},
		},
		&cli.BoolFlag{
			Name:    "symbols",
			Usage:   "Use special characters",
			Aliases: []string{"s"},
		},
	},
	Action: func(c *cli.Context) error {
		ds, err := dataset.New(c.String("hash-file"))
		if err != nil {
			return err
		}

		bf := bruteforce.New()
		cipher, err := cipherlib.NewSha2(256)
		if err != nil {
			return err
		}
		s := &bruteforce.Strategy{
			Cipher:    cipher,
			Uppercase: c.Bool("uppercase"),
			Lowercase: c.Bool("lowercase"),
			Numbers:   c.Bool("numbers"),
			Special:   c.Bool("special"),
			Min:       c.Int("min-length"),
			Max:       c.Int("max-length"),
		}

		fmt.Println("Starting Brute Force attack...")
		for ds.HasNext() {
			item, err := ds.Next()
			if err != nil {
				return err
			}

			fmt.Printf("%s     ", shortHash(item.Hash))
			res := bf.Crack(item.Hash, item.Salt, s)
			if !res.Ok {
				fmt.Println("no match")
				continue
			}

			fmt.Printf("%s (%f s, %d tries)\n", res.Password, res.Time.Seconds(), res.Tries)
		}
		fmt.Println("Done.")
		return nil
	},
}
