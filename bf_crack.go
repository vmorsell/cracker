package main

import (
	"fmt"

	"github.com/urfave/cli/v2"
	"github.com/vmorsell/cracker/bruteforce"
	"github.com/vmorsell/cracker/cipherlib"
	"github.com/vmorsell/cracker/dataset"
)

var bfCrack = &cli.Command{
	Name:    "bruteforce",
	Aliases: []string{"bf"},
	Usage:   "crack password hashes using brute force",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "hash-file",
			Aliases:  []string{"hf"},
			Required: true,
		},
		&cli.IntFlag{
			Name:    "max-length",
			Aliases: []string{"max"},
			Value:   4,
		},
		&cli.IntFlag{
			Name:    "min-length",
			Aliases: []string{"min"},
		},
		&cli.StringFlag{
			Name:  "cipher",
			Value: "sha256",
		},
		&cli.BoolFlag{
			Name:    "lowercase",
			Aliases: []string{"lc"},
		},
		&cli.BoolFlag{
			Name:    "uppercase",
			Aliases: []string{"uc"},
		},
		&cli.BoolFlag{
			Name:    "numbers",
			Aliases: []string{"n"},
		},
		&cli.BoolFlag{
			Name:    "symbols",
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
