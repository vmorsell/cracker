package main

import (
	"fmt"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/vmorsell/cracker/cipherlib"
	"github.com/vmorsell/cracker/dataset"
	"github.com/vmorsell/cracker/dictionary"
)

var dictCrack = &cli.Command{
	Name:    "dictionary",
	Aliases: []string{"dict"},
	Usage:   "crack password hashes using a dictionary",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "hash-file",
			Aliases:  []string{"hf"},
			Required: true,
		},
		&cli.StringFlag{
			Name:     "dictionary-file",
			Aliases:  []string{"df"},
			Required: true,
		},
		&cli.StringFlag{
			Name:  "cipher",
			Value: "sha256",
		},
	},
	Action: func(c *cli.Context) error {
		ds, err := dataset.New(c.String("hash-file"))
		if err != nil {
			return err
		}

		fmt.Print("Loading dictionary... ")
		t0 := time.Now()
		di, err := dictionary.New(c.String("dictionary-file"))
		if err != nil {
			return err
		}
		t := time.Now().Sub(t0)
		fmt.Printf("done. (%d words in %f seconds)\n", len(di.Words), t.Seconds())

		cipher, err := cipherlib.NewSha2(256)
		if err != nil {
			return err
		}

		s := &dictionary.Strategy{
			Cipher: cipher,
		}

		fmt.Println("Starting Dictionary attack...")
		for ds.HasNext() {
			item, err := ds.Next()
			if err != nil {
				return err
			}

			fmt.Printf("%s     ", shortHash(item.Hash))
			res := di.Crack(item.Hash, s)
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