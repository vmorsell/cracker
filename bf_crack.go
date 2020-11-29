package main

import (
	"fmt"
	"reflect"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/vmorsell/cracker/bruteforce"
	"github.com/vmorsell/cracker/cipherlib"
	"github.com/vmorsell/cracker/dataset"
)

type bfReport struct {
	Processed int
	Ok        int
	Tries     int
	Duration  time.Duration
}

func (r *bfReport) AddResult(res *bruteforce.Result) {
	r.Processed++
	if res.Ok {
		r.Ok++
	}
	r.Tries += res.Tries
	r.Duration = r.Duration + res.Time
}

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

		report := &bfReport{}
		fmt.Println("Starting Brute Force attack...")
		for ds.HasNext() {
			item, err := ds.Next()
			if err != nil {
				return err
			}

			fmt.Printf("%s     ", shortHash(item.Hash))
			res := bf.Crack(item.Hash, item.Salt, s)

			report.AddResult(res)
			if !res.Ok {
				fmt.Println("no match")
				continue
			}
			fmt.Printf("%s (%f s, %d tries)\n", res.Password, res.Time.Seconds(), res.Tries)
		}
		fmt.Printf("Done in %.1f seconds.\n\n", report.Duration.Seconds())

		v := reflect.ValueOf(*s)
		typ := reflect.TypeOf(*s)
		for i := 0; i < v.NumField(); i++ {
			fmt.Printf("%-20s%v\n", typ.Field(i).Name, v.Field(i).Interface())
		}

		fmt.Printf("\n%-20s%d\n%-20s%d (%.1f %%)\n%-20s%.0f %s\n",
			"Processed",
			report.Processed,
			"Cracked",
			report.Ok,
			float64(report.Ok)/float64(report.Processed)*100,
			"Hash rate (avg)",
			float64(report.Tries)/report.Duration.Seconds(),
			"h/s",
		)
		return nil
	},
}
