package main

import (
	"fmt"
	"reflect"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/vmorsell/cracker/cipherlib"
	"github.com/vmorsell/cracker/dataset"
	"github.com/vmorsell/cracker/dictionary"
	"github.com/vmorsell/cracker/digestcache"
)

type dictReport struct {
	Processed    int
	Ok           int
	Tries        int
	OkUsingCache int
	Duration     time.Duration
}

func (r *dictReport) AddResult(res *dictionary.Result) {
	r.Processed++
	if res.Ok {
		r.Ok++
	}
	if res.UsedCache {
		r.OkUsingCache++
	}
	r.Tries += res.Tries
	r.Duration = r.Duration + res.Duration
}

var dictCrack = &cli.Command{
	Name:      "dictionary",
	Aliases:   []string{"dict"},
	Usage:     "Perform a cracking attempt using a dictionary",
	UsageText: "cracker dictionary --hash-file FILE --dictionary-file FILE [options]",

	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "hash-file",
			Aliases:  []string{"hf"},
			Usage:    "Load hashes from `FILE` (required)",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "dictionary-file",
			Usage:    "Load dictionary from `FILE` (required)",
			Aliases:  []string{"df"},
			Required: true,
		},
		&cli.StringFlag{
			Name:    "cipher",
			Aliases: []string{"c"},
			Usage:   "Use cipher `NAME`",
			Value:   "sha256",
		},
		&cli.BoolFlag{
			Name:  "cache",
			Usage: "Use digest cache",
		},
	},
	Action: func(c *cli.Context) error {
		ds, err := dataset.New(c.String("hash-file"))
		if err != nil {
			return err
		}

		fmt.Print("Loading dictionary... ")
		diT0 := time.Now()
		di, err := dictionary.New(c.String("dictionary-file"))
		if err != nil {
			return err
		}
		diT := time.Now().Sub(diT0)
		fmt.Printf("done. (%d words in %f seconds)\n", len(di.Words), diT.Seconds())

		cipher, err := cipherlib.NewSHA2(256)
		if err != nil {
			return err
		}

		var cache *digestcache.DigestCache = nil
		if c.Bool("cache") {
			cache = digestcache.New()
		}

		s := &dictionary.Strategy{
			Cipher: cipher,
			Cache:  cache,
		}

		report := &dictReport{}
		fmt.Println("Starting Dictionary attack...")
		for ds.HasNext() {
			item, err := ds.Next()
			if err != nil {
				return err
			}

			fmt.Printf("%s     ", shortHash(item.Hash))
			res := di.Crack(item.Hash, item.Salt, s)

			report.AddResult(res)
			if !res.Ok {
				fmt.Println("no match")
				continue
			}

			fmt.Printf("%s (%f s, %d tries)\n", res.Password, res.Duration.Seconds(), res.Tries)
		}
		fmt.Printf("Done in %.1f seconds.\n\n", report.Duration.Seconds())

		v := reflect.ValueOf(*s)
		typ := reflect.TypeOf(*s)
		for i := 0; i < v.NumField(); i++ {
			fmt.Printf("%-20s%v\n", typ.Field(i).Name, v.Field(i).Interface())
		}

		fmt.Printf("\n%-20s%d\n%-20s%.1f %s\n",
			"Words",
			len(di.Words),
			"Loading duration",
			diT.Seconds(),
			"s",
		)

		fmt.Printf("\n%-20s%d\n%-20s%d (%.1f %%)\n%-20s%d (%.1f %%)\n%-20s%.0f %s\n",
			"Processed",
			report.Processed,
			"Cracked",
			report.Ok,
			float64(report.Ok)/float64(report.Processed)*100,
			"...using cache",
			report.OkUsingCache,
			float64(report.OkUsingCache)/float64(report.Ok)*100,
			"Hash rate (avg)",
			float64(report.Tries)/report.Duration.Seconds(),
			"h/s",
		)
		return nil
	},
}
