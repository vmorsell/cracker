# Cracker

`cracker` is a command line tool for demonstrating offline Brute Force and Dictionary attacks.

## Getting started

### Requirements

Cracker needs Go to run. Install using the [official instructions](https://golang.org/doc/install).

### Installation

The quickest way to install Cracker is using the `go get` command:

```
$ go get -u -v github.com/vmorsell/cracker
```

## Usage

All commands has the following structure:

```
$ cracker <command> [command options]
```

For example, the following command attempts to crack the hashes in the file `db.csv` using brute force. The guessed passphrases can have numbers and lowercase letters, and a max length of `5`:

```
$ cracker bf --hf db.csv --lc --n --max 5
```

### Documentation

To view available commands and general help:

```
$ cracker --help
```

To view documentation for a specific command:

```
$ cracker <command> --help
```
