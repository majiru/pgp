package main

import (
	"bytes"
	"flag"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"io"
	"io/ioutil"
	"os"
)

func exitOnError(err error, where string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR upon %s:\n%v\n", where, err)
		os.Exit(1)
	}
}

func main() {
	var privFile *os.File
	var err error

	var armor = flag.Bool("a", false, "armor")

	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-a] <private key file>\n", os.Args[0])
		os.Exit(0)
	}

	privFile, err = os.Open(flag.Arg(0))
	exitOnError(err, "opening private key")

	privBytes, err := ioutil.ReadAll(privFile)
	exitOnError(err, "reading private key file")

	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(privBytes))
	if err == io.EOF {
		entityList, err = openpgp.ReadKeyRing(bytes.NewBuffer(privBytes))
		exitOnError(err, "reading private key (decoding armor failed with EOF)")
	} else {
		exitOnError(err, "reading private key")
	}

	if *armor {
		err = openpgp.ArmoredDetachSign(os.Stdout, entityList[0], os.Stdin, nil)
	} else {
		err =openpgp.DetachSign(os.Stdout, entityList[0], os.Stdin, nil)
	}
	exitOnError(err, "signing data")
}
