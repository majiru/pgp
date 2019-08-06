package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/openpgp"
)

func main() {
	var armor = flag.Bool("a", false, "armor")
	log.SetFlags(0)

	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-a] <private key file>\n", os.Args[0])
		os.Exit(0)
	}

	privFile, err := os.Open(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	entityList, err := openpgp.ReadArmoredKeyRing(privFile)
	if err == io.EOF {
		privFile.Seek(0, io.SeekStart)
		entityList, err = openpgp.ReadKeyRing(privFile)
	}
	if err != nil {
		log.Fatal(err)
	}

	if *armor {
		err = openpgp.ArmoredDetachSign(os.Stdout, entityList[0], os.Stdin, nil)
	} else {
		err = openpgp.DetachSign(os.Stdout, entityList[0], os.Stdin, nil)
	}
	if err != nil {
		log.Fatal(err)
	}
}
