package main

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
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

	armorFlag := len(os.Args) == 3 && os.Args[1] == "-a"
	if len(os.Args) != 2 && !armorFlag {
		fmt.Fprintln(os.Stderr, "Usage: pgp/dec [-a] <private key>")
		os.Exit(1)
	}

	if armorFlag {
		privFile, err = os.Open(os.Args[2])
	} else {
		privFile, err = os.Open(os.Args[1])
	}
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

	stdinBytes, err := ioutil.ReadAll(os.Stdin)
	exitOnError(err, "reading stdin")

	var cipherReader io.Reader
	cipherReader = bytes.NewReader(stdinBytes)
	block, err := armor.Decode(cipherReader)
	if err == nil {
		cipherReader = block.Body
	} else if err == io.EOF {
		cipherReader = bytes.NewReader(stdinBytes)
	} else {
		exitOnError(err, "decoding message armor")
	}

	mesg, err := openpgp.ReadMessage(cipherReader, entityList, nil , nil)
	exitOnError(err, "decrypting message")

	bytes, err := ioutil.ReadAll(mesg.UnverifiedBody)
	exitOnError(err, "reading decrypted message")

	_, err = os.Stdout.Write(bytes)
	exitOnError(err, "writing to stdout")
}
