package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <private key>\n", os.Args[0])
		os.Exit(1)
	}

	privFile, err := os.Open(os.Args[1])
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

	stdinBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	var cipherReader io.Reader
	block, err := armor.Decode(bytes.NewReader(stdinBytes))
	switch err {
	default:
		log.Fatal(err)
	case nil:
		cipherReader = block.Body
	case io.EOF:
		cipherReader = bytes.NewReader(stdinBytes)
	}

	mesg, err := openpgp.ReadMessage(cipherReader, entityList, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	_, err = io.Copy(os.Stdout, mesg.UnverifiedBody)
	if err != nil {
		log.Fatal(err)
	}
}
