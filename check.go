package main

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
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
	var pubFile *os.File
	var err error

	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <signature file> <public key file>\n", os.Args[0])
		os.Exit(0)
	}

	sigFile, err := os.Open(os.Args[1])
	exitOnError(err, "opening signature file")
	sigBytes, err := ioutil.ReadAll(sigFile)
	exitOnError(err, "reading stdin")

	var entityList openpgp.EntityList
	entityList = []*openpgp.Entity{}

	pubFile, err = os.Open(os.Args[2])
	exitOnError(err, "opening public key")

	pubBytes, err := ioutil.ReadAll(pubFile)
	exitOnError(err, fmt.Sprintf("reading from public key"))
	pubFile.Close()

	var pubReader *packet.Reader

	block, err := armor.Decode(bytes.NewReader(pubBytes))
	if err == nil {
		pubReader = packet.NewReader(block.Body)
	} else if err == io.EOF {
		pubReader = packet.NewReader(bytes.NewReader(pubBytes))
	} else {
		exitOnError(err, fmt.Sprintf("decoding public key"))
	}

	pubEntity, err := openpgp.ReadEntity(pubReader)
	exitOnError(err, fmt.Sprintf("reading entity from public key"))
	entityList = append(entityList, pubEntity)

	stdinBytes, err := ioutil.ReadAll(os.Stdin)
	exitOnError(err, "reading stdin")


	signer, err := openpgp.CheckArmoredDetachedSignature(entityList, bytes.NewReader(stdinBytes), bytes.NewReader(sigBytes))
	if err == io.EOF {
		signer, err = openpgp.CheckDetachedSignature(entityList, bytes.NewReader(stdinBytes), bytes.NewReader(sigBytes))
		exitOnError(err, "verifying data")
	} else {
		exitOnError(err, "verifying armored data")
	}
	fmt.Println(signer)
}
