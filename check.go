package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <signature file> <public key file>\n", os.Args[0])
		os.Exit(0)
	}

	sigFile, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer sigFile.Close()

	pubFile, err := os.Open(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	defer pubFile.Close()

	var pubReader *packet.Reader

	block, err := armor.Decode(pubFile)
	switch err {
	default:
		log.Fatal(err)
	case nil:
		pubReader = packet.NewReader(block.Body)
	case io.EOF:
		pubFile.Seek(0, io.SeekStart)
		pubReader = packet.NewReader(pubFile)
	}

	pubEntity, err := openpgp.ReadEntity(pubReader)
	if err != nil {
		log.Fatal(err)
	}

	entityList := openpgp.EntityList{pubEntity}
	_, err = openpgp.CheckArmoredDetachedSignature(entityList, os.Stdin, sigFile)
	if err == io.EOF {
		sigFile.Seek(0, io.SeekStart)
		_, err = openpgp.CheckDetachedSignature(entityList, os.Stdin, sigFile)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Message is signed with provided public key")
}
