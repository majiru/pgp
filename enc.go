package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func entityListFromPubKeyFilePaths(keyFilePaths ...string) (openpgp.EntityList, error) {
	entityList := []*openpgp.Entity{}

	for _, k := range keyFilePaths {
		pubFile, err := os.Open(k)
		if err != nil {
			return nil, err
		}

		var pubReader *packet.Reader
		block, err := armor.Decode(pubFile)
		switch err {
		default:
			return nil, err
		case io.EOF:
			pubFile.Seek(0, io.SeekStart)
			pubReader = packet.NewReader(pubFile)
		case nil:
			pubReader = packet.NewReader(block.Body)
		}

		pubEntity, err := openpgp.ReadEntity(pubReader)
		if err != nil {
			return nil, err
		}
		entityList = append(entityList, pubEntity)
	}

	return entityList, nil
}

func main() {
	var armorFlag = flag.Bool("a", false, "armor")
	log.SetFlags(0)

	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-a] <public keys>\n", os.Args[0])
		os.Exit(1)
	}

	entityList, err := entityListFromPubKeyFilePaths(flag.Args()...)
	if err != nil {
		log.Fatal(err)
	}

	cipherBuf := new(bytes.Buffer)
	cipherWriter, err := openpgp.Encrypt(cipherBuf, entityList, nil, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	_, err = io.Copy(cipherWriter, os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	cipherWriter.Close()

	if *armorFlag {
		armorWriter, err := armor.Encode(os.Stdout, "PGP MESSAGE", nil)
		if err != nil {
			log.Fatal(err)
		}

		_, err = armorWriter.Write(cipherBuf.Bytes())
		if err != nil {
			log.Fatal(err)
		}
		armorWriter.Close()
	} else {
		_, err = os.Stdout.Write(cipherBuf.Bytes())
		if err != nil {
			log.Fatal(err)
		}
	}
}
