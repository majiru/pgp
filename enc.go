package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func entityListFromPubKeyFilePaths(keyFilePaths []string) openpgp.EntityList {
	var entityList openpgp.EntityList
	entityList = []*openpgp.Entity{}

	for i := 0; i < len(keyFilePaths); i++ {
		pubFile, err := os.Open(keyFilePaths[i])
		exitOnError(err, "opening public key")

		pubBytes, err := ioutil.ReadAll(pubFile)
		exitOnError(err, fmt.Sprintf("reading from public key (%s)", keyFilePaths[i]))
		pubFile.Close()

		var pubReader *packet.Reader

		block, err := armor.Decode(bytes.NewReader(pubBytes))
		if err == nil {
			pubReader = packet.NewReader(block.Body)
		} else if err == io.EOF {
			pubReader = packet.NewReader(bytes.NewReader(pubBytes))
		} else {
			exitOnError(err, fmt.Sprintf("decoding armor for public key (%s)", keyFilePaths[i]))
		}

		pubEntity, err := openpgp.ReadEntity(pubReader)
		exitOnError(err, fmt.Sprintf("reading public key (%s)", keyFilePaths[i]))
		entityList = append(entityList, pubEntity)
	}

	return entityList
}

func exitOnError(err error, where string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR upon %s:\n%v\n", where, err)
		os.Exit(1)
	}
}

func main() {
	var err error

	armorFlag := len(os.Args) > 2 && os.Args[1] == "-a"
	if len(os.Args) < 3 && !(!armorFlag && len(os.Args) == 2) {
		fmt.Fprintln(os.Stderr, "Usage: pgp/enc [-a] <public keys>")
		os.Exit(1)
	}

	var entityList openpgp.EntityList
	if armorFlag {
		entityList = entityListFromPubKeyFilePaths(os.Args[2:])
	} else {
		entityList = entityListFromPubKeyFilePaths(os.Args[1:])
	}

	cipherBuffer := new(bytes.Buffer)
	cipherWriter, err := openpgp.Encrypt(cipherBuffer, entityList, nil, nil, nil)
	exitOnError(err, "opening encryption writer")

	plainBytes, err := ioutil.ReadAll(os.Stdin)
	exitOnError(err, "reading from stdin")

	_, err = cipherWriter.Write(plainBytes)
	exitOnError(err, "writing to encryption write")
	cipherWriter.Close()

	if armorFlag {
		armorWriter, err := armor.Encode(os.Stdout, "PGP MESSAGE", nil)
		exitOnError(err, "opening armor encoder")
		_, err = armorWriter.Write(cipherBuffer.Bytes())
		exitOnError(err, "error writing to armor encoder")
		err = armorWriter.Close()
		exitOnError(err, "error closing armor encoder")
	} else {
		_, err = os.Stdout.Write(cipherBuffer.Bytes())
		exitOnError(err, "error writing to stdout")
	}
}
