package main

import (
	"crypto"
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func main() {
	log.SetFlags(0)
	var name = flag.String("n", "", "Full name")
	var comment = flag.String("c", "", "Comment")
	var mail = flag.String("m", "", "E-Mail address")

	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-m <mail>] [-n <full name>] [-c <comment>] <key file name>\n", os.Args[0])
		os.Exit(1)
	}
	keyname := flag.Arg(0)

	cfg := &packet.Config{
		DefaultHash: crypto.SHA256,
	}

	keyPair, err := openpgp.NewEntity(*name, *comment, *mail, cfg)
	if err != nil {
		log.Fatal(err)
	}

	// sign all key identities
	for _, id := range keyPair.Identities {
		err = id.SelfSignature.SignUserId(id.UserId.Id, keyPair.PrimaryKey, keyPair.PrivateKey, nil)
		if err != nil {
			log.Fatal(err)
		}
	}

	pub, err := os.Create(keyname + ".pub")
	if err != nil {
		log.Fatal(err)
	}

	armorWriter, err := armor.Encode(pub, openpgp.PublicKeyType, nil)
	if err != nil {
		log.Fatal(err)
	}

	err = keyPair.Serialize(armorWriter)
	if err != nil {
		log.Fatal(err)
	}
	armorWriter.Close()
	pub.Close()

	priv, err := os.Create(keyname + ".priv")
	if err != nil {
		log.Fatal(err)
	}

	armorWriter, err = armor.Encode(priv, openpgp.PrivateKeyType, nil)
	if err != nil {
		log.Fatal(err)
	}

	err = keyPair.SerializePrivate(armorWriter, nil)
	if err != nil {
		log.Fatal(err)
	}
	armorWriter.Close()
	priv.Close()
}
