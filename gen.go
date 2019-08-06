package main

import (
	"crypto"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func exitOnError(err error, where string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR upon %s:\n%v\n", where, err)
		os.Exit(1)
	}
}

func main() {
	var name = flag.String("n", "", "Full name")
	var comment = flag.String("c", "", "Comment")
	var mail = flag.String("m", "", "E-Mail address")
	var keyname string
	var help = flag.Bool("help", false, "View this help message and exit.")

	flag.Parse()
	if *help || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage: pgp/gen [-m <mail>] [-n <full name>] [-c <comment>] <key file name>")
		os.Exit(1)
	}
	keyname = flag.Arg(0)

	cfg := &packet.Config{
		DefaultHash: crypto.SHA256,
	}

	var keyPair *openpgp.Entity
	keyPair, err := openpgp.NewEntity(*name, *comment, *mail, cfg)
	exitOnError(err, "creating key pair")

	// sign all key identities
	for _, id := range keyPair.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, keyPair.PrimaryKey, keyPair.PrivateKey, nil)
		exitOnError(err, "signing identity")
	}

	pub, err := os.Create(keyname + ".pub")
	exitOnError(err, "creating public key file")

	armorWriter, err := armor.Encode(pub, openpgp.PublicKeyType, nil)
	exitOnError(err, "opening public armor encoder")

	err = keyPair.Serialize(armorWriter)
	exitOnError(err, "serializing public key")
	err = armorWriter.Close()
	exitOnError(err, "closing public armor encoder")
	err = pub.Close()
	exitOnError(err, "closing public key file")

	priv, err := os.Create(keyname + ".priv")
	exitOnError(err, "creating private key file")

	armorWriter, err = armor.Encode(priv, openpgp.PrivateKeyType, nil)
	exitOnError(err, "opening private armor encoder")

	err = keyPair.SerializePrivate(armorWriter, nil)
	exitOnError(err, "serializing private key")
	err = armorWriter.Close()
	exitOnError(err, "closing private armor encoder")
	err = priv.Close()
	exitOnError(err, "closing private key file")
}
