# OpenPGP client written in Go

A simple OpenPGP client written in Go which consists of multiple executables for usage within a Plan 9 environment, but maybe used elsewhere of course.

## dec.go

Given private key, decrypts cipher text from stdin and writes it to stdout:
`pgp/dec <private key>`

## enc.go

Given one or more public keys, encrypts plain text from stdin and writes [armored] cipher text to stdout:
`pgp/enc [-a] <public keys>`

## gen.go

Generates a new public/private PGP key pair. For encryption/decryption and signing/verifying.
Creates `<keyname>.pub` and `<keyname>.priv` in working directory.
`pgp/gen [-n <fullname>] [-c <comment>] [-m <mail address>] <keyname>`

## check.go

Given a signature and public key, verifies detached signature against stdin.
`pgp/check <sig file> <public key>`

## sign.go

Given a private key, writes [armored] detached signature to stdout.
`pgp/sign [-a] <private key>`

# TODO
* Better error messages
* Man page
