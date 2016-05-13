package main

import (
	"fmt"
	"os"
	"path"

	"hostutils"
	"quickpgp"
)

func usage(binname string) {
	fmt.Println("Usage: " + binname + " <operation> <arg> ...")
	binname = path.Base(binname)
	fmt.Println(`
` + binname + ` sign <file> <private key file>
    Generate detached signature for <file> in <file>.sig.asc

` + binname + ` verify <file> <public key file>
    Verify detached signature <file>.sig.asc for <file>

` + binname + ` encryptsign <file> <private key file> <public key file>
    Encrypt <file> with (recipient) <public key file>, sign with
    (signer) <private key file>, output to <file>.pgp

` + binname + ` decrypt <file> <private key file> <public key file>
    Decrypt <file> with (recipient) <private key file> and verify
    its signature with (signer) <public key file>.
    <file> must have the extension .pgp and the output will be written to
    the filename hint if set, otherwise <file> without the .pgp extension

` + binname + ` genkey <keyfilebase>
    Generates key pair in <keyfilebase>.{key,pub}.asc
    Uses envvars LOGNAME, COMMENT, and HOSTNAME to set the identity

` + binname + ` identify <keyfile>
    Display details of the given <keyfile>

` + binname + ` license
    View the license
`)
}

func printError(err error) {
	if err == nil {
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "%s: %s\n", path.Base(os.Args[0]), err)
	os.Exit(1)
}

func readPassword(filename string) (pass []byte, err error) {
	prompt := fmt.Sprintf("Passphrase to decrypt %s: ", filename)
	pass, err = hostutils.ReadPassword(prompt, 0)
	return
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Args[0])
		os.Exit(1)
	}

	action := os.Args[1]

	switch action {
	case "license":
		printLicense()
	case "sign":
		if len(os.Args) == 4 {
			ifile := os.Args[2]
			keyfile := os.Args[3]
			printError(quickpgp.Sign(keyfile, readPassword, ifile, ifile+".sig.asc"))
		}
	case "encryptsign":
		if len(os.Args) == 5 {
			ifile := os.Args[2]
			keyfile := os.Args[3]
			pubfile := os.Args[4]
			printError(quickpgp.EncryptSign(keyfile, readPassword, pubfile, ifile, ifile+".pgp"))
		}
	case "decrypt":
		if len(os.Args) == 5 {
			ifile := os.Args[2]
			keyfile := os.Args[3]
			pubfile := os.Args[4]
			printError(quickpgp.Decrypt(keyfile, readPassword, pubfile, ifile))
		}
	case "verify":
		if len(os.Args) == 4 {
			ifile := os.Args[2]
			keyfile := os.Args[3]
			printError(quickpgp.Verify(keyfile, ifile, ifile+".sig.asc"))
		}
	case "genkey":
		if len(os.Args) == 3 {
			keyfilebase := os.Args[2]
			printError(quickpgp.GenerateKey(keyfilebase))
		}
	case "identify":
		if len(os.Args) == 3 {
			keyfile := os.Args[2]
			printError(quickpgp.IdentifyKey(keyfile))
		}
	}
	usage(os.Args[0])
	os.Exit(1)
}

func printLicense() {
	fmt.Println(`
The MIT License (MIT)

Copyright (c) 2015 Andrew Bakun

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Additional portions Copyright (c) 2009 The Go Authors. All rights reserved.
`)
	os.Exit(0)
}
