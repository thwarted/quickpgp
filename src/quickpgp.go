package main

import (
	"fmt"
	"os"
	"path"

	"quickpgp"
)

func usage(binname string) {
	fmt.Println("Usage: " + binname + " <operation> <arg> ...")
	binname = path.Base(binname)
	fmt.Println(`
Generate detached signature for <file> in <file>.sig.asc
   ` + binname + ` sign <file> <private key file>

Verify detached signature <file>.sig.asc for <file>
   ` + binname + ` verify <file> <public key file>

Generates key pair in <keyfilebase>.{key,pub}.asc
   ` + binname + ` genkey <keyfilebase>
   Uses envvars LOGNAME, COMMENT, and HOSTNAME to set the identity

Display details of the given <keyfile>
   ` + binname + ` identify <keyfile>

View the license
   ` + binname + ` license
`)
}

func printError(err error) {
	if err == nil {
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "%s: %s\n", path.Base(os.Args[0]), err)
	os.Exit(1)
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
			printError(quickpgp.Sign(keyfile, ifile, ifile+".sig.asc"))
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
`)
    os.Exit(0)
}

