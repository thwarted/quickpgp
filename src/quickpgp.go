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
	fmt.Println(`  Generate detached signature for <file> in <file>.sig.asc`)
	fmt.Println(`   ` + binname + ` sign <file> <private key file>`)
	fmt.Println()
	fmt.Println(`  Verify detached signature <file>.sig.asc for <file>`)
	fmt.Println(`   ` + binname + ` verify <file> <public key file>`)
	fmt.Println()
	fmt.Println(`  Generates key pair in <keyfilebase>.{key,pub}.asc`)
	fmt.Println(`   ` + binname + ` genkey <keyfilebase>`)
	fmt.Println(`   Uses envvars LOGNAME, COMMENT, and HOSTNAME to set the identity`)
	fmt.Println()
	fmt.Println(`  Display details of the given <keyfile>`)
	fmt.Println(`   ` + binname + ` identify <keyfile>`)
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
