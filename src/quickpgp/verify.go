package quickpgp

import (
	"fmt"
	"os"

	"golang.org/x/crypto/openpgp"
)

func Verify(publicKeyFileName string, fileToVerify string, sigFileName string) error {
	signed, err := os.Open(fileToVerify)
	if err != nil {
		return err
	}
	defer signed.Close()

	kr, err := os.Open(publicKeyFileName)
	if err != nil {
		return err
	}
	keyring, err := openpgp.ReadArmoredKeyRing(kr)
	if err != nil {
		return err
	}

	signature, err := os.Open(sigFileName)
	if err != nil {
		return err
	}
	defer signature.Close()

	signer, err := openpgp.CheckArmoredDetachedSignature(keyring, signed, signature)
	if err != nil {
		return err
	}
	for _, identity := range signer.Identities {
		fmt.Fprintf(os.Stderr, "Good signature from \"%s\"\n", identity.Name)
	}

	return nil
}
