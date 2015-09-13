package quickpgp

import (
	"os"

	"golang.org/x/crypto/openpgp"
	"hostutils"
)

func Decrypt(privateKeyFileName string, publicKeyFileName string, file string) (err error) {

	var signer openpgp.EntityList
	if signer, err = readPublicKeyFile(publicKeyFileName); err != nil {
		return err
	}

	var recipients openpgp.EntityList
	if recipients, err = readPublicKeyFile(publicKeyFileName); err != nil {
		return err
	}

	keyring := append(recipients, signer[0])

	var cipherTextFile *os.File
	if cipherTextFile, err = os.Open(file); err != nil {
		return err
	}

	md, err := openpgp.ReadMessage(cipherTextFile, keyring, nil, nil)
	if err != nil {
		return err
	}
	hostutils.Display("md", md)

	return nil
}
