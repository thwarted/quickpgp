package quickpgp

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/openpgp"
	"hostutils"
)

func Sign(privateKeyFileName string, fileToSign string, signatureFile string) error {
	message, err := os.Open(fileToSign)
	if err != nil {
		return err
	}
	defer message.Close()

	w, err := os.Create(signatureFile)
	if err != nil {
		return err
	}

	kr, err := os.Open(privateKeyFileName)
	if err != nil {
		return err
	}
	defer kr.Close()
	entityList, err := openpgp.ReadArmoredKeyRing(kr)
	if err != nil {
		return err
	}
	if len(entityList) != 1 {
		return errors.New("private key file must contain only the key to sign with")
	}
	signer := entityList[0]
	if signer.PrivateKey.Encrypted {
		prompt := fmt.Sprintf("Passphrase to decrypt %s: ", privateKeyFileName)
		pass, err := hostutils.ReadPassword(prompt, 0)
		if err != nil {
			return err
		}
		err = signer.PrivateKey.Decrypt(pass)
		if err != nil {
			return err
		}
	}

	if err := openpgp.ArmoredDetachSign(w, signer, message, nil); err != nil {
		return err
	}
	w.Write([]byte("\n"))

	return nil
}
