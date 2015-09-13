package quickpgp

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/openpgp"
	"hostutils"
)

func readPrivateKeyFile(filename string) (signer *openpgp.Entity, err error) {
	var krpriv *os.File

	if krpriv, err = os.Open(filename); err != nil {
		return nil, err
	}
	defer krpriv.Close()

	entityList, err := openpgp.ReadArmoredKeyRing(krpriv)
	if err != nil {
		return nil, err
	}
	if len(entityList) != 1 {
		return nil, errors.New("private key file must contain only one key")
	}
	signer = entityList[0]
	if signer.PrivateKey == nil {
		return nil, fmt.Errorf("%s does not contain a private key", filename)
	}
	if signer.PrivateKey.Encrypted {
		prompt := fmt.Sprintf("Passphrase to decrypt %s: ", filename)
		var pass []byte
		if pass, err = hostutils.ReadPassword(prompt, 0); err == nil {
			err = signer.PrivateKey.Decrypt(pass)
		}
	}
	return signer, err
}

func readPublicKeyFile(filename string) (openpgp.EntityList, error) {
	krpub, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	recipients, err := openpgp.ReadArmoredKeyRing(krpub)
	if err != nil {
		return nil, err
	}
	return recipients, nil
}
