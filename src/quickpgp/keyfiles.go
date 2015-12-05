package quickpgp

import (
	"fmt"
	"os"

	"golang.org/x/crypto/openpgp"
	"hostutils"
)

func readPrivateKeyFile(filename string) (e *openpgp.Entity, err error) {
	var krpriv *os.File

	if krpriv, err = os.Open(filename); err != nil {
		return nil, err
	}
	defer krpriv.Close()

	entityList, err := openpgp.ReadArmoredKeyRing(krpriv)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %s", filename, err)
	}
	if len(entityList) != 1 {
		return nil, fmt.Errorf("%s must contain only one key", filename)
	}
	e = entityList[0]
	if e.PrivateKey == nil {
		return nil, fmt.Errorf("%s does not contain a private key", filename)
	}
	if e.PrivateKey.Encrypted {
		prompt := fmt.Sprintf("Passphrase to decrypt %s: ", filename)
		var pass []byte
		if pass, err = hostutils.ReadPassword(prompt, 0); err == nil {
			err = e.PrivateKey.Decrypt(pass)
		}
	}
	return e, err
}

func readPublicKeyFile(filename string) (openpgp.EntityList, error) {
	krpub, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	e, err := openpgp.ReadArmoredKeyRing(krpub)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %s", filename, err)
	}
	return e, nil
}
