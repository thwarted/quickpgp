package quickpgp

import (
	"fmt"
	"os"

	"golang.org/x/crypto/openpgp"
)

type readPasswordCallback func(filename string) (pass []byte, err error)

func readPrivateKeyFile(filename string, passPrompt readPasswordCallback) (e *openpgp.Entity, err error) {
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
		if passPrompt != nil {
			var pass []byte
			if pass, err = passPrompt(filename); err == nil {
				err = e.PrivateKey.Decrypt(pass)
			}
		} else {
			return nil, fmt.Errorf("%s is encrypted", filename)
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
