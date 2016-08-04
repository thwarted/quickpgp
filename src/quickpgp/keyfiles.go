package quickpgp

import (
	"fmt"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

type readPasswordCallback func(filename string) (pass []byte, err error)

func readPrivateKeyFile(filename string, passPrompt readPasswordCallback) (e *openpgp.Entity, err error) {
	var krpriv *os.File

	if krpriv, err = os.Open(filename); err != nil {
		return nil, err
	}
	defer krpriv.Close()

	var entityList openpgp.EntityList

	keyFileReader := openpgp.ReadKeyRing
	if _, err = armor.Decode(krpriv); err == nil {
		keyFileReader = openpgp.ReadArmoredKeyRing
	}

	if _, err = krpriv.Seek(0, 0); err != nil {
		return nil, err
	}
	if entityList, err = keyFileReader(krpriv); err != nil {
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

func readPublicKeyFile(filename string) (entityList openpgp.EntityList, err error) {
	var krpub *os.File

	if krpub, err = os.Open(filename); err != nil {
		return nil, err
	}
	defer krpub.Close()

	keyFileReader := openpgp.ReadKeyRing
	if _, err = armor.Decode(krpub); err == nil {
		keyFileReader = openpgp.ReadArmoredKeyRing
	}

	if _, err = krpub.Seek(0, 0); err != nil {
		return nil, err
	}
	if entityList, err = keyFileReader(krpub); err != nil {
		return nil, fmt.Errorf("reading %s: %s", filename, err)
	}
	return entityList, nil
}
