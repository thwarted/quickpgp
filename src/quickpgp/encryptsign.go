package quickpgp

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/openpgp"
	"hostutils"
)

func EncryptSign(privateKeyFileName string, publicKeyFileName string, fileToEnc string, outfile string) error {

	krpriv, err := os.Open(privateKeyFileName)
	if err != nil {
		return err
	}
	defer krpriv.Close()
	entityList, err := openpgp.ReadArmoredKeyRing(krpriv)
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

	krpub, err := os.Open(publicKeyFileName)
	if err != nil {
		return err
	}
	recipients, err := openpgp.ReadArmoredKeyRing(krpub)
	if err != nil {
		return err
	}

	message, err := os.Open(fileToEnc)
	if err != nil {
		return err
	}
	defer message.Close()

	messageStat, err := message.Stat()
	if err != nil {
		return err
	}
	messageBytes := messageStat.Size()

	encryptToFile, err := os.Create(outfile)
	if err != nil {
		return err
	}

	we, err := openpgp.Encrypt(encryptToFile, recipients, signer, nil, nil)
	if err != nil {
		return err
	}
	defer we.Close()

	copiedBytes, err := io.Copy(we, message)
	if copiedBytes != messageBytes {
		return fmt.Errorf("only copied %d bytes out of %d", copiedBytes, messageBytes)
	}
	return nil
}
