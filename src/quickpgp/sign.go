package quickpgp

import (
	"os"

	"golang.org/x/crypto/openpgp"
)

func Sign(privateKeyFileName string, fileToSign string, signatureFile string) (err error) {

	var signer *openpgp.Entity
	if signer, err = readPrivateKeyFile(privateKeyFileName); err != nil {
		return err
	}

	var message *os.File
	if message, err = os.Open(fileToSign); err != nil {
		return err
	}
	defer message.Close()

	var w *os.File
	if w, err = os.Create(signatureFile); err != nil {
		return err
	}
	defer w.Close()

	if err = openpgp.ArmoredDetachSign(w, signer, message, nil); err != nil {
		return err
	}
	w.Write([]byte("\n"))

	return nil
}
