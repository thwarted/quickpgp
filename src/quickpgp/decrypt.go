package quickpgp

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
	openpgperrors "golang.org/x/crypto/openpgp/errors"
	"hostutils"
)

var _ = hostutils.Display

func Decrypt(privateKeyFileName string, publicKeyFileName string, file string) (err error) {

	var signer openpgp.EntityList
	if signer, err = readPublicKeyFile(publicKeyFileName); err != nil {
		return err
	}

	var recipient *openpgp.Entity
	if recipient, err = readPrivateKeyFile(privateKeyFileName); err != nil {
		return err
	}
	if recipient == nil {
		return fmt.Errorf("quickpgp: unable to read %s", privateKeyFileName)
	}

	var keyring openpgp.EntityList
	keyring = append(keyring, signer[0])
	keyring = append(keyring, recipient)

	var cipherTextFile *os.File
	if cipherTextFile, err = os.Open(file); err != nil {
		return err
	}

	md, err := openpgp.ReadMessage(cipherTextFile, keyring, nil, nil)
	if err != nil {
		return err
	}

	var plainTextOutput *os.File
	// Should use temp file here
	// Then rename to either file (without .pgp extension) or
	//  use md.LiteralData.FileName
	outfile := strings.TrimSuffix(file, ".pgp")
	if plainTextOutput, err = os.Create(outfile + ".new"); err != nil {
		return err
	}
	_, err = io.Copy(plainTextOutput, md.UnverifiedBody)
	if err != nil {
		return err
	}
	if md.SignatureError != nil {
		// TODO cleanup tmp file
		return err
	}
	if md.Signature == nil {
		return openpgperrors.ErrUnknownIssuer
	}

	return nil
}
