package quickpgp

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/openpgp"
	openpgperrors "golang.org/x/crypto/openpgp/errors"
)

func Decrypt(privateKeyFileName string, publicKeyFileName string, file string) (err error) {

	if filepath.Ext(file) != ".pgp" {
		return fmt.Errorf("quickpgp: filename to decrypt must end in .pgp")
	}

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

	var cwd string
	if cwd, err = os.Getwd(); err != nil {
		return err
	}
	var plainTextOutput *os.File
	if plainTextOutput, err = ioutil.TempFile(cwd, ".quickpgp."); err != nil {
		return err
	}
	var cleanExit bool
	defer func() {
		if !cleanExit {
			_ = os.Remove(plainTextOutput.Name())
		}
	}()

	_, err = io.Copy(plainTextOutput, md.UnverifiedBody)
	if err != nil {
		return err
	}
	plainTextOutput.Close()
	if md.SignatureError != nil {
		return err
	}
	if md.Signature == nil {
		return openpgperrors.ErrUnknownIssuer
	}

	bareFilename := strings.TrimSuffix(file, filepath.Ext(file))
	if len(md.LiteralData.FileName) != 0 && md.LiteralData.FileName != bareFilename {
		fmt.Fprintf(os.Stderr, "quickpgp: suggested filename \"%s\"\n", md.LiteralData.FileName)
	}
	var finalFilename string
	if _, err := os.Stat(bareFilename); os.IsNotExist(err) {
		finalFilename = bareFilename
	} else {
		finalFilename = fmt.Sprintf("%s.%X", bareFilename, uint32(md.SignedByKeyId&0xffffffff))
		fmt.Fprintf(os.Stderr, "quickpgp: \"%s\" exists, writing to \"%s\"\n", bareFilename, finalFilename)
	}

	err = os.Rename(plainTextOutput.Name(), finalFilename)
	if err == nil {
		cleanExit = true
	}
	return err
}
