package quickpgp

import (
	"fmt"
	"io"
	"os"
	"path"

	"golang.org/x/crypto/openpgp"
)

func EncryptSign(privateKeyFileName string, publicKeyFileName string, fileToEnc string, outfile string) (err error) {

	var signer *openpgp.Entity
	if signer, err = readPrivateKeyFile(privateKeyFileName); err != nil {
		return err
	}

	var recipients openpgp.EntityList
	if recipients, err = readPublicKeyFile(publicKeyFileName); err != nil {
		return err
	}

	var input *os.File
	if input, err = os.Open(fileToEnc); err != nil {
		return err
	}
	defer input.Close()

	inputStat, err := input.Stat()
	if err != nil {
		return err
	}
	inputBytes := inputStat.Size()

	var output *os.File
	if output, err = os.Create(outfile); err != nil {
		return err
	}

	fHints := &openpgp.FileHints{
		IsBinary: true,
		FileName: path.Base(fileToEnc),
		ModTime: inputStat.ModTime(),
	}

	we, err := openpgp.Encrypt(output, recipients, signer, fHints, nil)
	if err != nil {
		return err
	}
	defer we.Close()

	copiedBytes, err := io.Copy(we, input)
	if copiedBytes != inputBytes {
		return fmt.Errorf("encrypted only %d bytes out of %d", copiedBytes, inputBytes)
	}
	return nil
}
