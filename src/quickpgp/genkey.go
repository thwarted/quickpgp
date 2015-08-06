package quickpgp

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func entityData() (name string, comment string, email string) {
	name = os.Getenv("LOGNAME")
	comment = os.Getenv("COMMENT")
	email = fmt.Sprintf("%s@%s", name, os.Getenv("HOSTNAME"))
	return
}

func isExistingDirectory(p string) bool {
	s, err := os.Stat(p)
	if err != nil {
		return false
	}
	return s.Mode().IsDir()
}

func GenerateKey(keyFileBase string) (err error) {
	if len(keyFileBase) == 0 {
		return errors.New("key file basename must not be emtpy")
	}
	if isExistingDirectory(keyFileBase) {
		return errors.New("key file basename must not be a directory")
	}

	var f *os.File
	var e *openpgp.Entity
	name, comment, email := entityData()
	e, err = openpgp.NewEntity(name, comment, email, nil)
	if err != nil {
		return err
	}
	for _, id := range e.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, nil)
		if err != nil {
			return err
		}
	}

	f, err = os.Create(keyFileBase + ".key.asc")
	if err != nil {
		return err
	}
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	w, err := armor.Encode(f, openpgp.PrivateKeyType, nil)
	if err != nil {
		return err
	}
	e.SerializePrivate(w, nil)
	w.Close()
	f.Write([]byte{'\n'})

	f, err = os.Create(keyFileBase + ".pub.asc")
	if err != nil {
		return err
	}
	defer f.Close()
	w, err = armor.Encode(f, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	e.Serialize(w)
	w.Close()
	f.Write([]byte{'\n'})

	return nil
}
