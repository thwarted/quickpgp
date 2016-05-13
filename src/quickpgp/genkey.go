package quickpgp

import (
	"crypto"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"
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

func hashToHashId(h crypto.Hash) uint8 {
	v, ok := s2k.HashToHashId(h)
	if !ok {
		panic("tried to convert unknown hash")
	}
	return v
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
		id.SelfSignature.PreferredSymmetric = []uint8{
			uint8(packet.CipherAES128),
			uint8(packet.CipherAES256),
			uint8(packet.CipherAES192),
			uint8(packet.CipherCAST5),
		}
		id.SelfSignature.PreferredHash = []uint8{
			hashToHashId(crypto.RIPEMD160),
			hashToHashId(crypto.SHA256),
			hashToHashId(crypto.SHA384),
			hashToHashId(crypto.SHA512),
			hashToHashId(crypto.SHA224),
			hashToHashId(crypto.MD5),
		}
		id.SelfSignature.PreferredCompression = []uint8{
			uint8(packet.CompressionNone),
		}
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
