package quickpgp

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

var border = "----------"

func fingerprintString(fp []byte) (s string) {
	for grp := 0; grp < 10; grp += 2 {
		s += fmt.Sprintf("%X ", fp[grp:grp+2])
	}
	for grp := 10; grp < 20; grp += 2 {
		s += fmt.Sprintf(" %X", fp[grp:grp+2])
	}
	return s
}

func printHeader(f string) {
	fmt.Println(f)
	whole := int(len(f) / len(border))
	frac := int(len(f) % len(border))
	for ; whole > 0; whole-- {
		fmt.Printf(border)
	}
	fmt.Println(border[:frac])
}

func IdentifyKey(keyfile string) error {
	if handled, err := trySig(keyfile); handled == true {
		return err
	}
	kr, err := os.Open(keyfile)
	if err != nil {
		return err
	}
	keyring, err := openpgp.ReadArmoredKeyRing(kr)
	if err != nil {
		return err
	}

	printHeader(keyfile)

	for _, entity := range keyring {
		dumpKeyInfo(entity)
	}

	return nil
}

func dumpKeyInfo(entity *openpgp.Entity) {
	var bl uint16
	sec := entity.PrivateKey

	if sec != nil {
		bl, _ = sec.BitLength()
		fmt.Printf("%3s   %4d /%16s %s\n", "sec", bl, sec.KeyIdString(), sec.CreationTime.Format(time.RFC3339))
		fmt.Printf("%3s   Key fingerprint = %s\n", "", fingerprintString(sec.Fingerprint[:]))
		fmt.Println()
	}

	pub := entity.PrimaryKey
	bl, _ = pub.BitLength()
	fmt.Printf("%3s   %4d /%16s %s\n", "pub", bl, pub.KeyIdString(), pub.CreationTime.Format(time.RFC3339))
	fmt.Printf("%3s   Key fingerprint = %s\n", "", fingerprintString(pub.Fingerprint[:]))
	for _, identity := range entity.Identities {
		fmt.Printf("%3s   %4s  %16s %s\n", "uid", "", "", identity.Name)
	}
	for _, sk := range entity.Subkeys {
		subkey := sk.PublicKey
		bl, _ := subkey.BitLength()
		fmt.Printf("%3s   %4d /%16s %s\n", "sub", bl, subkey.KeyIdString(), subkey.CreationTime.Format(time.RFC3339))
	}
}

func trySig(filename string) (bool, error) {
	sigFile, err := os.Open(filename)
	if err != nil {
		return true, err
	}
	defer sigFile.Close()

	b, err := armor.Decode(sigFile)
	if err != nil && err != io.EOF {
		return true, err
	}
	if b == nil {
		return false, nil
	}

	// Read the signature file
	pack, err := packet.Read(b.Body)
	if err != nil {
		return true, err
	}

	// Was it really a signature file ? If yes, get the Signature
	if signature, ok := pack.(*packet.Signature); !ok {
		return false, nil
	} else {
		fmt.Printf("Signature made %s\n", signature.CreationTime.Format(time.RFC3339))
		// Signature made Wed 05 Aug 2015 11:48:13 PM UTC using RSA key ID F553000C
		// Primary key fingerprint: EF64 BCCB 58BC F501 FEDA  0582 0581 2930 F553 000C
		// binary signature, digest algorithm SHA256
		return true, nil
	}
}
