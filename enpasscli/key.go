package enpasscli

import (
	"bufio"
	"crypto/sha512"
	"os"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// current key derivation algo
	keyDerivationAlgo = "pbkdf2"
	// current database encryption algo
	dbEncryptionAlgo = "aes-256-cbc"
	// database key salt length
	saltLength = 16
	// length of the database master key (capped)
	masterKeyLength = 64
)

// extractSalt : extract the encryption salt stored in the database
func (v *Vault) extractSalt(databasePath string) ([]byte, error) {
	f, err := os.OpenFile(databasePath, os.O_RDONLY, 0)
	if err != nil {
		return []byte{}, errors.Wrap(err, "could not open database")
	}
	defer f.Close()

	bytesSalt, err := bufio.NewReader(f).Peek(saltLength)
	if err != nil {
		return []byte{}, errors.Wrap(err, "could not read database salt")
	}

	return bytesSalt, nil
}

// deriveKey : generate the SQLCipher crypto key, possibly with the 64-bit Keyfile
func (v *Vault) deriveKey(masterPassword []byte, salt []byte) ([]byte, error) {
	if v.vaultInfo.KDFAlgo != keyDerivationAlgo {
		return nil, errors.New("key derivation algo has changed, open up a github issue")
	}

	if v.vaultInfo.EncryptionAlgo != dbEncryptionAlgo {
		return nil, errors.New("database encryption algo has changed, open up a github issue")
	}

	// PBKDF2- HMAC-SHA256
	return pbkdf2.Key(masterPassword, salt, v.vaultInfo.KDFIterations, sha512.Size, sha512.New), nil
}
