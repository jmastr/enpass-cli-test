package enpasscli

import (
	"bufio"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"os"
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
func (v *Vault) extractSalt(databasePath string) (bytesSalt []byte, err error) {
	f, err := os.Open(databasePath)
	if err != nil {
		return []byte{}, err
	}
	defer f.Close()

	bytesSalt, err = bufio.NewReader(f).Peek(saltLength)
	if err != nil {
		return []byte{}, err
	}

	return bytesSalt, err
}

// deriveKey : generate the SQLCipher crypto key, possibly with the 64-bit Keyfile
func (v *Vault) deriveKey(masterPassword []byte, salt []byte) (resultKey string, err error) {
	if v.vaultInfo.KDFAlgo != keyDerivationAlgo {
		return "", errors.New("key derivation algo has changed, open up a github issue")
	}

	if v.vaultInfo.EncryptionAlgo != dbEncryptionAlgo {
		return "", errors.New("database encryption algo has changed, open up a github issue")
	}

	// PBKDF2- HMAC-SHA256
	key := pbkdf2.Key(masterPassword, salt, v.vaultInfo.KDFIterations, sha512.Size, sha512.New)

	hexKey := make([]byte, hex.EncodedLen(sha512.Size))
	hex.Encode(hexKey, key)

	return string(hexKey)[:masterKeyLength], nil
}
