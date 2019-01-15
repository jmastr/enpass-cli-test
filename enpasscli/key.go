package enpasscli

import (
	"crypto/sha256"
	"errors"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// current key derivation algo
	keyDerivationAlgo = "pbkdf2"
	// current database encryption algo
	dbEncryptionAlgo = "aes-256-cbc"
	// AES-256
	masterKeyLength = 32
)

// deriveKey : generate the SQLCipher crypto key, possibly with the 64-bit Keyfile
func (v *Vault) deriveKey(masterPassword []byte, keyFile []byte) (dk []byte, err error) {
	if v.vaultInfo.KDFAlgo != keyDerivationAlgo {
		return nil, errors.New("key derivation algo has changed, open up a github issue")
	}

	if v.vaultInfo.EncryptionAlgo != dbEncryptionAlgo {
		return nil, errors.New("database encryption algo has changed, open up a github issue")
	}

	// PBKDF2- HMAC-SHA256
	return pbkdf2.Key(masterPassword, keyFile, v.vaultInfo.KDFIterations, masterKeyLength, sha256.New), nil
}
