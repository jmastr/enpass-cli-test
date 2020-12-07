package enpasscli

import (
	"crypto/aes"
	cryptocipher "crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"path/filepath"

	_ "github.com/mutecomm/go-sqlcipher/v4"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// contains info about your vault
	vaultInfoFileName = "vault.json"
	// PBKDF iterations for row key
	rowKeyIterations = 2
)

type Vault struct {
	// vault.enpassdb : SQLCipher database
	databaseFilename string

	// vault.json
	vaultInfoFilename string

	// <uuid>.enpassattach : SQLCipher database files for attachments >1KB
	attachments []string

	// pointer to our opened database
	db *sql.DB

	// vault.json : contains info about your vault for synchronizing
	vaultInfo VaultInfo
}

func (v *Vault) openEncryptedDatabase(path string, dbKey []byte) (err error) {
	dbName := fmt.Sprintf(
		"%s?_pragma_key=x'%s'&_pragma_cipher_page_size=4096&_pragma_cipher_compatibility=3",
		path,
		hex.EncodeToString(dbKey),
	)

	v.db, err = sql.Open("sqlite3", dbName)
	if err != nil {
		return errors.Wrap(err, "could not open database")
	}

	return nil
}

func generateMasterPassword(password []byte, keyfilePath string) ([]byte, error) {
	if keyfilePath == "" {
		if password == nil || len(password) == 0 {
			return nil, errors.New("empty master password provided")
		}

		return password, nil
	}

	// TODO: implement keyfile
	return nil, errors.New("keyfile not implemented yet")
}

func OpenVault(databasePath string, keyfilePath string, password []byte) (Vault, error) {
	vault := Vault{
		databaseFilename:  databasePath,
		vaultInfoFilename: filepath.Join(filepath.Dir(databasePath), vaultInfoFileName),
	}

	vaultInfo, err := loadVaultInfo(vault.vaultInfoFilename)
	if err != nil {
		return Vault{}, err
	}

	vault.vaultInfo = vaultInfo

	if keyfilePath == "" && vaultInfo.HasKeyfile == 1 {
		return Vault{}, errors.New("you should specify a keyfile")
	} else if keyfilePath != "" && vaultInfo.HasKeyfile == 0 {
		return Vault{}, errors.New("you are not currently using a keyfile")
	}

	masterPassword, err := generateMasterPassword(password, keyfilePath)
	if err != nil {
		return Vault{}, errors.Wrap(err, "could not generate vault unlock key")
	}

	keySalt, err := vault.extractSalt(databasePath)
	if err != nil {
		return Vault{}, errors.Wrap(err, "could not get master password salt")
	}

	fullKey, err := vault.deriveKey(masterPassword, keySalt)
	if err != nil {
		return Vault{}, errors.Wrap(err, "could not derive master key from master password")
	}

	if err := vault.openEncryptedDatabase(databasePath, fullKey); err != nil {
		return Vault{}, errors.Wrap(err, "could not open vault")
	}

	return vault, nil
}

func (v *Vault) Close() {
	v.db.Close()
}

func (v *Vault) generateRowKey(hash []byte, salt []byte) []byte {
	// PBKDF2- HMAC-SHA256
	return pbkdf2.Key(hash, salt, rowKeyIterations, sha256.Size, sha256.New)
}

func (v *Vault) getCryptoParameters() (iv []byte, key []byte, err error) {
	var info []byte
	var hash []byte

	row := v.db.QueryRow("SELECT i.title, i.uuid, i.key, if.value, if.hash FROM item i, itemfield if")
	if err := row.Scan(&info, &hash); err != nil {
		return nil, nil, errors.Wrap(err, "could not query crypto parameters")
	}

	//if len(info) != 47 {
	//	return nil, nil, errors.New(fmt.Sprintf("row encryption info is not 47 bytes long but %d bytes", len(info)))
	//}

	// First 16 bytes are for "mHashData", which is unused
	iv = info[17:31]
	salt := info[32:]

	key = v.generateRowKey(hash, salt)

	return iv, key, nil
}

func (v *Vault) decrypt(input []byte, key []byte, iv []byte) (output []byte, err error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypter := cryptocipher.NewCBCDecrypter(cipher, iv)
	decrypter.CryptBlocks(output, input)

	return output, nil
}

func (v *Vault) GetCards() error {
	decIv, decKey, err := v.getCryptoParameters()
	if err != nil {
		return errors.Wrap(err, "could not retrieve crypto parameters")
	}

	rows, err := v.db.Query("SELECT title, key FROM item;")
	if err != nil {
		return errors.Wrap(err, "could not retrieve cards")
	}

	for rows.Next() {
		var title string
		var key []byte

		if err := rows.Scan(&title, &key); err != nil {
			log.Fatal(err)
		}

		decrypted, err := v.decrypt(key, decKey, decIv)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("%v", decrypted)
	}

	return nil
}
