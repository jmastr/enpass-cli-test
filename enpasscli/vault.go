package enpasscli

import (
	"crypto/aes"
	cipher2 "crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/mutecomm/go-sqlcipher"
	"golang.org/x/crypto/pbkdf2"
	"log"
	"path/filepath"
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
	vaultInfo *VaultInfo
}

func (v *Vault) openEncryptedDatabase(path string, hexKey string) (*sql.DB, error) {
	dbname := fmt.Sprintf("%s?_pragma_key=x'%s'", path, hexKey)

	db, err := sql.Open("sqlite3", dbname)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("open error: %v", err))
	}

	return db, nil
}

func OpenVault(databasePath string, keyfilePath string, masterPassword []byte) (*Vault, error) {
	vault := Vault{
		databaseFilename: databasePath,
		vaultInfoFilename: filepath.Dir(databasePath) + "/" + vaultInfoFileName,
	}

	vaultInfo, err := loadVaultInfo(vault.vaultInfoFilename)
	if err != nil {
		return nil, err
	}

	vault.vaultInfo = vaultInfo

	if keyfilePath == "" && vaultInfo.HasKeyfile == 1 {
		return nil, errors.New("you should specify a keyfile")
	} else
	if keyfilePath != "" && vaultInfo.HasKeyfile  == 0 {
		return nil, errors.New("you are not currently using a keyfile")
	}

	/*
	var keyfileBytes []byte
	if keyfilePath != "" {
		keyfile, err := loadKeyFile(keyfilePath)
		if err != nil {
			return nil, err
		}

		keyfileBytes, err = hex.DecodeString(keyfile.Key)
		if err != nil {
			return nil, errors.New("could not decode keyfile")
		}

		log.Printf("%d", len(keyfileBytes))
	}*/

	salt, err := vault.extractSalt(databasePath)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("could not extract database key salt: %v", err))
	}

	derivedKey, err := vault.deriveKey(masterPassword, salt)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("could not generate key: %v", err))
	}

	db, err := vault.openEncryptedDatabase(databasePath, derivedKey)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("could not open vault: %v", err))
	}

	vault.db = db

	return &vault, nil
}

func (v *Vault) Close() {
	v.db.Close()
}

func (v *Vault) generateRowKey(hash []byte, salt []byte) ([]byte) {
	// PBKDF2- HMAC-SHA256
	return pbkdf2.Key(hash, salt, rowKeyIterations, sha256.Size, sha256.New)
}

func (v *Vault) getCryptoParameters() (iv []byte, key []byte, err error) {
	var info []byte
	var hash []byte

	row := v.db.QueryRow("SELECT Info, Hash FROM Identity;")
	if err := row.Scan(&info, &hash); err != nil {
		return nil, nil, err
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
	if err != nil { return nil, err }

	decrypter := cipher2.NewCBCDecrypter(cipher, iv)
	decrypter.CryptBlocks(output, input)

	return output, nil
}

func (v *Vault) GetCards() {
	decIv, decKey, err := v.getCryptoParameters()
	if err != nil { log.Fatal(err) }

	rows, err := v.db.Query("SELECT title, key FROM item;");
	if err != nil { log.Fatal(err) }

	for rows.Next() {
		var title string
		var key []byte

		if err := rows.Scan(&title, &key); err != nil {
			log.Fatal(err)
		}

		decrypted, err := v.decrypt(key, decKey, decIv)
		if err != nil { log.Fatal(err) }

		log.Printf("%v", decrypted)
	}
}