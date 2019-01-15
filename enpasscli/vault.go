package enpasscli

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	_ "github.com/xeodou/go-sqlcipher"
	"log"
	"path/filepath"
)

const (
	// contains info about your vault
	vaultInfoFileName = "vault.json"
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

func deccrypt(input []byte, key []byte) {

	block, err := aes.NewCipher(key)

	if err != nil {

		panic(err.Error())

	}


	aesgcm, err := cipher.NewGCM(block)

	if err != nil {

		panic(err.Error())

	}


	plaintext, err := aesgcm.Open(nil, input[:16], input[16:], nil)

	if err != nil {

		panic(err.Error())

	}


	fmt.Printf("%s\n", plaintext)
}

func (v *Vault) openEncryptedDatabase(path string, key []byte) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("open error: %v", err))
	}

	_, err = db.Exec(fmt.Sprintf(`PRAGMA key = "x'%s'"`, hex.EncodeToString(key)))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("pragma error: %v", err))
	}

	return db, nil
}

func OpenVault(path string, keyfile string, masterPassword []byte) (*Vault, error) {
	vault := Vault{
		databaseFilename: path,
		vaultInfoFilename: filepath.Dir(path) + "/" + vaultInfoFileName,
	}

	vaultInfo, err := loadVaultInfo(vault.vaultInfoFilename)
	if err != nil {
		return nil, err
	}

	vault.vaultInfo = vaultInfo

	if keyfile == "" && vaultInfo.HasKeyfile == 1 {
		return nil, errors.New("you should specify a keyfile")
	} else
	if keyfile != "" && vaultInfo.HasKeyfile  == 0 {
		return nil, errors.New("you are not currently using a keyfile")
	}

	derivedKey, err := vault.deriveKey(masterPassword, keyfile)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("could not generate key: %v", err))
	}

	db, err := vault.openEncryptedDatabase(path, derivedKey)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("could not open vault: %v", err))
	}

	vault.db = db

	return &vault, nil
}

func (v *Vault) Close() {
	v.db.Close()
}

func (v *Vault) GetTables() {
	rows, err := v.db.Query(`SELECT name FROM my_db.sqlite_master WHERE type='table';`)
	if err != nil { log.Fatal(err) }

	for rows.Next() {
		var row sql.Row
		if err := rows.Scan(row); err != nil {
			log.Fatalf("%v", err)
		}

		log.Printf("%v\n", row)
	}
}