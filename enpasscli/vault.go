package enpasscli

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	_ "github.com/mutecomm/go-sqlcipher"
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

func (v *Vault) openEncryptedDatabase(path string, key []byte) (*sql.DB, error) {
	dbname := fmt.Sprintf("db?file=%s&_pragma_key=x'%s'", path, hex.EncodeToString(key))

	db, err := sql.Open("sqlite3", dbname)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("open error: %v", err))
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
	rows, err := v.db.Query("SELECT name FROM sqlite_master;")
	if err != nil { log.Fatal(err) }

	for rows.Next() {
		log.Println("line")
		var interf1 interface{}
		var interf2 interface{}
		var interf3 interface{}
		if err := rows.Scan(&interf1, &interf2, &interf3); err != nil {
			log.Fatalf("%v", err)
		}

		log.Printf("%s\n%s\n%s\n", interf1, interf2, interf3)
	}
}