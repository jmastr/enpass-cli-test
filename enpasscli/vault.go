package enpasscli

import (
	"database/sql"
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

func (v *Vault) openEncryptedDatabase(path string, hexKey string) (*sql.DB, error) {
	dbname := fmt.Sprintf("db?file=%s&_pragma_key=x'%s'", path, hexKey)

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

func (v *Vault) GetTables() {
	rows, err := v.db.Query("SELECT * FROM Identity;")
	if err != nil { log.Fatal(err) }

	for rows.Next() {
		log.Println("line")
		var interf1 interface{}
		if err := rows.Scan(&interf1); err != nil {
			log.Fatalf("%v", err)
		}

		log.Printf("%s\n", interf1)
	}
}