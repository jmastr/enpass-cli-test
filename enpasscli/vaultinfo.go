package enpasscli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
)

type VaultInfo struct {
	EncryptionAlgo 	string 		`json:"encryption_algo"`
	HasKeyfile 		int 	  	`json:"have_keyfile"`
	KDFAlgo 		string 		`json:"kdf_algo"`
	KDFIterations 	int 	  	`json:"kdf_iter"`
	VaultNumItems 	int 	  	`json:"vault_items_count"`
	VaultName 		string      `json:"vault_name"`
	VaultVersion 	int	  		`json:"version"`
}

func loadVaultInfo(path string) (*VaultInfo, error) {
	vaultInfoJson, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("could not load vault info: %v", err))
	}

	var vaultInfo VaultInfo
	if err := json.Unmarshal(vaultInfoJson, &vaultInfo); err != nil {
		return nil, errors.New(fmt.Sprintf("could not parse vault info: %v", err))
	}

	return &vaultInfo, nil
}