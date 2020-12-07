package enpasscli

import (
	"encoding/json"
	"io/ioutil"

	"github.com/pkg/errors"
)

type VaultInfo struct {
	EncryptionAlgo string `json:"encryption_algo"`
	HasKeyfile     int    `json:"have_keyfile"`
	KDFAlgo        string `json:"kdf_algo"`
	KDFIterations  int    `json:"kdf_iter"`
	VaultNumItems  int    `json:"vault_items_count"`
	VaultName      string `json:"vault_name"`
	VaultVersion   int    `json:"version"`
}

func loadVaultInfo(path string) (VaultInfo, error) {
	vaultInfoBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return VaultInfo{}, errors.Wrap(err, "could not read vault info")
	}

	var vaultInfo VaultInfo
	if err := json.Unmarshal(vaultInfoBytes, &vaultInfo); err != nil {
		return VaultInfo{}, errors.Wrap(err, "could not parse vault info")
	}

	return vaultInfo, nil
}
