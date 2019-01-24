package enpasscli

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
)

type Keyfile struct {
	Key string `xml:",innerxml"`
}

func loadKeyFile(path string) (*Keyfile, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("could not load keyfile: %v", err))
	}

	var kf Keyfile
	if err := xml.Unmarshal(bytes, &kf); err != nil {
		return nil, errors.New(fmt.Sprintf("could not parse keyfile: %v", err))
	}

	return &kf, nil
}
