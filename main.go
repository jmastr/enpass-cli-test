package main

import (
	"log"
	"main/enpasscli"
)

func main() {
	enpass, err := enpasscli.OpenVault("vault.enpassdb", "", []byte("mypassword"))
	if err != nil {
		log.Fatal(err)
	}

	defer enpass.Close()

	log.Println("printing tables")
	enpass.GetTables()
}