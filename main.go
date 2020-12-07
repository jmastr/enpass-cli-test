package main

import (
	"log"
	"main/enpasscli"
)

func main() {
	enpass, err := enpasscli.OpenVault("vault.enpassdb", "", []byte("mymasterpassword"))
	if err != nil {
		log.Fatalf("could not open vault: %v", err)
	}

	defer enpass.Close()

	log.Println("printing tables")
	log.Fatal(enpass.GetCards())
}
