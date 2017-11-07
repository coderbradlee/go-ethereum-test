package main

import (
	_"bytes"
	_"crypto/aes"
	_"crypto/sha256"
	_"encoding/hex"
	_"encoding/json"
	_"fmt"
	_"io/ioutil"
	_"path/filepath"

	_"github.com/ethereum/go-ethereum/common"
	_"github.com/ethereum/go-ethereum/common/math"
	_"github.com/ethereum/go-ethereum/crypto"
	_"github.com/ethereum/go-ethereum/crypto/randentropy"
	_"github.com/pborman/uuid"
	_"golang.org/x/crypto/pbkdf2"
	_"golang.org/x/crypto/scrypt"
	"github.com/ethereum/go-ethereum/common"
)


func main() {
    keyjson := `{"address":"390bae9e7e9684a09b1aa73590eee3e78add44a0","crypto":{"cipher":"aes-128-ctr","ciphertext":"7d598fb7bad75120ea4f43250c52363773058dee3879db1d7a078e0d2675ffdf","cipherparams":{"iv":"3b11c9ec8d98fb7232f1f3ca1f057482"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"1e70cec326fb861773828c86e298714cfb553be06e108768359e33b782b11d3e"},"mac":"e3077a460009ff184b03e1eca47440dc3d3e9eddfe933270e304893310d81706"},"id":"4ec991ef-ae20-421e-ba31-ad36a6b08efe","version":3}`
	
	password := ""
	address := common.HexToAddress("390bae9e7e9684a09b1aa73590eee3e78add44a0")

	// Do a few rounds of decryption and encryption
	for i := 0; i < 3; i++ {
		// Try a bad password first
		if _, err := DecryptKey(keyjson, password+"bad"); err == nil {
			t.Errorf("test %d: json key decrypted with bad password", i)
		}
		// Decrypt with the correct password
		key, err := DecryptKey(keyjson, password)
		if err != nil {
			t.Fatalf("test %d: json key failed to decrypt: %v", i, err)
		}
		if key.Address != address {
			t.Errorf("test %d: key address mismatch: have %x, want %x", i, key.Address, address)
		}
		// Recrypt with a new password and start over
		password += "new data appended"
		if keyjson, err = EncryptKey(key, password, veryLightScryptN, veryLightScryptP); err != nil {
			t.Errorf("test %d: failed to recrypt key %v", i, err)
		}else{
			fmt.Println(keyjson)
		}

	}
}
