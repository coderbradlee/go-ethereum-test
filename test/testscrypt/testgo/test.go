package main

import (
	_"bytes"
	_"crypto/aes"
	_"crypto/sha256"
	"encoding/hex"
	_"encoding/json"
	"fmt"
	_"io/ioutil"
	_"path/filepath"
	"crypto/ecdsa"
	_"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	_"github.com/ethereum/go-ethereum/crypto/randentropy"
	_"github.com/pborman/uuid"
	_"golang.org/x/crypto/pbkdf2"
	_"golang.org/x/crypto/scrypt"
	_"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	_"crypto/elliptic"
	"github.com/btcsuite/btcd/btcec"
	"errors"
	"strings"
	xxx "../../../mobile"
)
const(
	StandardScryptN = int(keystore.StandardScryptN)//65536

	// StandardScryptP is the P parameter of Scrypt encryption algorithm, using 256MB
	// memory and taking approximately 1s CPU time on a modern processor.
	StandardScryptP = int(keystore.StandardScryptP)//1

	// LightScryptN is the N parameter of Scrypt encryption algorithm, using 4MB
	// memory and taking approximately 100ms CPU time on a modern processor.
	LightScryptN = int(keystore.LightScryptN)//4096

	// LightScryptP is the P parameter of Scrypt encryption algorithm, using 4MB
	// memory and taking approximately 100ms CPU time on a modern processor.
	LightScryptP = int(keystore.LightScryptP)//6
	// scryptR     = 8
	// scryptDKLen = 32
)
// Hash represents the 32 byte Keccak256 hash of arbitrary data.
// type Hash struct {
// 	hash common.Hash
// }

// // NewHashFromBytes converts a slice of bytes to a hash value.
// func NewHashFromBytes(binary []byte) (hash *Hash, _ error) {
// 	h := new(Hash)
// 	if err := h.SetBytes(common.CopyBytes(binary)); err != nil {
// 		return nil, err
// 	}
// 	return h, nil
// }	
func bytesToBits(data []byte)[]bool {
        bits := make([]bool, len(data) * 8);

        for i := 0; i < len(data); i++ {
            for j := 0; j < 8; j++ {
                bits[i * 8 + j] = (data[i] & 1 << 7 - j) != 0;
            }
        }

        return bits;
    }
    
func PrivateToMnemonic(entropy []byte) ([]string,error){
	wordList:=strings.Split(Mnemonic, "\r\n")
	// words:=make([]string)
	var words []string
    if(len(entropy) % 4 > 0) {
        return words,errors.New("wrong length");
    } else if(len(entropy) == 0) {
        return words,errors.New("empty");
    } else {
    	h,e:=xxx.NewHashFromBytes(entropy)
    	if e!=nil{
    		return words,errors.New("NewHashFromBytes");
    	}
        hash := h.GetBytes();
        hashBits := bytesToBits(hash);
        entropyBits := bytesToBits(entropy);
        checksumLengthBits := len(entropyBits) / 32;
        concatBits := make([]bool,len(entropyBits) + checksumLengthBits);
        copy(concatBits[0:len(entropyBits)],entropyBits[:])
        copy(concatBits[len(entropyBits):],hashBits[:])
        
        nwords := len(concatBits) / 11;

        for i := 0; i < nwords; i++ {
            index := 0;

            for j := 0; j < 11; j++ {
                index <<= 1;
                if(concatBits[i * 11 + j]) {
                    index |= 1;
                }
            }
			append(words,wordList[index]);
        }

        return words,nil;
    }
}
func main() {
	//以下keystore对应的
	//地址 0xeb918706a6ab0ceab8d1ce37ba3aabf9095c1e96
	//助记词 oil tuition enter extra lunar cheap cash cute elbow ability method hobby beauty domain pizza always rib exhibit broom type gym shift brick battle
	//私钥 99dd452da888504dc8d1b547200630b6213a81e9683cb8e9f07375e6818b86e8
	//密码 123456789
    keys := `{"address":"eb918706a6ab0ceab8d1ce37ba3aabf9095c1e96","id":"204571b9-5e1d-4137-8838-c8c647131e43","version":3,"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"08bd2e3885a112dbf2fa982eb0f532e2"},"ciphertext":"18e025399b4844b047c9a0f9b6c746ea281621118a305d2c19e49bf814c3f7e4","kdf":"scrypt","kdfparams":{"dklen":32,"n":4096,"p":6,"r":8,"salt":"00204836e78455c6f4728178565a0d2a22a5d2b8d5b0e504751d598182f69741"},"mac":"63b76967e0dab6879707761efdc24ccfdaec517e0b10f3a1723498f458b9d711"}}`
	keyjson:=[]byte(keys)
	password := "123456789"
	// address := common.HexToAddress("eb918706a6ab0ceab8d1ce37ba3aabf9095c1e96")
	// m := make(map[string]interface{})
	// if err := json.Unmarshal(keyjson, &m); err != nil {
	// 	fmt.Println(err)
	// }
	// if address1, ok := m["address"].(string); ok{
	// 	fmt.Println(address1)
	// }

	// Decrypt with the correct password
	key, err := keystore.DecryptKey(keyjson, password)
	if err != nil {
		fmt.Printf("json key failed to decrypt: %v", err)
		return
	}

	fmt.Printf("key address %x\n", key.Address)
	fmt.Printf("key id %x\n", key.Id)
	// fmt.Printf("key PrivateKey.D %x\n", key.PrivateKey.D)
	fmt.Printf("key PublicKey %x\n", key.PrivateKey.PublicKey)

	fmt.Println("/////////////from private key to keystore:")
	fmt.Printf("key PrivateKey.D %x\n", key.PrivateKey.D)

	fmt.Println("/////////////from PublicKey to address:")
	fmt.Printf("key address %x\n", crypto.PubkeyToAddress(key.PrivateKey.PublicKey))
	// type PublicKey struct {
	// 	elliptic.Curve
	// 	X, Y *big.Int
	// }
	// type CurveParams struct {
	// 	P       *big.Int // the order of the underlying field
	// 	N       *big.Int // the order of the base point
	// 	B       *big.Int // the constant of the curve equation
	// 	Gx, Gy  *big.Int // (x,y) of the base point
	// 	BitSize int      // the size of the underlying field
	// 	Name    string   // the canonical name of the curve
	// }
	fmt.Printf("key PublicKey params P %x\n", key.PrivateKey.PublicKey.Params().P)
	fmt.Printf("key PublicKey params N %x\n", key.PrivateKey.PublicKey.Params().N)
	fmt.Printf("key PublicKey params B %x\n", key.PrivateKey.PublicKey.Params().B)
	fmt.Printf("key PublicKey params Gx %x\n", key.PrivateKey.PublicKey.Params().Gx)
	fmt.Printf("key PublicKey params Gy %x\n", key.PrivateKey.PublicKey.Params().Gy)
	fmt.Printf("key PublicKey params BitSize %x\n", key.PrivateKey.PublicKey.Params().BitSize)
	fmt.Printf("key PublicKey params Name %s\n", key.PrivateKey.PublicKey.Params().Name)
	fmt.Println("/////////////from PrivateKey to PublicKey:")
	// func PrivKeyFromBytes(curve elliptic.Curve, pk []byte) (*PrivateKey,*PublicKey)
	// private,public:=btcec.PrivKeyFromBytes(elliptic.P256(),[]byte("99dd452da888504dc8d1b547200630b6213a81e9683cb8e9f07375e6818b86e8"))
	b, err := hex.DecodeString("99dd452da888504dc8d1b547200630b6213a81e9683cb8e9f07375e6818b86e8")
	if err != nil {
		fmt.Println("invalid hex string")
	}
	// private,public:=btcec.PrivKeyFromBytes(elliptic.P256(),b)
	private,public:=btcec.PrivKeyFromBytes(crypto.S256(),b)
	fmt.Printf("public %x\n", public)
	fmt.Printf("private %x\n", private.D)
	fmt.Printf("key address %x\n", crypto.PubkeyToAddress(ecdsa.PublicKey(*public)))

	// type Key struct {
	// 	Id uuid.UUID // Version 4 "random" for unique id not derived from key data
	// 	// to simplify lookups we also store the address
	// 	Address common.Address
	// 	// we only store privkey as pubkey/address can be derived from it
	// 	// privkey in this struct is always in plaintext
	// 	PrivateKey *ecdsa.PrivateKey
	// }
	inputkey := &keystore.Key{
		Id:         key.Id,
		Address:    crypto.PubkeyToAddress(ecdsa.PublicKey(*public)),
		PrivateKey: (*ecdsa.PrivateKey)(private),
	}
	if keyjson, err = keystore.EncryptKey(inputkey, password, LightScryptN, LightScryptP); err != nil {
		fmt.Printf("failed to crypt key %v",err)
	}else{
		//fmt.Println("keystore is:\n"+string(keyjson)+"\n")
	}
	fmt.Println("/////////////from PrivateKey to Mnemonic:")
	
	{
		inputkey := &keystore.Key{
			Id:         key.Id,
			Address:    crypto.PubkeyToAddress(key.PrivateKey.PublicKey),
			PrivateKey: key.PrivateKey,
		}
		if keyjson, err = keystore.EncryptKey(inputkey, password, LightScryptN, LightScryptP); err != nil {
			fmt.Printf("failed to crypt key %v",err)
		}else{
			fmt.Println("keystore is:\n"+string(keyjson)+"\n")
		}
	}
	









	//in java
	
	// public List<String> toMnemonic(byte[] entropy) throws MnemonicLengthException {
 //        if(entropy.length % 4 > 0) {
 //            throw new MnemonicLengthException("Entropy length not multiple of 32 bits.");
 //        } else if(entropy.length == 0) {
 //            throw new MnemonicLengthException("Entropy is empty.");
 //        } else {
 //            byte[] hash = Sha256Hash.create(entropy).getBytes();
 //            boolean[] hashBits = bytesToBits(hash);
 //            boolean[] entropyBits = bytesToBits(entropy);
 //            int checksumLengthBits = entropyBits.length / 32;
 //            boolean[] concatBits = new boolean[entropyBits.length + checksumLengthBits];
 //            System.arraycopy(entropyBits, 0, concatBits, 0, entropyBits.length);
 //            System.arraycopy(hashBits, 0, concatBits, entropyBits.length, checksumLengthBits);
 //            ArrayList<String> words = new ArrayList();
 //            int nwords = concatBits.length / 11;

 //            for(int i = 0; i < nwords; ++i) {
 //                int index = 0;

 //                for(int j = 0; j < 11; ++j) {
 //                    index <<= 1;
 //                    if(concatBits[i * 11 + j]) {
 //                        index |= 1;
 //                    }
 //                }

 //                words.add(this.wordList.get(index));
 //            }

 //            return words;
 //        }
 //    }
	/////////////////////////////////////////////////////////////////
	// fmt.Println("/////////////decrypt after encrypt:")
	// {
	// 	key, err := keystore.DecryptKey(keyjson, password)
	// 	if err != nil {
	// 		fmt.Printf("json key failed to decrypt: %v", err)
	// 		return
	// 	}

	// 	fmt.Printf("key address %x\n", key.Address)
	// 	fmt.Printf("key id %x\n", key.Id)
	// 	fmt.Printf("key PrivateKey.D %x\n", key.PrivateKey.D)
	// 	fmt.Printf("key PublicKey %x\n", key.PrivateKey.PublicKey)
	// }
	
}
