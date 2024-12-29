package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/mortimus/maldev/pkg/maldev"
	"github.com/mortimus/maldev/pkg/shellcode"
)

func main() {
	// get flags for encryption type, key, data file, and output type
	eType := flag.String("enc", "aes", "encryption types: aes, xor, rc4")
	key := flag.String("key", "", "key for encryption")
	calc := flag.Bool("calc", false, "pop calc as shellcode")
	dataFile := flag.String("data", "", "file containing data to encrypt")
	outputType := flag.String("type", "go", "output type: raw, file, go, base64")
	outFile := flag.String("o", "", "output file")
	flag.Parse()

	if *key == "" {
		*key = maldev.RandomString(32)
		fmt.Printf("No key provided, generating random string\n\n")
	}
	fmt.Printf("Encryption Type: %s\n", *eType)
	fmt.Printf("Key: %s\n\n", *key)

	var data []byte
	var err error
	if *calc {
		data = shellcode.Calc()
	} else {
		// read data from file
		data, err = os.ReadFile(*dataFile)
		if err != nil {
			fmt.Printf("Error reading data file: %v\n", err)
			return
		}
	}

	// encrypt data
	var encryptedData []byte
	switch *eType {
	case "aes":
		encryptedData, err = maldev.AESEncrypt(data, []byte(*key))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
	case "xor":
		encryptedData = maldev.XorByInputKey(data, []byte(*key))
	case "rc4":
		encryptedData = maldev.RC4(data, []byte(*key))
	default:
		fmt.Printf("Invalid encryption type: %s\n", *eType)
		return
	}

	// output data
	switch *outputType {
	case "raw":
		fmt.Printf("%s\n", encryptedData)
	case "file":
		err = os.WriteFile(*outFile, encryptedData, 0644)
		if err != nil {
			fmt.Printf("Error writing output file: %v\n", err)
			return
		}
	case "go":
		fmt.Printf("var key []byte = []byte(\"%s\")\n", *key)
		shellcode.PrintSourcecode("encryptedData", encryptedData)
	case "base64":
		fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(encryptedData))
	default:
		fmt.Printf("Invalid output type: %s\n", *outputType)
	}

}
