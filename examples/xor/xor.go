package main

import (
	"fmt"

	"github.com/mortimus/maldev/pkg/maldev"
	"github.com/mortimus/maldev/pkg/shellcode"
)

func main() {
	fmt.Printf("---XOR Encryption By One Key---\n")
	// XOR by one key
	secretString := "Hello, World!"
	secretData := []byte(secretString)
	shellcode.Print("Secret Data", 0, secretData)
	key := byte(0x41)
	fmt.Printf("Key: 0x%X\n", key)
	encryptedData := maldev.XorByOneKey(secretData, key)
	shellcode.Print("Encrypted Data", 0, encryptedData)
	decryptedData := maldev.XorByOneKey(encryptedData, key)
	shellcode.Print("Decrypted Data", 0, decryptedData)

	fmt.Printf("---XOR Encryption By i Keys---\n")
	// XOR by i keys
	secretData = []byte(secretString)
	shellcode.Print("Secret Data", 0, secretData)
	encryptedData = maldev.XorByiKeys(secretData, key)
	shellcode.Print("Encrypted Data", 0, encryptedData)
	decryptedData = maldev.XorByiKeys(encryptedData, key)
	shellcode.Print("Decrypted Data", 0, decryptedData)

	fmt.Printf("---XOR Encryption By input Key---\n")
	// XOR by input key
	secretData = []byte(secretString)
	shellcode.Print("Secret Data", 0, secretData)
	keyArray := []byte{0x41, 0x42, 0x43}
	shellcode.Print("Key", 0, keyArray)
	encryptedData = maldev.XorByInputKey(secretData, keyArray)
	shellcode.Print("Encrypted Data", 0, encryptedData)
	decryptedData = maldev.XorByInputKey(encryptedData, keyArray)
	shellcode.Print("Decrypted Data", 0, decryptedData)
}
