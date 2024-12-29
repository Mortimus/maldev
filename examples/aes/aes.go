package main

import (
	"fmt"

	"github.com/mortimus/maldev/pkg/maldev"
	"github.com/mortimus/maldev/pkg/shellcode"
)

func main() {
	fmt.Printf("---AES 128-bit Function---\n")
	secretData := []byte("Hello, World!")
	shellcode.Print("Secret Data", 0, secretData)
	key := []byte(maldev.RandomString(16))
	shellcode.Print("Key", 0, key)
	encryptedData, err := maldev.AESEncrypt(secretData, key)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	shellcode.Print("Encrypted Data", 0, encryptedData)
	decryptedData, err := maldev.AESDecrypt(encryptedData, key)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	shellcode.Print("Decrypted Data", 0, decryptedData)

	fmt.Printf("---AES 192-bit Function---\n")
	secretData = []byte("Hello, World!")
	shellcode.Print("Secret Data", 0, secretData)
	key = []byte(maldev.RandomString(24))
	shellcode.Print("Key", 0, key)
	encryptedData, err = maldev.AESEncrypt(secretData, key)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	shellcode.Print("Encrypted Data", 0, encryptedData)
	decryptedData, err = maldev.AESDecrypt(encryptedData, key)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	shellcode.Print("Decrypted Data", 0, decryptedData)

	fmt.Printf("---AES 256-bit Function---\n")
	secretData = []byte("Hello, World!")
	shellcode.Print("Secret Data", 0, secretData)
	key = []byte(maldev.RandomString(32))
	shellcode.Print("Key", 0, key)
	encryptedData, err = maldev.AESEncrypt(secretData, key)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	shellcode.Print("Encrypted Data", 0, encryptedData)
	decryptedData, err = maldev.AESDecrypt(encryptedData, key)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	shellcode.Print("Decrypted Data", 0, decryptedData)
}
