package main

import (
	"fmt"

	"github.com/mortimus/maldev/pkg/maldev"
	"github.com/mortimus/maldev/pkg/shellcode"
)

func main() {
	fmt.Printf("---RC4 Custom Function---\n")
	secretData := []byte("Hello, World!")
	shellcode.Print("Secret Data", 0, secretData)
	key := []byte(maldev.RandomString(16))
	shellcode.Print("Key", 0, key)
	encryptedData := maldev.RC4(secretData, key)
	shellcode.Print("Encrypted Data", 0, encryptedData)
	decryptedData := maldev.RC4(encryptedData, key)
	shellcode.Print("Decrypted Data", 0, decryptedData)

	fmt.Printf("---RC4 SystemFunction032---\n")
	shellcode.Print("Secret Data", 0, secretData)
	code, status := maldev.SystemFunction032(secretData, key)
	shellcode.Print("Encrypted Data", 0, code)
	fmt.Printf("Status: 0x%X\n", status)
	code, status = maldev.SystemFunction032(code, key)
	shellcode.Print("Decrypted Data", 0, code)
	fmt.Printf("Status: 0x%X\n", status)

	fmt.Printf("---RC4 SystemFunction033---\n")
	secretData = []byte("Hello, World!") // needs to be reset
	shellcode.Print("Secret Data", 0, secretData)
	code, status = maldev.SystemFunction033(secretData, key)
	shellcode.Print("Encrypted Data", 0, code)
	fmt.Printf("Status: 0x%X\n", status)
	code, status = maldev.SystemFunction033(code, key)
	shellcode.Print("Decrypted Data", 0, code)
	fmt.Printf("Status: 0x%X\n", status)
}
