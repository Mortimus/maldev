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
	rc4 := maldev.Rc4Context{}
	rc4.Init(key)
	encryptedData := rc4.Cipher(secretData)
	shellcode.Print("Encrypted Data", 0, encryptedData)
	rc4.Init(key)
	decryptedData := rc4.Cipher(encryptedData)
	shellcode.Print("Decrypted Data", 0, decryptedData)

	fmt.Printf("---RC4 SystemFunction032---\n")
	shellcode.Print("Secret Data", 0, secretData)
	code, status := maldev.SystemFunction032(secretData, key)
	shellcode.Print("Encrypted Data", 0, code)
	fmt.Printf("Status: 0x%X\n", status)
	code, status = maldev.SystemFunction032(code, key)
	shellcode.Print("Decrypted Data", 0, code)
	fmt.Printf("Status: 0x%X\n", status)
}
