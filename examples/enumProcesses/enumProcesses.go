package main

import (
	"fmt"
	"log"

	"github.com/mortimus/maldev/pkg/maldev"
)

func main() {
	// maldev.DEBUG = true
	processes, err := maldev.GetProcesses(false)
	if err != nil {
		log.Fatalf("Error getting processes: %v", err)
	}
	for _, process := range processes {
		fmt.Printf("PID: %d\tName: %s\n", process.ID, process.Name)
	}

	pHandle, err := maldev.GetRemoteProcessHandleCreateToolhelp32Snapshot("notepad.exe")
	if err != nil {
		log.Fatalf("Error getting process handle: %v", err)
	}
	fmt.Printf("Process Handle: %d\n", pHandle)
}
