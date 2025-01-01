package maldev

import (
	"fmt"
	"math/rand"
)

const NOP = 0x90

var DEBUG = false

func RandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// This function makes sure the data is a specific multiple to ensure proper length's for obfuscation
func ShellCodePadding(data []byte, multiple int) ([]byte, error) {
	if len(data)%multiple != 0 {
		for i := 0; i < len(data)%multiple; i++ {
			// append NOPS
			data = append(data, NOP)
		}
	}
	// double check that the data is a multiple of multiple
	if len(data)%multiple != 0 {
		return nil, fmt.Errorf("failed to make data multiple of %d", multiple)
	}
	return data, nil
}

func Debugf(format string, args ...interface{}) {
	if DEBUG {
		fmt.Printf("[!] "+format, args...)
	}
}

func DebugWait(reason string) {
	if DEBUG {
		fmt.Printf("[#] Press <Enter> To %s ... ", reason)
		fmt.Scanln()
	}
}
