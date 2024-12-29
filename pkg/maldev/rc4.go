package maldev

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func RC4(data, key []byte) []byte {
	var i, j int
	var s [256]byte
	// Initialize the S array with identity permutation
	for i = 0; i < 256; i++ {
		s[i] = byte(i)
	}

	// s is then processed for 256 iterations
	j = 0
	for i = 0; i < 256; i++ {
		//Randomize the permutations using the supplied key
		j = (j + int(s[i]) + int(key[i%len(key)])) % 256
		//Swap the values of s[i] and s[j]
		s[i], s[j] = s[j], s[i]
	}
	i, j = 0, 0
	// Create a buffer to store the encrypted data
	encrypted := make([]byte, len(data))
	// Loop through each byte of the data
	for k := 0; k < len(data); k++ {
		// Update the i and j variables
		i = (i + 1) % 256
		j = (j + int(s[i])) % 256
		// Swap the values of s[i] and s[j]
		s[i], s[j] = s[j], s[i]
		// Encrypt the data using the s array
		encrypted[k] = data[k] ^ s[(int(s[i])+int(s[j]))%256]
	}
	// Return the encrypted data
	return encrypted
}

type NTSTATUS uint32

type USTRING struct {
	Length        uint32
	MaximumLength uint32
	Buffer        unsafe.Pointer
}

func SystemFunction032(secret, key []byte) ([]byte, NTSTATUS) {
	// get SystemFunction032 address from ADVAPI32.dll
	advapi32 := windows.NewLazyDLL("ADVAPI32.dll")
	systemFunction032 := advapi32.NewProc("SystemFunction032")
	data := &USTRING{
		Length:        uint32(len(secret)),
		MaximumLength: uint32(len(secret)),
		Buffer:        unsafe.Pointer(&secret[0]),
	}
	code := &USTRING{
		Length:        uint32(len(key)),
		MaximumLength: uint32(len(key)),
		Buffer:        unsafe.Pointer(&key[0]),
	}

	// call SystemFunction032
	ret, _, _ := systemFunction032.Call(uintptr(unsafe.Pointer(data)), uintptr(unsafe.Pointer(code)))
	// get data.buffer as a byte array
	secretData := make([]byte, len(secret))
	for i := 0; i < len(secret); i++ {
		secretData[i] = *(*byte)(unsafe.Pointer(uintptr(data.Buffer) + uintptr(i)))
	}
	// return the encrypted data and the status code
	return secretData, NTSTATUS(ret)
}

func SystemFunction033(secret, key []byte) ([]byte, NTSTATUS) {
	// get SystemFunction033 address from ADVAPI32.dll
	advapi32 := windows.NewLazyDLL("ADVAPI32.dll")
	systemFunction033 := advapi32.NewProc("SystemFunction033")
	data := &USTRING{
		Length:        uint32(len(secret)),
		MaximumLength: uint32(len(secret)),
		Buffer:        unsafe.Pointer(&secret[0]),
	}
	code := &USTRING{
		Length:        uint32(len(key)),
		MaximumLength: uint32(len(key)),
		Buffer:        unsafe.Pointer(&key[0]),
	}

	// call SystemFunction033
	ret, _, _ := systemFunction033.Call(uintptr(unsafe.Pointer(data)), uintptr(unsafe.Pointer(code)))
	// get data.buffer as a byte array
	secretData := make([]byte, len(secret))
	for i := 0; i < len(secret); i++ {
		secretData[i] = *(*byte)(unsafe.Pointer(uintptr(data.Buffer) + uintptr(i)))
	}
	// return the encrypted data and the status code
	return secretData, NTSTATUS(ret)
}
