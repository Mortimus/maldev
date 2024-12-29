package maldev

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

type Rc4Context struct {
	i, j int
	s    [256]byte
}

func (rc4 *Rc4Context) Init(key []byte) {
	// Initialize the S array with identity permutation
	for i := 0; i < 256; i++ {
		rc4.s[i] = byte(i)
	}

	// s is then processed for 256 iterations
	j := 0
	for i := 0; i < 256; i++ {
		//Randomize the permutations using the supplied key
		j = (j + int(rc4.s[i]) + int(key[i%len(key)])) % 256
		//Swap the values of s[i] and s[j]
		rc4.s[i], rc4.s[j] = rc4.s[j], rc4.s[i]
	}
	rc4.i, rc4.j = 0, 0
}

func (rc4 *Rc4Context) Cipher(data []byte) []byte {
	// Initialize the i and j variables
	rc4.i, rc4.j = 0, 0
	// Create a buffer to store the encrypted data
	encrypted := make([]byte, len(data))
	// Loop through each byte of the data
	for k := 0; k < len(data); k++ {
		// Update the i and j variables
		rc4.i = (rc4.i + 1) % 256
		rc4.j = (rc4.j + int(rc4.s[rc4.i])) % 256
		// Swap the values of s[i] and s[j]
		rc4.s[rc4.i], rc4.s[rc4.j] = rc4.s[rc4.j], rc4.s[rc4.i]
		// Encrypt the data using the s array
		encrypted[k] = data[k] ^ rc4.s[(int(rc4.s[rc4.i])+int(rc4.s[rc4.j]))%256]
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
