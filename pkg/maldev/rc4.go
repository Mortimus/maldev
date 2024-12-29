package maldev

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
