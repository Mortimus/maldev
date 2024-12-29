package maldev

/*
	- data : Base address of the payload to encrypt
	- key : A single arbitrary byte representing the key for encrypting the payload
*/
func XorByOneKey(data []byte, key byte) []byte {
	for i := 0; i < len(data); i++ {
		data[i] ^= key
	}
	return data
}

/*
	- data : Base address of the payload to encrypt
	- key : A single arbitrary byte representing the key for encrypting the payload
*/
func XorByiKeys(data []byte, key byte) []byte {
	for i := 0; i < len(data); i++ {
		data[i] ^= (key + byte(i))
	}
	return data
}

/*
	- data : Base address of the payload to encrypt
	- key : A random array of bytes of specific size
*/
func XorByInputKey(data []byte, key []byte) []byte {
	for i := 0; i < len(data); i++ {
		data[i] ^= key[i%len(key)]
	}
	return data
}
