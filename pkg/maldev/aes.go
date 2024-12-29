package maldev

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

func AESEncrypt(data, key []byte) ([]byte, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, errors.New("key length must match block size of AES 16, 24, or 32 bytes")
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cipherText := make([]byte, aes.BlockSize+len(data))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(c, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], data)

	return cipherText, nil
}

func AESDecrypt(data, key []byte) ([]byte, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, errors.New("key length must match block size of AES 16, 24, or 32 bytes")
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(c, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}
