package maldev

import (
	"bytes"
	"testing"
)

func TestAES128(t *testing.T) {
	secretData := []byte(RandomString(128))
	key := []byte(RandomString(16))
	encryptedData, err := AESEncrypt(secretData, key)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	decryptedData, err := AESDecrypt(encryptedData, key)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	if !bytes.Equal(secretData, decryptedData) {
		t.Errorf("AES 128-bit failed to encrypt/decrypt properly")
	}
}

func TestAES192(t *testing.T) {
	secretData := []byte(RandomString(128))
	key := []byte(RandomString(24))
	encryptedData, err := AESEncrypt(secretData, key)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	decryptedData, err := AESDecrypt(encryptedData, key)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	if !bytes.Equal(secretData, decryptedData) {
		t.Errorf("AES 192-bit failed to encrypt/decrypt properly")
	}
}

func TestAES256(t *testing.T) {
	secretData := []byte(RandomString(128))
	key := []byte(RandomString(32))
	encryptedData, err := AESEncrypt(secretData, key)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	decryptedData, err := AESDecrypt(encryptedData, key)
	if err != nil {
		t.Errorf("Error: %v\n", err)
	}
	if !bytes.Equal(secretData, decryptedData) {
		t.Errorf("AES 256-bit failed to encrypt/decrypt properly")
	}
}
