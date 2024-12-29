package maldev

import (
	"bytes"
	"testing"
)

func TestXorByOneKey(t *testing.T) {
	secretData := []byte(RandomString(64))
	key := RandomString(1)[0]
	encryptedData := XorByOneKey(secretData, key)
	decryptedData := XorByOneKey(encryptedData, key)
	if !bytes.Equal(secretData, decryptedData) {
		t.Errorf("XorByOneKey failed")
	}
}

func TestXorByiKeys(t *testing.T) {
	secretData := []byte(RandomString(64))
	key := RandomString(1)[0]
	encryptedData := XorByiKeys(secretData, key)
	decryptedData := XorByiKeys(encryptedData, key)
	if !bytes.Equal(secretData, decryptedData) {
		t.Errorf("XorByiKeys failed")
	}
}

func TestXorByInputKey(t *testing.T) {
	secretData := []byte(RandomString(64))
	key := []byte(RandomString(3))
	encryptedData := XorByInputKey(secretData, key)
	decryptedData := XorByInputKey(encryptedData, key)
	if !bytes.Equal(secretData, decryptedData) {
		t.Errorf("XorByInputKey failed")
	}
}
