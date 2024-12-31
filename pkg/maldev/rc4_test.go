package maldev

import (
	"bytes"
	"testing"
)

func TestRC4(t *testing.T) {
	secretData := []byte(RandomString(64))
	key := []byte(RandomString(3))
	encryptedData := RC4(secretData, key)
	decryptedData := RC4(encryptedData, key)
	if !bytes.Equal(secretData, decryptedData) {
		t.Errorf("RC4 failed")
	}
}

func TestSystemFunction032(t *testing.T) {
	secretData := []byte(RandomString(64))
	key := []byte(RandomString(3))
	enc, err := SystemFunction032(secretData, key)
	if err != nil {
		t.Errorf("SystemFunction032 failed: %s", err)
	}
	dec, err := SystemFunction032(enc, key)
	if err != nil {
		t.Errorf("SystemFunction032 failed: %s", err)
	}
	if !bytes.Equal(enc, dec) {
		t.Errorf("SystemFunction032 failed")
	}
}

func TestSystemFunction033(t *testing.T) {
	secretData := []byte(RandomString(64))
	key := []byte(RandomString(3))
	enc, err := SystemFunction033(secretData, key)
	if err != nil {
		t.Errorf("SystemFunction033 failed: %s", err)
	}
	dec, err := SystemFunction033(enc, key)
	if err != nil {
		t.Errorf("SystemFunction033 failed: %s", err)
	}
	if !bytes.Equal(enc, dec) {
		t.Errorf("SystemFunction033 failed")
	}
}
