package maldev

import "testing"

func TestRC4(t *testing.T) {
	secretData := []byte(RandomString(64))
	key := []byte(RandomString(3))
	encryptedData := RC4(secretData, key)
	decryptedData := RC4(encryptedData, key)
	if string(secretData) != string(decryptedData) {
		t.Errorf("RC4 failed")
	}
}

func TestSystemFunction032(t *testing.T) {
	secretData := []byte(RandomString(64))
	key := []byte(RandomString(3))
	enc, status := SystemFunction032(secretData, key)
	dec, status2 := SystemFunction032(enc, key)
	if (string(enc) != string(dec)) || status != 0 || status2 != 0 {
		t.Errorf("SystemFunction032 failed")
	}
}

func TestSystemFunction033(t *testing.T) {
	secretData := []byte(RandomString(64))
	key := []byte(RandomString(3))
	enc, status := SystemFunction033(secretData, key)
	dec, status2 := SystemFunction033(enc, key)
	if (string(enc) != string(dec)) || status != 0 || status2 != 0 {
		t.Errorf("SystemFunction033 failed")
	}
}
