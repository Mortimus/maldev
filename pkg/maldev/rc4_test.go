package maldev

import "testing"

func TestRC4(t *testing.T) {
	secretData := []byte(RandomString(64))
	key := []byte(RandomString(3))
	rc4 := Rc4Context{}
	rc4.Init(key)
	encryptedData := rc4.Cipher(secretData)
	rc4.Init(key)
	decryptedData := rc4.Cipher(encryptedData)
	if string(secretData) != string(decryptedData) {
		t.Errorf("RC4 failed")
	}
}
