package maldev

import (
	"bytes"
	"testing"
)

func TestConvertIPv4(t *testing.T) {
	data := []byte(RandomString(32))
	ips, err := ConvertToIPv4(data)
	if err != nil {
		t.Errorf("ConvertToIPv4 failed: %s", err)
	}
	data2 := ConvertIPv4ToBytes(ips)
	if !bytes.Equal(data, data2) {
		t.Errorf("ConvertIPv4 failed")
	}
}

func TestConvertIPv6(t *testing.T) {
	data := []byte(RandomString(128))
	ips, err := ConvertToIPv6(data)
	if err != nil {
		t.Errorf("ConvertToIPv6 failed: %s", err)
	}
	data2 := ConvertIPv6ToBytes(ips)
	if !bytes.Equal(data, data2) {
		t.Errorf("ConvertIPv6 failed")
	}
}

func TestConvertMAC(t *testing.T) {
	data := []byte(RandomString(96))
	macs, err := ConvertToMACAddress(data)
	if err != nil {
		t.Errorf("ConvertToMACAddress failed: %s", err)
	}
	data2 := ConvertMACToBytes(macs)
	if !bytes.Equal(data, data2) {
		t.Errorf("ConvertMACAddress failed")
	}
}

func TestConvertUUID(t *testing.T) {
	data := []byte(RandomString(192))
	uuids, err := ConvertToUUID(data)
	if err != nil {
		t.Errorf("ConvertToUUID failed: %s", err)
	}
	data2 := ConvertUUIDToBytes(uuids)
	if !bytes.Equal(data, data2) {
		t.Errorf("ConvertUUID failed")
	}
}
