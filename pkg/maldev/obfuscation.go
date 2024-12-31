package maldev

import (
	"fmt"
)

// TODO: Pad data to ensure multiple of 4
// TODO: Make sure IP is valid (no 0's, no 255's, etc)
func ConvertToIPv4(data []byte) ([]string, error) {
	// check if data length is a multiple of 4
	if len(data)%4 != 0 {
		return nil, fmt.Errorf("data length is not a multiple of 4")
	}
	// loop through data and convert each 4 bytes to an IP address
	ips := make([]string, 0)
	for len(data) > 0 {
		// convert 4 bytes to an IP address
		ip := fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
		// append to slice
		ips = append(ips, ip)
		// move to next 4 bytes
		data = data[4:]
	}
	return ips, nil
}

// TODO: Pad data to ensure multiple of 32
// TODO: Make sure IP is valid (no 0's, no 255's, etc)
func ConvertToIPv6(data []byte) ([]string, error) {
	// check if data length is a multiple of 32
	if len(data)%32 != 0 {
		return nil, fmt.Errorf("data length is not a multiple of 32")
	}

	// loop through data and convert each 32 bytes to an IP address
	ips := make([]string, 0)
	for len(data) > 0 {
		// // convert 32 bytes to an IP address
		// output0 := fmt.Sprintf("%02x%02x%02x%02x", data[0], data[1], data[2], data[3])
		// output1 := fmt.Sprintf("%02x%02x%02x%02x", data[4], data[5], data[6], data[7])
		// output2 := fmt.Sprintf("%02x%02x%02x%02x", data[8], data[9], data[10], data[11])
		// output3 := fmt.Sprintf("%02x%02x%02x%02x", data[12], data[13], data[14], data[15])
		// ip := fmt.Sprintf("%s:%s:%s:%s", output0, output1, output2, output3)
		// ip := fmt.Sprintf("%02%02%02%02:%02%02%02%02:%02%02%02%02:%02%02%02%02", data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15])
		ip := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15])
		// append to slice
		ips = append(ips, ip)
		// move to next 32 bytes
		data = data[16:]
	}
	return ips, nil
}

func ConvertIPv4ToBytes(ips []string) []byte {
	// loop through ips and convert each IP address to 4 bytes
	data := make([]byte, 0)
	for _, ip := range ips {
		// convert IP address to 4 bytes
		var a, b, c, d int
		fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
		// append to slice
		data = append(data, byte(a), byte(b), byte(c), byte(d))
	}
	return data
}

func ConvertIPv6ToBytes(ips []string) []byte {
	// loop through ips and convert each IP address to 32 bytes
	data := make([]byte, 0)
	for _, ip := range ips {
		// convert IP address to 32 bytes
		var a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p int
		fmt.Sscanf(ip, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", &a, &b, &c, &d, &e, &f, &g, &h, &i, &j, &k, &l, &m, &n, &o, &p)
		// append to slice
		data = append(data, byte(a), byte(b), byte(c), byte(d), byte(e), byte(f), byte(g), byte(h), byte(i), byte(j), byte(k), byte(l), byte(m), byte(n), byte(o), byte(p))
	}
	return data
}

func ConvertToMACAddress(data []byte) ([]string, error) {
	// check if data length is a multiple of 6
	if len(data)%6 != 0 {
		return nil, fmt.Errorf("data length is not a multiple of 6")
	}
	// loop through data and convert each 6 bytes to a MAC address
	macs := make([]string, 0)
	for len(data) > 0 {
		// convert 6 bytes to a MAC address
		mac := fmt.Sprintf("%02x-%02x-%02x-%02x-%02x-%02x", data[0], data[1], data[2], data[3], data[4], data[5])
		// append to slice
		macs = append(macs, mac)
		// move to next 6 bytes
		data = data[6:]
	}
	return macs, nil
}

func ConvertMACToBytes(macs []string) []byte {
	// loop through macs and convert each MAC address to 6 bytes
	data := make([]byte, 0)
	for _, mac := range macs {
		// convert MAC address to 6 bytes
		var a, b, c, d, e, f int
		fmt.Sscanf(mac, "%02x-%02x-%02x-%02x-%02x-%02x", &a, &b, &c, &d, &e, &f)
		// append to slice
		data = append(data, byte(a), byte(b), byte(c), byte(d), byte(e), byte(f))
	}
	return data
}

func ConvertToUUID(data []byte) ([]string, error) {
	// There are 5 segments in a UUID
	// First 3 segments are little endian
	// Last 2 segments are big endian
	// check if data length is a multiple of 16
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("data length is not a multiple of 16")
	}
	// loop through data and convert each 16 bytes to a UUID
	uuids := make([]string, 0)
	for len(data) > 0 {
		// convert 16 bytes to a UUID
		// First 3 segments are little endian
		// Last 2 segments are big endian
		// ########-####-####-####-############
		segment1 := fmt.Sprintf("%02x%02x%02x%02x", data[3], data[2], data[1], data[0])
		segment2 := fmt.Sprintf("%02x%02x", data[5], data[4])
		segment3 := fmt.Sprintf("%02x%02x", data[7], data[6])
		segment4 := fmt.Sprintf("%02x%02x", data[8], data[9])
		segment5 := fmt.Sprintf("%02x%02x%02x%02x%02x%02x", data[10], data[11], data[12], data[13], data[14], data[15])
		uuid := fmt.Sprintf("%s-%s-%s-%s-%s", segment1, segment2, segment3, segment4, segment5)
		// append to slice
		uuids = append(uuids, uuid)
		// move to next 16 bytes
		data = data[16:]
	}
	return uuids, nil
}

func ConvertUUIDToBytes(uuids []string) []byte {
	// loop through uuids and convert each UUID to 16 bytes
	data := make([]byte, 0)
	for _, uuid := range uuids {
		// convert UUID to 16 bytes
		var a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p int
		fmt.Sscanf(uuid, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", &d, &c, &b, &a, &f, &e, &h, &g, &i, &j, &k, &l, &m, &n, &o, &p)
		// append to slice
		data = append(data, byte(a), byte(b), byte(c), byte(d), byte(e), byte(f), byte(g), byte(h), byte(i), byte(j), byte(k), byte(l), byte(m), byte(n), byte(o), byte(p))
	}
	return data
}
