package main

import (
	"fmt"
	"log"

	"github.com/mortimus/maldev/pkg/maldev"
	"github.com/mortimus/maldev/pkg/shellcode"
)

func main() {
	sc := []byte(maldev.RandomString(4))
	shellcode.Print("Shellcode", 0, sc)
	fmt.Printf("Converting to IPv4\n")
	ip4, err := maldev.ConvertToIPv4(sc)
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}
	for i, ip := range ip4 {
		fmt.Printf("IP %d: %s\n", i, ip)
	}
	fmt.Printf("Converting back to bytes\n")
	data := maldev.ConvertIPv4ToBytes(ip4)
	shellcode.Print("IPv4 Data", 0, data)
	fmt.Printf("Converting to IPv6 and padding data\n")
	sc, err = maldev.ShellCodePadding(sc, 16)
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}
	ip6, err := maldev.ConvertToIPv6(sc)
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}
	for i, ip := range ip6 {
		fmt.Printf("IP %d: %s\n", i, ip)
	}
	fmt.Printf("Converting back to bytes\n")
	data = maldev.ConvertIPv6ToBytes(ip6)
	shellcode.Print("IPv6 Data", 0, data)

	fmt.Printf("Converting to MAC Addresses and padding to 6\n")
	sc, err = maldev.ShellCodePadding(sc, 6)
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}
	macs, err := maldev.ConvertToMACAddress(sc)
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}
	for i, mac := range macs {
		fmt.Printf("MAC %d: %s\n", i, mac)
	}
	fmt.Printf("Converting back to bytes\n")
	data = maldev.ConvertMACToBytes(macs)
	shellcode.Print("MAC Data", 0, data)

	fmt.Printf("Converting to UUIDs and padding\n")
	sc, err = maldev.ShellCodePadding(sc, 16)
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}
	uuids, err := maldev.ConvertToUUID(sc)
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}
	for i, uuid := range uuids {
		fmt.Printf("UUID %d: %s\n", i, uuid)
	}
	fmt.Printf("Converting back to bytes\n")
	data = maldev.ConvertUUIDToBytes(uuids)
	shellcode.Print("UUID Data", 0, data)
}
