package main

import (
	"fmt"
	"log"

	"github.com/mortimus/maldev/pkg/maldev"
	"github.com/mortimus/maldev/pkg/shellcode"
)

func main() {
	sc := shellcode.Calc()
	shellcode.Print("Shellcode", 0, sc)
	fmt.Printf("Converting to IPv4\n")
	ip4, err := maldev.ConvertToIPv4(sc)
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}
	for i, ip := range ip4 {
		fmt.Printf("IP %d: %s\n", i, ip)
	}
	fmt.Printf("Converting to IPv6\n")
	ip6, err := maldev.ConvertToIPv6(sc)
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}
	for i, ip := range ip6 {
		fmt.Printf("IP %d: %s\n", i, ip)
	}
	fmt.Printf("Converting back to bytes\n")
	data := maldev.ConvertIPv4ToBytes(ip4)
	shellcode.Print("IPv4 Data", 0, data)
	data = maldev.ConvertIPv6ToBytes(ip6)
	shellcode.Print("IPv6 Data", 0, data)
}
