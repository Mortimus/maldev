package main

import (
	"fmt"

	"github.com/mortimus/maldev/pkg/maldev"
)

func main() {
	path := maldev.GetEnvironmentalVariable("WINDIR")
	fmt.Printf("Windows Directory: %s\n", path)
}
