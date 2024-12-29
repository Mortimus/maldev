package shellcode

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

// print shellcode in hexdump format with coloring
func Print(title string, baseAddress uint64, shellcode []byte) {
	code := hex.Dump(shellcode)
	// make the address blue
	// loop through each line
	color.Set(color.FgYellow)
	fmt.Printf("%s\n", title)
	color.Unset()
	for _, line := range strings.Split(strings.TrimSuffix(code, "\n"), "\n") {
		// first 8 bytes of each line are the address
		address := line[:8]
		// convert the address to uint64
		loc, _ := strconv.ParseUint(address, 16, 64)
		address = fmt.Sprintf("%08X", loc+baseAddress)
		// get the address of the | character
		pipe := strings.Index(line, "|")
		// hex is between 8 and pipe
		hex := line[9:pipe]
		// ascii is after the pipe
		ascii := line[pipe+1 : len(line)-1]
		color.Set(color.FgBlue)
		fmt.Printf("0x%s", address)
		color.Unset()
		color.Set(color.FgGreen)
		fmt.Printf("%s", hex)
		color.Unset()
		fmt.Printf("| ")
		color.Set(color.FgRed)
		fmt.Printf("%-16s", ascii)
		color.Unset()
		fmt.Printf(" |\n")
	}
}
