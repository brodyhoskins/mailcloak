// Command mailcloak-encrypt is an outbound mail filter: it signs and encrypts
// a message with PGP or S/MIME depending on the keys each recipient has.
//
//	mailcloak-encrypt -pgp keys/ -f alice@corp.example -- bob@example.org < msg.eml
package main

import (
	"os"

	"github.com/brodyhoskins/mailcloak/internal/filter"
)

func main() {
	os.Exit(filter.Run("encrypt", filter.Encrypt, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
