// Command mailcloak-decrypt is an inbound mail filter: it decrypts PGP/MIME
// and S/MIME messages addressed to users whose private keys it holds.
//
//	mailcloak-decrypt -pgp keys/ < in.eml > out.eml
package main

import (
	"os"

	"github.com/brodyhoskins/mailcloak/internal/filter"
)

func main() {
	os.Exit(filter.Run("decrypt", filter.Decrypt, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
