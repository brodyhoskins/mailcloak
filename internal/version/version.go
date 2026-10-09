// Package version reports mailcloak's version.
package version

import (
	"runtime/debug"
	"sync"
)

// Version is set at build time:
//
//	go build -ldflags "-X github.com/brodyhoskins/mailcloak/internal/version.Version=1.2.3"
//
// Without it, the version comes from the build info Go embeds: the module
// version for `go install …@v1.2.3`, or "dev-<commit>" for a local build.
var Version string

// Product is the name used in User-Agent strings.
const Product = "mailcloak"

var computed = sync.OnceValue(func() string {
	if Version != "" {
		return Version
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	rev, dirty := "", false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	v := "dev-" + rev[:min(len(rev), 12)]
	if dirty {
		v += "-dirty"
	}
	return v
})

// String returns the version, e.g. "1.2.3" or "dev-0123456789ab".
func String() string { return computed() }

// Token returns the product token "mailcloak/<version>" (RFC 9110 / RFC 5536).
func Token() string { return Product + "/" + String() }
