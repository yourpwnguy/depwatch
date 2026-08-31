// Command depwatch is a dependency confusion monitor. It detects public packages
// that collide with internal dependencies and assesses supply-chain risk. Run
// `depwatch --help` for subcommands.
package main

import (
	"github.com/yourpwnguy/depwatch/internal/cli"
)

// version is stamped at build time via -ldflags. The default is "dev" for
// untagged builds; release builds inject the git tag via the Makefile.
var version = "dev"

func main() {
	cli.Run(version)
}
