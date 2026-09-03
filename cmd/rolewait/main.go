package main

import (
	"os"

	"github.com/alecthomas/kong"
	"github.com/winebarrel/rolewait"
)

// version is stamped in by GoReleaser at release time.
var version string

var cli struct {
	Version kong.VersionFlag
	rolewait.Cmd
}

func main() {
	kctx := kong.Parse(&cli,
		kong.Name("rolewait"),
		kong.Description("Wait until an IAM Identity Center permission set can be assumed."),
		kong.Vars{"version": resolveVersion(version)},
		kong.UsageOnError(),
	)

	// Progress belongs on stderr: the point of the command is what it exits
	// with, and whatever runs after it should not have to filter this out.
	kctx.FatalIfErrorf(cli.Run(&rolewait.Context{Out: os.Stderr}))
}
