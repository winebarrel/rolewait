// Package rolewait blocks until an IAM Identity Center permission set can be
// assumed.
//
// A permission set granted through privileged access management -- Entra PIM
// activating a group, or anything else that ends in an assignment being
// provisioned into Identity Center -- is not usable the moment the request is
// approved. It appears seconds or minutes later, and until it does every
// command that needs it fails with an error about access that looks exactly
// like having asked for the wrong thing. rolewait waits for the assignment to
// arrive, so a script can put it in front of the work that depends on it.
package rolewait

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
)

// Context is what the command needs from its surroundings.
type Context struct {
	// Out is where the wait says what it is doing. Nil is silent, as --quiet is.
	Out io.Writer

	// Config is what the Identity Center portal clients are built from. The
	// region is filled in from the profile, and the portal API needs no
	// credentials, so there is nothing to set for ordinary use; tests point it
	// at a stub.
	Config aws.Config
}

// Cmd is the command line.
type Cmd struct {
	Profile  string            `short:"p" env:"AWS_PROFILE" help:"Profile naming the account and the permission set to wait for."`
	Role     string            `short:"r" help:"Permission set to wait for, if not the one the profile names."`
	Alias    map[string]string `short:"a" env:"ROLEWAIT_ALIAS,SR_ALIAS" mapsep:"," help:"Short names for permission sets, as 'short=PermissionSetName'."`
	Interval time.Duration     `short:"i" default:"1s" help:"How long to wait between checks."`
	Timeout  time.Duration     `short:"t" default:"10m" help:"Give up after this long."`
	Times    int               `short:"n" default:"2" help:"Consecutive successful checks before the wait is over."`
	Quiet    bool              `short:"q" help:"Say nothing."`
}

// Run waits for the permission set and returns as soon as it is there.
func (cmd *Cmd) Run(cmdCtx *Context) error {
	if cmd.Interval <= 0 || cmd.Timeout <= 0 || cmd.Times < 1 {
		return errors.New("--interval and --timeout must be positive, and --times at least 1")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmd.Timeout)
	defer cancel()

	tgt, err := resolveTarget(ctx, cmd.Profile, resolveRole(cmd.Role, cmd.Alias))

	if err != nil {
		return err
	}

	cfg := cmdCtx.Config
	cfg.Region = tgt.Region

	// Read once, before the loop. The token is what says who is waiting, and a
	// wait that could not have started is worth refusing now rather than in
	// however many minutes the timeout allows.
	token, err := accessToken(ctx, cfg, tgt.CacheKey)

	if err != nil {
		return err
	}

	out := cmd.report(cmdCtx.Out)
	say(out, "waiting for %s in %s, checking every %s, giving up after %s\n", tgt.Role, tgt.AccountID, cmd.Interval, cmd.Timeout)

	started := time.Now()

	if err := cmd.wait(ctx, sso.NewFromConfig(cfg), tgt, token); err != nil {
		return err
	}

	say(out, "%s is available in %s after %s\n", tgt.Role, tgt.AccountID, time.Since(started).Round(time.Second))

	return nil
}

// report returns where progress goes, which is nowhere if nobody asked for it.
func (cmd *Cmd) report(out io.Writer) io.Writer {
	if cmd.Quiet || out == nil {
		return io.Discard
	}

	return out
}

// say reports progress, and does not care whether it arrived. A terminal that
// has gone away is not a reason to stop waiting, and there would be nowhere to
// report that either.
func say(out io.Writer, format string, args ...any) {
	fmt.Fprintf(out, format, args...) //nolint:errcheck
}
