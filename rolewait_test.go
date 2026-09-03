package rolewait_test

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/rolewait"
)

func TestCmdParse(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		env      map[string]string
		profile  string
		role     string
		alias    map[string]string
		interval time.Duration
		timeout  time.Duration
		times    int
		quiet    bool
		errMsg   string
	}{
		{
			// Everything the wait needs is in the profile already, so there is
			// nothing that has to be passed.
			name:     "no flags",
			args:     []string{},
			interval: time.Second,
			timeout:  10 * time.Minute,
			times:    2,
		},
		{
			name:     "profile",
			args:     []string{"-p", "example"},
			profile:  "example",
			interval: time.Second,
			timeout:  10 * time.Minute,
			times:    2,
		},
		{
			name:     "every flag",
			args:     []string{"-p", "example", "-r", "admin", "-a", "ro=ReadOnlyAccess,admin=AdministratorAccess", "-i", "5s", "-t", "30m", "-n", "3", "-q"},
			profile:  "example",
			role:     "admin",
			alias:    map[string]string{"ro": "ReadOnlyAccess", "admin": "AdministratorAccess"},
			interval: 5 * time.Second,
			timeout:  30 * time.Minute,
			times:    3,
			quiet:    true,
		},
		{
			// Aliases are usually exported rather than passed, since they are
			// the same every time.
			name:     "aliases from the environment",
			args:     []string{},
			env:      map[string]string{"ROLEWAIT_ALIAS": "admin=AdministratorAccess"},
			alias:    map[string]string{"admin": "AdministratorAccess"},
			interval: time.Second,
			timeout:  10 * time.Minute,
			times:    2,
		},
		{
			// Anyone using sr alongside rolewait has already defined these
			// once, and defining them twice under two names is how the two
			// tools end up disagreeing about what a short name means.
			name:     "aliases fall back to sr's",
			args:     []string{},
			env:      map[string]string{"SR_ALIAS": "admin=AdministratorAccess"},
			alias:    map[string]string{"admin": "AdministratorAccess"},
			interval: time.Second,
			timeout:  10 * time.Minute,
			times:    2,
		},
		{
			name:   "unknown flag",
			args:   []string{"--account-id", accountID},
			errMsg: "unknown flag --account-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			t.Setenv("AWS_PROFILE", "")
			unsetenv(t, "ROLEWAIT_ALIAS")
			unsetenv(t, "SR_ALIAS")

			for name, value := range tt.env {
				t.Setenv(name, value)
			}

			var cli struct {
				Version kong.VersionFlag
				rolewait.Cmd
			}

			parser, err := kong.New(&cli, kong.Name("rolewait"), kong.Vars{"version": ""})
			require.NoError(t, err)

			_, err = parser.Parse(tt.args)

			if tt.errMsg != "" {
				assert.ErrorContains(err, tt.errMsg)

				return
			}

			require.NoError(t, err)
			assert.Equal(tt.profile, cli.Profile)
			assert.Equal(tt.role, cli.Role)
			assert.Equal(tt.alias, cli.Alias)
			assert.Equal(tt.interval, cli.Interval)
			assert.Equal(tt.timeout, cli.Timeout)
			assert.Equal(tt.times, cli.Times)
			assert.Equal(tt.quiet, cli.Quiet)
		})
	}
}

// TestCmdRun covers the permission set arriving while the wait is running.
func TestCmdRun(t *testing.T) {
	assert := assert.New(t)

	center := startPortal(t,
		reply{Roles: []string{"ReadOnlyAccess"}},
		reply{Roles: []string{"ReadOnlyAccess", "AdministratorAccess"}},
	)

	signedIn(t, testConfig)

	var out bytes.Buffer

	cmd := &rolewait.Cmd{
		Profile:  "example",
		Role:     "AdministratorAccess",
		Interval: time.Millisecond,
		Timeout:  10 * time.Second,
		Times:    1,
	}

	require.NoError(t, cmd.Run(center.context(&out)))

	// Two requests: the permission set was not there the first time.
	assert.Equal(2, center.count())

	request := center.Requests[0]
	assert.Equal("/assignment/roles", request.URL.Path)
	assert.Equal(accountID, request.URL.Query().Get("account_id"))
	assert.Equal("the-token", request.Header.Get("x-amz-sso_bearer_token"))

	assert.Contains(out.String(), "waiting for AdministratorAccess in "+accountID)
	assert.Contains(out.String(), "AdministratorAccess is available in "+accountID)
}

// TestCmdRunProfileRole covers leaving -r off: the permission set the profile
// names is the one to wait for, which is the case when the profile is the
// privileged one.
func TestCmdRunProfileRole(t *testing.T) {
	center := startPortal(t, reply{Roles: []string{"ReadOnlyAccess"}})

	signedIn(t, testConfig)

	cmd := &rolewait.Cmd{
		Profile:  "example",
		Interval: time.Millisecond,
		Timeout:  10 * time.Second,
		Times:    1,
	}

	require.NoError(t, cmd.Run(center.context(io.Discard)))
	assert.Equal(t, 1, center.count())
}

// TestCmdRunLegacyProfile covers a profile written before sso-session existed,
// whose token is cached under the start URL rather than a session name.
func TestCmdRunLegacyProfile(t *testing.T) {
	center := startPortal(t, reply{Roles: []string{"ReadOnlyAccess"}})

	writeToken(t, isolateAWS(t, testConfig), startURL, validToken())

	cmd := &rolewait.Cmd{
		Profile:  "legacy",
		Interval: time.Millisecond,
		Timeout:  10 * time.Second,
		Times:    1,
	}

	require.NoError(t, cmd.Run(center.context(io.Discard)))
	assert.Equal(t, 1, center.count())
}

// TestCmdRunEnvProfile covers AWS_PROFILE, which is how the profile arrives
// when nobody passed one.
func TestCmdRunEnvProfile(t *testing.T) {
	center := startPortal(t, reply{Roles: []string{"ReadOnlyAccess"}})

	signedIn(t, testConfig)
	t.Setenv("AWS_PROFILE", "example")

	cmd := &rolewait.Cmd{
		Interval: time.Millisecond,
		Timeout:  10 * time.Second,
		Times:    1,
	}

	require.NoError(t, cmd.Run(center.context(io.Discard)))
	assert.Equal(t, 1, center.count())
}

// TestCmdRunPagination covers an account with more permission sets than fit in
// one page, where the one being waited for is on a later one.
func TestCmdRunPagination(t *testing.T) {
	center := startPortal(t,
		reply{Roles: []string{"ReadOnlyAccess"}, Next: "page-2"},
		reply{Roles: []string{"AdministratorAccess"}},
	)

	signedIn(t, testConfig)

	cmd := &rolewait.Cmd{
		Profile:  "example",
		Role:     "AdministratorAccess",
		Interval: time.Millisecond,
		Timeout:  10 * time.Second,
		Times:    1,
	}

	require.NoError(t, cmd.Run(center.context(io.Discard)))

	assert.Equal(t, 2, center.count())
	assert.Equal(t, "page-2", center.Requests[1].URL.Query().Get("next_token"))
}

// TestCmdRunQuiet covers -q, for a wait inside a script that has its own idea
// of what should be on the terminal.
func TestCmdRunQuiet(t *testing.T) {
	center := startPortal(t, reply{Roles: []string{"ReadOnlyAccess"}})

	signedIn(t, testConfig)

	var out bytes.Buffer

	cmd := &rolewait.Cmd{
		Profile:  "example",
		Interval: time.Millisecond,
		Timeout:  10 * time.Second,
		Times:    1,
		Quiet:    true,
	}

	require.NoError(t, cmd.Run(center.context(&out)))
	assert.Empty(t, out.String())
}
