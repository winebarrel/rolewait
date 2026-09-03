package rolewait_test

import (
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/rolewait"
)

// TestCmdRunForbidden covers the account being invisible rather than the
// permission set being absent, which is what an account with no assignment at
// all answers, and so what an elevation looks like before it lands.
func TestCmdRunForbidden(t *testing.T) {
	center := startPortal(t,
		forbidden,
		forbidden,
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
	assert.Equal(t, 3, center.count())
}

// TestCmdRunThrottled covers being asked to slow down. The wait is about to
// sleep anyway, so there is nothing to be gained by failing over it.
func TestCmdRunThrottled(t *testing.T) {
	center := startPortal(t,
		reply{Status: 429, ErrType: "TooManyRequestsException"},
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
}

// TestCmdRunConsecutive covers the permission set going missing again after
// being seen once. Provisioning is not atomic as far as the portal API is
// concerned, and returning on the first sighting would hand the work that
// follows a failure that looks like a permissions bug.
func TestCmdRunConsecutive(t *testing.T) {
	center := startPortal(t,
		reply{Roles: []string{"AdministratorAccess"}},
		reply{Roles: []string{"ReadOnlyAccess"}},
		reply{Roles: []string{"AdministratorAccess"}},
		reply{Roles: []string{"AdministratorAccess"}},
	)

	signedIn(t, testConfig)

	cmd := &rolewait.Cmd{
		Profile:  "example",
		Role:     "AdministratorAccess",
		Interval: time.Millisecond,
		Timeout:  10 * time.Second,
		Times:    2,
	}

	require.NoError(t, cmd.Run(center.context(io.Discard)))

	// The count that started at the first reply was given up at the second, so
	// the wait ran to the fourth rather than stopping at the third.
	assert.Equal(t, 4, center.count())
}

// TestCmdRunTimeout covers an elevation that never arrives.
func TestCmdRunTimeout(t *testing.T) {
	center := startPortal(t, reply{Roles: []string{"ReadOnlyAccess"}})

	signedIn(t, testConfig)

	cmd := &rolewait.Cmd{
		Profile:  "example",
		Role:     "AdministratorAccess",
		Interval: time.Millisecond,
		Timeout:  50 * time.Millisecond,
		Times:    1,
	}

	err := cmd.Run(center.context(io.Discard))

	assert.ErrorContains(t, err, "AdministratorAccess is still not available in "+accountID+" after 50ms")
	assert.Positive(t, center.count())
}

// TestCmdRunFatal covers what the wait must not sit through: an answer that
// will say the same thing however long anyone waits.
func TestCmdRunFatal(t *testing.T) {
	tests := []struct {
		name   string
		reply  reply
		errMsg string
	}{
		{
			// The session ended while the wait was running. Nothing rolewait
			// can do about it, and not something to wait out.
			name:   "session expired mid-wait",
			reply:  reply{Status: 401, ErrType: "UnauthorizedException"},
			errMsg: "run `aws sso login`",
		},
		{
			name:   "malformed request",
			reply:  reply{Status: 400, ErrType: "InvalidRequestException"},
			errMsg: "InvalidRequestException",
		},
		{
			name:   "no such account",
			reply:  reply{Status: 404, ErrType: "ResourceNotFoundException"},
			errMsg: "ResourceNotFoundException",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			center := startPortal(t, tt.reply)

			signedIn(t, testConfig)

			cmd := &rolewait.Cmd{
				Profile:  "example",
				Role:     "AdministratorAccess",
				Interval: time.Millisecond,
				Timeout:  10 * time.Second,
				Times:    1,
			}

			err := cmd.Run(center.context(io.Discard))

			assert.ErrorContains(t, err, tt.errMsg)

			// Reported at once rather than waited out.
			assert.Equal(t, 1, center.count())
		})
	}
}

// TestCmdRunErrors covers what stops the wait from starting at all. None of it
// reaches Identity Center.
func TestCmdRunErrors(t *testing.T) {
	// waiting is a command that would poll, for the cases that are refused
	// before it gets to.
	waiting := rolewait.Cmd{
		Role:     "AdministratorAccess",
		Interval: time.Millisecond,
		Timeout:  10 * time.Second,
		Times:    1,
	}

	tests := []struct {
		name   string
		cmd    rolewait.Cmd
		key    string
		token  string
		errMsg string
	}{
		{
			// Nobody has signed in on this machine, or the session was logged
			// out.
			name:   "not signed in",
			cmd:    rolewait.Cmd{Profile: "example"},
			errMsg: "run `aws sso login`",
		},
		{
			name:   "expired session",
			cmd:    rolewait.Cmd{Profile: "example"},
			key:    sessionName,
			token:  expiredToken(),
			errMsg: "run `aws sso login`",
		},
		{
			// The token was cached for a different session, so as far as this
			// profile is concerned there is none.
			name:   "signed in to another session",
			cmd:    rolewait.Cmd{Profile: "example"},
			key:    startURL,
			token:  validToken(),
			errMsg: "run `aws sso login`",
		},
		{
			// There is no assignment to wait for, and asking about it would
			// only fail later and less clearly.
			name:   "not an sso profile",
			cmd:    rolewait.Cmd{Profile: "keys"},
			key:    sessionName,
			token:  validToken(),
			errMsg: "profile keys does not use IAM Identity Center",
		},
		{
			name:   "unknown profile",
			cmd:    rolewait.Cmd{Profile: "nope"},
			key:    sessionName,
			token:  validToken(),
			errMsg: "failed to get shared config profile, nope",
		},
		{
			// A ticker cannot be built from a zero interval, and a wait that
			// never checks would not be one anyway.
			name:   "no interval",
			cmd:    rolewait.Cmd{Profile: "example", Timeout: time.Second, Times: 1},
			key:    sessionName,
			token:  validToken(),
			errMsg: "--interval and --timeout must be positive",
		},
		{
			name:   "no timeout",
			cmd:    rolewait.Cmd{Profile: "example", Interval: time.Millisecond, Times: 1},
			key:    sessionName,
			token:  validToken(),
			errMsg: "--interval and --timeout must be positive",
		},
		{
			// A wait that is over before it looked is not a wait.
			name:   "no sightings required",
			cmd:    rolewait.Cmd{Profile: "example", Interval: time.Millisecond, Timeout: time.Second},
			key:    sessionName,
			token:  validToken(),
			errMsg: "--times at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			center := startPortal(t, reply{Roles: []string{"AdministratorAccess"}})

			home := isolateAWS(t, testConfig)

			if tt.token != "" {
				writeToken(t, home, tt.key, tt.token)
			}

			cmd := tt.cmd

			// The cases about the profile and the token would otherwise have
			// no interval to poll on, and would be refused for that instead.
			if cmd.Interval == 0 && cmd.Timeout == 0 && cmd.Times == 0 {
				cmd.Interval, cmd.Timeout, cmd.Times = waiting.Interval, waiting.Timeout, waiting.Times
			}

			cmd.Role = waiting.Role

			err := cmd.Run(center.context(io.Discard))

			assert.ErrorContains(t, err, tt.errMsg)
			assert.Zero(t, center.count())
		})
	}
}
