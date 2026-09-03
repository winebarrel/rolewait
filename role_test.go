package rolewait_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/rolewait"
)

// TestCmdRunAlias covers a short name standing in for a permission set. The
// expansion is local, so what the wait looks for is the full name -- which is
// what the stub is given, and what the wait says it found.
func TestCmdRunAlias(t *testing.T) {
	tests := []struct {
		name     string
		role     string
		alias    map[string]string
		expected string
	}{
		{
			name:     "alias",
			role:     "admin",
			alias:    map[string]string{"admin": "AdministratorAccess"},
			expected: "AdministratorAccess",
		},
		{
			// A permission set name is always usable as written, whether or
			// not anyone has given it a short name.
			name:     "full name passes through",
			role:     "AdministratorAccess",
			alias:    map[string]string{"admin": "AdministratorAccess"},
			expected: "AdministratorAccess",
		},
		{
			// Matching is exact, and so is Identity Center: a permission set
			// differing only in case is a different permission set, and
			// guessing at the case here would mean waiting for one while
			// reporting the other.
			name:     "case must match",
			role:     "Admin",
			alias:    map[string]string{"admin": "AdministratorAccess"},
			expected: "Admin",
		},
		{
			// Aliases are read from the environment, so there are often none.
			name:     "no aliases",
			role:     "AdministratorAccess",
			expected: "AdministratorAccess",
		},
		{
			// Nothing was passed, so the permission set the profile names is
			// the one to wait for. There is no name here to expand, whatever
			// the alias map claims about the absence of one.
			name:     "nothing to expand",
			alias:    map[string]string{"": "AdministratorAccess"},
			expected: "ReadOnlyAccess",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			center := startPortal(t, reply{Roles: []string{tt.expected}})

			signedIn(t, testConfig)

			var out bytes.Buffer

			cmd := &rolewait.Cmd{
				Profile:  "example",
				Role:     tt.role,
				Alias:    tt.alias,
				Interval: time.Millisecond,
				Timeout:  10 * time.Second,
				Times:    1,
			}

			require.NoError(t, cmd.Run(center.context(&out)))

			assert.Equal(t, 1, center.count())
			assert.Contains(t, out.String(), tt.expected+" is available in "+accountID)
		})
	}
}

// TestCmdRunAliasUnknown covers a short name nobody defined. It is taken for a
// permission set name, which is the only other thing it could be, and the wait
// says which name it is waiting for so that a typo is visible from the start.
func TestCmdRunAliasUnknown(t *testing.T) {
	center := startPortal(t, reply{Roles: []string{"AdministratorAccess"}})

	signedIn(t, testConfig)

	cmd := &rolewait.Cmd{
		Profile:  "example",
		Role:     "adnim",
		Alias:    map[string]string{"admin": "AdministratorAccess"},
		Interval: time.Millisecond,
		Timeout:  50 * time.Millisecond,
		Times:    1,
	}

	err := cmd.Run(center.context(nil))

	assert.ErrorContains(t, err, "adnim is still not available in "+accountID)
}
