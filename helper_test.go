package rolewait_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/rolewait"
)

const (
	startURL    = "https://example.awsapps.com/start"
	sessionName = "example-session"
	accountID   = "123456789012"
)

// testConfig covers the two ways a profile can name an Identity Center
// session, which are cached under different keys, and one profile rolewait has
// to refuse.
const testConfig = `
[profile example]
sso_session = ` + sessionName + `
sso_account_id = ` + accountID + `
sso_role_name = ReadOnlyAccess
region = ap-northeast-1

[sso-session ` + sessionName + `]
sso_start_url = ` + startURL + `
sso_region = us-east-1

[profile legacy]
sso_start_url = ` + startURL + `
sso_region = us-east-1
sso_account_id = ` + accountID + `
sso_role_name = ReadOnlyAccess

[profile keys]
aws_access_key_id = AKIAEXAMPLE
aws_secret_access_key = secret
`

// reply is one answer from the stub: either the permission sets the account
// has, or the refusal Identity Center returns instead.
type reply struct {
	Roles []string

	// Next, when set, is returned as the page token, so the paginator asks
	// again and the following reply serves the next page.
	Next string

	Status  int
	ErrType string
}

// forbidden is how the portal answers about an account the user has no
// assignment in at all, which is what an account looks like before an
// elevation reaches Identity Center.
var forbidden = reply{Status: 403, ErrType: "ForbiddenException"}

// portal is a stub of the one call rolewait makes.
type portal struct {
	// URL is where the stub is listening.
	URL string

	// Requests is every request that arrived, for tests that care what was
	// asked rather than what came back.
	Requests []*http.Request

	replies []reply
	mu      sync.Mutex
}

// startPortal starts a stub that answers ListAccountRoles with replies in
// order. The last one is repeated for as long as the wait keeps asking, so a
// test only has to say what changes.
func startPortal(t *testing.T, replies ...reply) *portal {
	t.Helper()

	center := &portal{replies: replies}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		center.mu.Lock()
		rep := center.replies[min(len(center.Requests), len(center.replies)-1)]
		center.Requests = append(center.Requests, r)
		center.mu.Unlock()

		if rep.Status != 0 {
			w.Header().Set("X-Amzn-Errortype", rep.ErrType)
			w.WriteHeader(rep.Status)
			json.NewEncoder(w).Encode(map[string]any{"message": "denied"}) //nolint:errcheck

			return
		}

		roles := make([]map[string]any, 0, len(rep.Roles))

		for _, role := range rep.Roles {
			roles = append(roles, map[string]any{"roleName": role, "accountId": accountID})
		}

		body := map[string]any{"roleList": roles}

		if rep.Next != "" {
			body["nextToken"] = rep.Next
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body) //nolint:errcheck
	}))

	t.Cleanup(server.Close)
	center.URL = server.URL

	return center
}

// context returns a Context that talks to the stub and reports to out.
//
// Overriding the endpoint is enough here, unlike a tool that has to resolve
// credentials first: the portal clients are built from this configuration, so
// there is nothing that could have been created before it.
func (center *portal) context(out io.Writer) *rolewait.Context {
	return &rolewait.Context{
		Out: out,
		Config: aws.Config{
			BaseEndpoint: aws.String(center.URL),
			// The stub answers straight away, so a retry would only be the
			// test waiting on a backoff it did not ask for. It also keeps the
			// request counts a test asserts on meaning what they say.
			RetryMaxAttempts: 1,
		},
	}
}

// count returns how many requests the stub has answered.
func (center *portal) count() int {
	center.mu.Lock()
	defer center.mu.Unlock()

	return len(center.Requests)
}

// isolateAWS points the AWS configuration at a temporary directory holding
// config, so whatever the machine running the tests has in ~/.aws cannot take
// part. The directory it returns stands in for the home directory, and is
// where a cached SSO token is looked for.
func isolateAWS(t *testing.T, config string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	require.NoError(t, os.WriteFile(path, []byte(config), 0600))

	t.Setenv("HOME", dir)
	t.Setenv("AWS_CONFIG_FILE", path)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))

	// A profile the machine running the tests happens to export would
	// otherwise be waited for instead of the one under test.
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")

	return dir
}

// writeToken puts body where the AWS CLI would have cached a token for key,
// under the given home directory.
func writeToken(t *testing.T, home, key, body string) {
	t.Helper()

	path, err := ssocreds.StandardCachedTokenFilepath(key)
	require.NoError(t, err)
	require.Equal(t, home, path[:len(home)], "the cache path must be inside the test home directory")

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
}

// signedIn writes a cached token that has not expired for the sso-session the
// example profile names.
func signedIn(t *testing.T, config string) {
	t.Helper()

	writeToken(t, isolateAWS(t, config), sessionName, validToken())
}

// validToken is a cached token that has not expired.
func validToken() string {
	return `{"accessToken":"the-token","expiresAt":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`
}

// expiredToken is a cached token from a session that has since ended, with no
// refresh token, so signing in again is the only way out.
func expiredToken() string {
	return `{"accessToken":"the-token","expiresAt":"2020-01-01T00:00:00Z"}`
}
