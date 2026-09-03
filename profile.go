package rolewait

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
)

// target is the permission set to wait for, and what it takes to ask about it.
type target struct {
	// AccountID and Role are what ListAccountRoles is asked about.
	AccountID string
	Role      string

	// Region is sso_region. The portal API lives with the Identity Center
	// instance, not in whatever region the profile does its work in.
	Region string

	// CacheKey is what the cached token file is named after: the sso-session
	// name, or the start URL for a profile written before sso-session existed.
	CacheKey string
}

// resolveTarget reads the profile the way any other AWS tool reads it and takes
// from it what identifies the permission set.
//
// Nothing has to be passed on the command line because it is all in
// ~/.aws/config already: the same profile is what the work after the wait will
// use. role, when given, stands in for the profile's sso_role_name -- waiting
// for a permission set the profile does not name is the ordinary case, since
// the profile you have is usually the unprivileged one.
func resolveTarget(ctx context.Context, profile, role string) (target, error) {
	env, err := config.NewEnvConfig()

	if err != nil {
		return target{}, err
	}

	if profile == "" {
		profile = env.SharedConfigProfile
	}

	if profile == "" {
		profile = config.DefaultSharedConfigProfile
	}

	// LoadSharedConfigProfile, unlike LoadDefaultConfig, does not consult the
	// environment for where the files are, so AWS_CONFIG_FILE would otherwise
	// be ignored by rolewait alone.
	shared, err := config.LoadSharedConfigProfile(ctx, profile, func(o *config.LoadSharedConfigOptions) {
		if env.SharedConfigFile != "" {
			o.ConfigFiles = []string{env.SharedConfigFile}
		}

		if env.SharedCredentialsFile != "" {
			o.CredentialsFiles = []string{env.SharedCredentialsFile}
		}
	})

	if err != nil {
		return target{}, err
	}

	if role == "" {
		role = shared.SSORoleName
	}

	// An sso-session profile keeps the start URL and the region in a section
	// several profiles can share; one written before that existed has them
	// inline. Either way, the token cache is named after whichever of the two
	// the AWS CLI signed in with.
	region, cacheKey := shared.SSORegion, shared.SSOStartURL

	if shared.SSOSession != nil {
		region, cacheKey = shared.SSOSession.SSORegion, shared.SSOSession.Name
	}

	// A profile that gets its credentials some other way has no assignment to
	// wait for, and asking Identity Center about it would only fail later and
	// less clearly.
	if shared.SSOAccountID == "" || role == "" || region == "" || cacheKey == "" {
		return target{}, fmt.Errorf("profile %s does not use IAM Identity Center", profile)
	}

	return target{
		AccountID: shared.SSOAccountID,
		Role:      role,
		Region:    region,
		CacheKey:  cacheKey,
	}, nil
}
