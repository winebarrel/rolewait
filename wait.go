package rolewait

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/smithy-go"
)

// listAccountRoles is the one call the wait makes.
type listAccountRoles interface {
	ListAccountRoles(context.Context, *sso.ListAccountRolesInput, ...func(*sso.Options)) (*sso.ListAccountRolesOutput, error)
}

// wait polls until the permission set has been assigned, or gives up.
//
// Nothing is assumed and no credentials are fetched: listing is what the
// question actually is, and it leaves nothing behind in ~/.aws/cli/cache for
// the command that runs next to pick up in place of asking for itself.
//
// The permission set has to be seen Times times in a row. Provisioning an
// assignment is not atomic as far as the portal API is concerned, and a single
// sighting can be followed by the role going missing again, which is worse
// than waiting one more interval: it hands the work that follows a failure
// that looks like a permissions bug.
func (cmd *Cmd) wait(ctx context.Context, client listAccountRoles, tgt target, token string) error {
	ticker := time.NewTicker(cmd.Interval)
	defer ticker.Stop()

	seen := 0

	for {
		found, err := assigned(ctx, client, tgt, token)

		switch {
		// The deadline is checked first because it arrives as a failure of
		// whichever call was in flight, which says nothing useful.
		case ctx.Err() != nil:
		case err != nil && !pending(err):
			return withLoginHint(err)
		case err != nil, !found:
			seen = 0
		default:
			if seen++; seen >= cmd.Times {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("%s is still not available in %s after %s", tgt.Role, tgt.AccountID, cmd.Timeout)
		case <-ticker.C:
		}
	}
}

// assigned reports whether the permission set is one of those the account has
// for whoever the access token belongs to.
func assigned(ctx context.Context, client listAccountRoles, tgt target, token string) (bool, error) {
	paginator := sso.NewListAccountRolesPaginator(client, &sso.ListAccountRolesInput{
		AccessToken: &token,
		AccountId:   &tgt.AccountID,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)

		if err != nil {
			return false, err
		}

		for _, role := range page.RoleList {
			// Exact, because a permission set differing only in case is a
			// different permission set, and waiting for one while reporting
			// the other is the kind of success nobody can act on.
			if aws.ToString(role.RoleName) == tgt.Role {
				return true, nil
			}
		}
	}

	return false, nil
}

// pending reports whether err is Identity Center saying "not yet" rather than
// something that will still be true however long anyone waits.
//
// An unassigned permission set is usually just absent from the list, but an
// account with no assignments at all for the user is not visible either and
// answers ForbiddenException -- which is exactly what an account looks like
// before an elevation lands, so it is the case that matters most here.
// Throttling is passed over for a different reason: the wait is about to sleep
// anyway, so there is nothing to be gained by failing over it.
func pending(err error) bool {
	var throttled *types.TooManyRequestsException

	if errors.As(err, &throttled) {
		return true
	}

	// The portal API does not model ForbiddenException, so there is no type to
	// match it against.
	var apiErr smithy.APIError

	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "ForbiddenException"
}

// withLoginHint adds the sign-in to an error about the access token.
//
// The token was read before the wait began, so this is a session that ended
// while it was running. It is not a thing to wait out, and it is not a thing
// rolewait can fix.
func withLoginHint(err error) error {
	var unauthorized *types.UnauthorizedException

	if errors.As(err, &unauthorized) {
		return fmt.Errorf("%w: run `aws sso login`", err)
	}

	return err
}
