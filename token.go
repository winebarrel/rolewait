package rolewait

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
)

// accessToken returns the SSO access token the AWS CLI cached for the session.
//
// Refreshing an expired token is the SDK's business and happens here if the
// cached one carries a refresh token, exactly as it would for any other AWS
// tool. Signing in is not: that means opening a browser and waiting for
// someone to come back to it, which is the one thing a command whose whole job
// is to wait unattended must not do. Every way this can fail -- no cached
// token, an unreadable one, one too old to refresh -- is answered by the same
// sign-in, so they are all reported the same way.
func accessToken(ctx context.Context, cfg aws.Config, cacheKey string) (string, error) {
	path, err := ssocreds.StandardCachedTokenFilepath(cacheKey)

	if err != nil {
		return "", err
	}

	token, err := ssocreds.NewSSOTokenProvider(ssooidc.NewFromConfig(cfg), path).RetrieveBearerToken(ctx)

	if err != nil {
		return "", fmt.Errorf("%w: run `aws sso login`", err)
	}

	return token.Value, nil
}
