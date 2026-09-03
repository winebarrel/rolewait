# rolewait

[![CI](https://github.com/winebarrel/rolewait/actions/workflows/ci.yml/badge.svg)](https://github.com/winebarrel/rolewait/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/winebarrel/rolewait/branch/main/graph/badge.svg)](https://codecov.io/gh/winebarrel/rolewait)
[![AI Generated](https://img.shields.io/badge/AI%20Generated-Claude-orange?logo=anthropic)](https://claude.ai/claude-code)

Wait until an IAM Identity Center permission set can be assumed.

A permission set granted through privileged access management — Entra PIM
activating a group, or anything else that ends in an assignment being
provisioned into Identity Center — is not usable the moment the request is
approved. It appears seconds or minutes later, and until it does every command
that needs it fails with an error about access that looks exactly like having
asked for the wrong thing.

`rolewait` blocks until the assignment arrives, so you can put it in front of
the work that depends on it instead of retrying by hand.

## Installation

Download an archive for your platform from the
[releases page](https://github.com/winebarrel/rolewait/releases) and put the
`rolewait` binary somewhere on your `PATH`:

```
tar xzf rolewait_...tar.gz
install rolewait /usr/local/bin/
```

Or build it yourself with Go 1.27 or later:

```
go install github.com/winebarrel/rolewait/cmd/rolewait@latest
```

## Usage

```
Usage: rolewait [flags]

Flags:
  -h, --help                   Show context-sensitive help.
      --version
  -p, --profile=STRING         Profile naming the account and the permission set
                               to wait for ($AWS_PROFILE).
  -r, --role=STRING            Permission set to wait for, if not the one the
                               profile names.
  -a, --alias=KEY=VALUE,...    Short names for permission sets, as
                               'short=PermissionSetName' ($ROLEWAIT_ALIAS,
                               $SR_ALIAS).
  -i, --interval=1s            How long to wait between checks.
  -t, --timeout=10m            Give up after this long.
  -n, --times=2                Consecutive successful checks before the wait is
                               over.
  -q, --quiet                  Say nothing.
```

Approve the elevation, then wait for it to land and get on with the work:

```
$ rolewait -p example -r AdministratorAccess && terraform apply
waiting for AdministratorAccess in 123456789012, checking every 1s, giving up after 10m0s
AdministratorAccess is available in 123456789012 after 42s
```

Progress goes to stderr, so nothing has to be filtered out of what follows.
`-q` turns it off.

Everything `rolewait` needs is in `~/.aws/config` already, since it is the same
profile the work after the wait will use. `-r` is there because the profile you
have is usually the unprivileged one — leave it off to wait for the permission
set the profile itself names:

```
$ rolewait -p admin
```

Without `-p`, the profile comes from `AWS_PROFILE` as usual:

```
$ AWS_PROFILE=example rolewait -r AdministratorAccess
```

### Aliases

Permission set names are long and repetitive to type. `ROLEWAIT_ALIAS` gives
them short names:

```sh
export ROLEWAIT_ALIAS='ro=ReadOnlyAccess,admin=AdministratorAccess,po=PowerUserAccess'
```

```
$ rolewait -p example -r admin && terraform apply
```

`SR_ALIAS` is read as a fallback, so anyone already using
[sr](https://github.com/winebarrel/sr) alongside `rolewait` — waiting for a
permission set and then running something against it are two halves of the same
job — does not have to define the same short names twice under two variables
and keep them agreeing:

```sh
export SR_ALIAS='ro=ReadOnlyAccess,admin=AdministratorAccess'
```

```
$ rolewait -p example -r admin && sr -p example -r admin terraform apply
```

`ROLEWAIT_ALIAS` wins wherever it is set, including when it is set to nothing.

The expansion is purely local — a name is either an alias you defined or the
permission set name itself. `rolewait` never asks Identity Center what the
short names could have meant, so there is no partial matching to be surprised
by, and a name that is neither is waited for as written:

```
$ rolewait -p example -r adnim
waiting for adnim in 123456789012, checking every 1s, giving up after 10m0s
```

## What it does

Once, before waiting:

1. Reads the profile the way any other AWS tool reads it, and takes the account
   and the permission set from it.
2. Reads the SSO access token the AWS CLI cached under `~/.aws/sso/cache`,
   refreshing it if it has expired and can be refreshed.

Then, every `--interval` until `--timeout`:

3. Calls `sso:ListAccountRoles` for the account and looks for the permission
   set by name.

`ListAccountRoles` is the only call it makes. Nothing is assumed and no
credentials are fetched, so nothing is left in `~/.aws/cli/cache` for the next
command to pick up in place of asking for itself — and a cached set of
credentials from before the elevation cannot make the wait finish early either.

It will not sign you in: that means opening a browser and waiting for someone
to come back to it, which is the one thing a command meant to wait unattended
must not do. If there is no cached token, or it is too old to refresh, it says
so and stops:

```
$ rolewait -p example -r AdministratorAccess
rolewait: error: failed to read cached SSO token file, ...: run `aws sso login`
```

### Why it checks more than once

`--times` defaults to 2: the permission set has to be seen twice in a row
before the wait is over. Provisioning an assignment is not atomic as far as the
portal API is concerned, and a single sighting can be followed by the role going
missing again — which is worse than waiting one more interval, because it hands
the work that follows a failure that looks like a permissions bug.

### What counts as "not yet"

An account you have no assignment in at all is not visible, and the portal
answers `ForbiddenException` rather than an empty list — which is exactly what
an account looks like before an elevation lands, so it is treated as "not yet"
and waited out. Being asked to slow down (`TooManyRequestsException`) is waited
out too, since the next check was about to sleep anyway.

Anything else is reported at once rather than waited out, because it will say
the same thing however long anyone waits — a mistyped account, or a session
that ended while the wait was running:

```
$ rolewait -p example -r AdministratorAccess
waiting for AdministratorAccess in 123456789012, checking every 1s, giving up after 10m0s
rolewait: error: operation error SSO: ListAccountRoles, ... UnauthorizedException: ...: run `aws sso login`
```

### Exit status

`0` once the permission set is there, non-zero otherwise — including on
timeout — so `&&` does the right thing.
