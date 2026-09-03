package rolewait

// resolveRole expands a short name that stands in for a permission set.
//
// The expansion is local: a name is either a key of the alias map or already
// the permission set name. Asking Identity Center what the account has is what
// the wait itself does, and doing it here as well would only mean failing
// before the thing being waited for has had its chance to arrive.
//
// An empty name is left alone. It is not something anyone aliased: it means
// nothing was passed, and the permission set the profile itself names is the
// one to wait for.
func resolveRole(name string, alias map[string]string) string {
	if name == "" {
		return ""
	}

	if full, ok := alias[name]; ok {
		return full
	}

	return name
}
