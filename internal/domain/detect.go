package domain

// DetectCollision compares an internal package against a public one and reports
// whether a dependency-confusion collision exists.
//
// Two collision types are recognized at MVP:
//   - Exact: the names are byte-identical (case-sensitive).
//   - Namespace: an internal scoped name (e.g. "@acme/auth") shares its scope
//     prefix with a public package under the same scope.
//
// Similarity-based detection (acme-auth vs acme-authentication) is intentionally
// NOT performed here; per the spec it requires human review and is deferred to V2
// because automated fuzzy matching produces unacceptable false positives at scale.
//
// Returns (collision, true) when a collision exists, (nil, false) otherwise.
// public may be nil when the registry reported the package does not exist.
func DetectCollision(internal InternalPackage, public *PackageInfo) (*Collision, bool) {
	if public == nil {
		return nil, false
	}
	if internal.Name == public.Name {
		return &Collision{Internal: internal, Public: *public, Type: CollisionExact}, true
	}
	if isNamespaceCollision(internal.Name, public.Name) {
		return &Collision{Internal: internal, Public: *public, Type: CollisionNamespace}, true
	}
	return nil, false
}

// isNamespaceCollision reports whether two scoped names share the same scope. A
// scope is the leading "@scope/" segment. Unscoped names never collide by
// namespace. Example: "@acme/auth" and "@acme/utils" share scope "@acme/".
func isNamespaceCollision(a, b string) bool {
	as, ai := splitScope(a)
	bs, bi := splitScope(b)
	if as == "" || bs == "" {
		return false
	}
	return as == bs && ai != bi
}

// splitScope returns the scope prefix ("@acme/") and the local name ("auth"). For
// unscoped names it returns ("", name). The scan is linear and allocation-free
// for the common (unscoped) case.
func splitScope(name string) (scope, local string) {
	if len(name) < 2 || name[0] != '@' {
		return "", name
	}
	for i := 1; i < len(name); i++ {
		if name[i] == '/' {
			return name[:i+1], name[i+1:]
		}
	}
	return "", name
}
