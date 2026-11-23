package utils

import "regexp"

// registryPath is the only repository path this proxy authorizes.
// It is anchored and segment-bounded: exactly
// /v2/<quay-namespace>/<ocp-namespace>/<component>/(manifests|blobs|tags|referrers)/<reference>.
// A greedy match would treat later path segments as part of the repository while the
// original path is forwarded upstream.
var registryPath = regexp.MustCompile(`^/v2/([^/]+)/([^/]+)/([^/]+)/(manifests|blobs|tags|referrers)/([^/]+)$`)

// RepoFromPath returns the repository for a registry API path that matches registryPath.
// Requests that do not match return an empty string and must be rejected.
func RepoFromPath(path string) string {
	match := registryPath.FindStringSubmatch(path)
	if len(match) != 6 {
		return ""
	}
	quayNamespace, ocpNamespace, component, reference := match[1], match[2], match[3], match[5]
	if !validPathSegment(quayNamespace) || !validPathSegment(ocpNamespace) || !validPathSegment(component) || !validPathSegment(reference) {
		return ""
	}
	return quayNamespace + "/" + ocpNamespace + "/" + component
}

func validPathSegment(segment string) bool {
	return segment != "." && segment != ".."
}
