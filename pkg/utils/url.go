package utils

import "regexp"

var repoMatch = regexp.MustCompile(`/v2/(\S+)/(?:manifests|blobs|tags|referrers)/`)

// RepoFromPath returns a repository from a registry API path
func RepoFromPath(path string) string {
	match := repoMatch.FindStringSubmatch(path)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}
