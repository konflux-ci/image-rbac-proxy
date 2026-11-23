package utils

import "testing"

func TestRepoFromPath(t *testing.T) {
	const repo = "org/ns/comp"
	operations := []string{"manifests", "blobs", "tags", "referrers"}
	for _, operation := range operations {
		t.Run(operation, func(t *testing.T) {
			got := RepoFromPath("/v2/" + repo + "/" + operation + "/latest")
			if got != repo {
				t.Errorf("Expected repo %s, but got %s", repo, got)
			}
		})
	}
}

func TestRepoFromPathRejectsUnscopedPaths(t *testing.T) {
	paths := []string{
		"/v2/",
		"/v2/org/manifests/latest",
		"/v2/org/ns/manifests/latest",
		"/v2/org/ns/comp/extra/manifests/latest",
		"/v2/org/ns/../manifests/latest",
		"/v2/./ns/comp/manifests/latest",
		"/v2/org/./comp/manifests/latest",
		"/v2/org/ns/./manifests/latest",
		"/v2/org/ns/comp/manifests/.",
		"/v2/org/ns/comp/manifests/..",
		"/v2/org/ns/comp/manifests/../../other/manifests/latest",
		"/v2/org/ns/comp/manifests/latest/extra",
		"/v2/org/ns/comp/blobs/",
		"prefix/v2/org/ns/comp/manifests/latest",
		"/v2/org/ns/comp/unknown/latest",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			if got := RepoFromPath(path); got != "" {
				t.Errorf("RepoFromPath(%q) = %q, want empty", path, got)
			}
		})
	}
}
