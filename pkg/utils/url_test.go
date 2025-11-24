package utils

import "testing"

func TestRepoFromPath(t *testing.T) {
	var pathTests = []struct {
		name string
		path string
	}{
		{"manifests", "/manifests/latest"},
		{"blobs", "/blobs/abc"},
		{"tags", "/tags/latest"},
		{"referrers", "/referrers/efg"},
	}
	repo := "testrepo"
	for _, tt := range pathTests {
		t.Run(tt.name, func(t *testing.T) {
			got := RepoFromPath("/v2/" + repo + tt.path)
			if got != repo {
				t.Errorf("Expected repo %s, but got %s", repo, got)
			}
		})
	}
}
