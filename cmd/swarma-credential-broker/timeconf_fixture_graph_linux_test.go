//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: the actual default-tag compiled graph for both the broker and standalone
// timeconf contains neither the fixture package nor its tagged source/symbols.
// The production factory retains its original parameters and closed backend.
func TestTimeconfFixtureDefaultBuildContainment(t *testing.T) {
	root := filepath.Join("..", "..")
	graph, err := containmentProductionGraph(t, root, "./timeconf")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := graph[containmentModule+"/timeconf"]; !ok {
		t.Fatal("standalone timeconf absent from compiled graph")
	}
	sources, err := containmentSources(root, graph)
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range containmentTimeFixtures(sources) {
		t.Error(issue)
	}
}

// Claim: a fixture symbol in a real compiled timeconf dependency is rejected;
// removing that symbol restores the identical graph's nearby valid control.
func TestTimeconfFixtureDefaultBuildCompiledPlant(t *testing.T) {
	root, wrapper := containmentWrapperFixture(t, "testdata", false)
	if err := os.Mkdir(filepath.Join(root, "timeconf"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "timeconf", "fixture.go")
	if err := os.WriteFile(path, []byte("package timeconf;type FixtureConsumer struct{}"), 0600); err != nil {
		t.Fatal(err)
	}
	bridge := filepath.Join(root, wrapper, "time.go")
	if err := os.WriteFile(bridge, []byte(`package containmentbridge;import _ "`+containmentModule+`/timeconf"`), 0600); err != nil {
		t.Fatal(err)
	}
	graph, err := containmentProductionGraph(t, root, "./timeconf")
	if err != nil {
		t.Fatal(err)
	}
	sources, err := containmentSources(root, graph)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(containmentTimeFixtures(sources), "\n"), "test-only time fixture in timeconf/fixture.go") {
		t.Fatal("compiled fixture plant not detected")
	}
	if err = os.WriteFile(path, []byte("package timeconf;type ClosedWitness struct{}"), 0600); err != nil {
		t.Fatal(err)
	}
	sources, err = containmentSources(root, graph)
	if err != nil {
		t.Fatal(err)
	}
	if issues := containmentTimeFixtures(sources); len(issues) != 0 {
		t.Fatal("closed backend control rejected", issues)
	}
}
