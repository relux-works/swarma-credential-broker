//go:build linux

package authowner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Claim: caching the fixture measurement never bypasses the real owner digest
// check. A matching executable copy admits; changing one byte refuses New.
func TestFixtureExecutableDigestRechecked(t *testing.T) {
	f := newFixture(t, "rotate")
	f.e.Close()
	image, err := os.ReadFile(fakeExecutable)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vendor")
	if err = os.WriteFile(path, image, 0700); err != nil {
		t.Fatal(err)
	}
	c := f.c
	c.Executable = path
	e, err := New(context.Background(), c, f.m, f.t, fakeClassifier{})
	if err != nil {
		t.Fatal("matching copy control", err)
	}
	e.Close()
	image[len(image)-1] ^= 1
	if err = os.WriteFile(path, image, 0700); err != nil {
		t.Fatal(err)
	}
	e, err = New(context.Background(), c, f.m, f.t, fakeClassifier{})
	if e != nil {
		e.Close()
	}
	if err != ErrUnavailable || e != nil {
		t.Fatal("changed executable admitted", err)
	}
}
