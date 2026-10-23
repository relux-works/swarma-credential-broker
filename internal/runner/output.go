package runner

import (
	"context"
	"os"
	"path/filepath"
)

type outputFile struct {
	root         *os.Root
	file         *os.File
	target, temp string
	before       os.FileInfo
}

func prepareOutput(path string) (*outputFile, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, refuse("output_unavailable", 75)
	}
	o := &outputFile{root: root, target: filepath.Base(path)}
	fail := func() (*outputFile, error) { o.abort(); return nil, refuse("output_unavailable", 75) }
	info, err := root.Lstat(o.target)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0222 == 0 {
			return fail()
		}
		o.before = info
	} else if !os.IsNotExist(err) {
		return fail()
	}
	// An actual exclusive create tests directory writability, including ACLs.
	for i := 0; i < 10; i++ {
		o.temp = ".run-codex-output-" + randomID()
		o.file, err = root.OpenFile(o.temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			return o, nil
		}
		if !os.IsExist(err) {
			return fail()
		}
	}
	return fail()
}
func (o *outputFile) abort() {
	if o.file != nil {
		o.file.Close()
		o.file = nil
	}
	if o.root != nil {
		if o.temp != "" {
			o.root.Remove(o.temp)
		}
		o.root.Close()
		o.root = nil
	}
}
func (o *outputFile) commit(ctx context.Context, data []byte) error {
	info, err := o.root.Lstat(o.target)
	if o.before == nil {
		if !os.IsNotExist(err) {
			return refuse("output_unavailable", 75)
		}
	} else if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, o.before) {
		return refuse("output_unavailable", 75)
	}
	if _, err = o.file.Write(data); err != nil {
		return refuse("output_unavailable", 75)
	}
	if err = o.file.Sync(); err != nil {
		return refuse("output_unavailable", 75)
	}
	if err = o.file.Close(); err != nil {
		o.file = nil
		return refuse("output_unavailable", 75)
	}
	o.file = nil
	// Staging I/O may overlap a stop. Check again after it, immediately before
	// admitting atomic replacement. A successful rename wins a concurrent stop.
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = o.root.Rename(o.temp, o.target); err != nil {
		return refuse("output_unavailable", 75)
	}
	// Rename is the publication point; no fallible operation follows it.
	o.temp = ""
	return nil
}
