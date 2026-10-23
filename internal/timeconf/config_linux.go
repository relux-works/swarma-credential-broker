//go:build linux

package timeconf

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Bound both recursive expansion and directory work, including ignored entries.
const (
	maxConfigDepth       = 8
	maxConfigFiles       = 128
	maxConfigDirectories = 128
	maxConfigEntries     = 4096
	maxConfigBytes       = 1 << 20
)

type configReader struct {
	ctx                                context.Context
	uid                                uint32
	limit                              int
	files, directories, entries, bytes int
}

func collectSources(ctx context.Context, p Policy) (Sources, error) {
	r := configReader{ctx: ctx, uid: uint32(os.Geteuid()), limit: p.MaxOutputBytes}
	var out Sources
	for _, path := range p.SourceFiles {
		sources, err := r.file(path, false, 0)
		if err != nil {
			return Sources{}, ErrUnavailable
		}
		out.Count += sources.Count
		out.Entries = append(out.Entries, sources.Entries...)
	}
	out.AllNTS = true
	return out, nil
}

func (r *configReader) file(path string, sourceOnly bool, depth int) (Sources, error) {
	r.files++
	if depth > maxConfigDepth || r.files > maxConfigFiles || r.ctx.Err() != nil {
		return Sources{}, ErrUnavailable
	}
	b, err := protectedRead(path, r.uid, r.limit, false)
	if err != nil {
		return Sources{}, ErrUnavailable
	}
	r.bytes += len(b)
	if r.bytes > maxConfigBytes {
		return Sources{}, ErrUnavailable
	}
	return parseSources(b, sourceOnly, func(kind string, dirs []string) (Sources, error) { return r.expand(kind, dirs, depth+1) })
}

func (r *configReader) expand(kind string, dirs []string, depth int) (Sources, error) {
	if depth > maxConfigDepth {
		return Sources{}, ErrUnavailable
	}
	suffix := ".conf"
	if kind == "sourcedir" {
		suffix = ".sources"
	}
	// Chrony sorts by basename across the whole directive. When directories
	// contain the same basename, only the first directory's file is effective.
	paths := map[string]string{}
	for _, dir := range dirs {
		names, err := r.directory(dir)
		if err != nil {
			return Sources{}, ErrUnavailable
		}
		for _, name := range names {
			if strings.HasSuffix(name, suffix) && paths[name] == "" {
				paths[name] = filepath.Join(dir, name)
			}
		}
	}
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	sort.Strings(names)
	var out Sources
	for _, name := range names {
		sources, err := r.file(paths[name], kind == "sourcedir", depth)
		if err != nil {
			return Sources{}, ErrUnavailable
		}
		out.Count += sources.Count
		out.Entries = append(out.Entries, sources.Entries...)
	}
	out.AllNTS = true
	return out, nil
}

func (r *configReader) directory(path string) ([]string, error) {
	r.directories++
	if !cleanPath(path) || r.directories > maxConfigDirectories || r.ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	// An absent DHCP directory contributes nothing. On the next sample an
	// appearing directory is opened and checked from scratch, including ancestors.
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, ErrUnavailable
	}
	if pathProtected(path, r.uid) != nil {
		return nil, ErrUnavailable
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !s.IsDir() || s.Mode().Perm()&0022 != 0 {
		return nil, ErrUnavailable
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 && st.Uid != r.uid {
		return nil, ErrUnavailable
	}
	var names []string
	for {
		entries, err := f.ReadDir(128)
		r.entries += len(entries)
		if r.entries > maxConfigEntries || r.ctx.Err() != nil {
			return nil, ErrUnavailable
		}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrUnavailable
		}
	}
	return names, nil
}
