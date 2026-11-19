package assemblyv0

import (
	"context"
	"io/fs"
)

type ProtectedFilePolicy struct {
	UID      uint32
	GID      uint32
	Mode     fs.FileMode
	Links    uint64
	MaxBytes int64
}

type FileIdentity struct {
	Device uint64
	Inode  uint64
	UID    uint32
	GID    uint32
	Mode   fs.FileMode
	Links  uint64
	Size   int64
}

type ProtectedRead interface {
	Read(context.Context, string, ProtectedFilePolicy) (FileIdentity, []byte, error)
}

type ConfigGate interface {
	WithRead(context.Context, func(context.Context) error) error
}
