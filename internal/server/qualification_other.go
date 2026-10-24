//go:build !linux

package server

func qualificationSocket(string) bool { return false }
