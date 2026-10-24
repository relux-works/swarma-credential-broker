//go:build !linux

package timeconf

// CollectorEntry is inert on platforms without the Linux system collector.
func CollectorEntry() {}
