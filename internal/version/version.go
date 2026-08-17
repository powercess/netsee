// Package version exposes the build version, overridable at build time.
package version

// Version is set at build time via
//
//	-ldflags "-X netsee/internal/version.Version=v0.1.0".
//
// It defaults to "dev" for local builds.
var Version = "dev"
