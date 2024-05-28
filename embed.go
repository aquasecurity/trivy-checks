package trivy_checks

import (
	"embed"
)

//go:embed checks/*
var EmbeddedPolicyFileSystem embed.FS

//go:embed lib/*
var EmbeddedLibraryFileSystem embed.FS
