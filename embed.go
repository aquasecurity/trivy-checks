package trivy_checks

import (
	"embed"
)

//go:embed checks/*
var EmbeddedPolicyFileSystem embed.FS

//go:embed lib/*
var EmbeddedLibraryFileSystem embed.FS

//go:embed commands/kubernetes
var EmbeddedK8sCommandsFileSystem embed.FS

//go:embed commands/config
var EmbeddedConfigCommandsFileSystem embed.FS
