//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aquasecurity/trivy-checks/integration/testcontainer"
)

// localTrivyBinary points to a locally built trivy binary. When set, the test
// runs against that binary instead of pulling release images, which simplifies
// local development against unreleased trivy changes.
var localTrivyBinary = os.Getenv("TRIVY_BINARY")

// trivyTarget abstracts how trivy is invoked: either via a locally built
// binary (TRIVY_BINARY) or in a container pinned to a released version. The
// mode is selected once by newTrivyTarget, so the test body stays free of
// per-call branching.
type trivyTarget interface {
	// VersionJSON returns the output of `trivy version -f json`.
	VersionJSON() ([]byte, error)
	// Run executes trivy with the given args and returns the combined output,
	// with a non-nil error when trivy exits with a non-zero code.
	Run(args []string) ([]byte, error)
	// BasePath is the path prefix used for --output and the scan target.
	BasePath() string
}

// newTrivyTarget selects the target based on the TRIVY_BINARY environment variable.
func newTrivyTarget(ctx context.Context, version, targetDir string) trivyTarget {
	if localTrivyBinary != "" {
		return localTrivy{binary: localTrivyBinary, targetDir: targetDir}
	}
	return containerTrivy{ctx: ctx, version: version, targetDir: targetDir}
}

// localTrivy runs trivy via a local binary on the host.
type localTrivy struct {
	binary    string
	targetDir string
}

func (l localTrivy) VersionJSON() ([]byte, error) {
	return exec.Command(l.binary, "version", "-f", "json", "-q").Output()
}

func (l localTrivy) Run(args []string) ([]byte, error) {
	return exec.Command(l.binary, args...).CombinedOutput()
}

func (l localTrivy) BasePath() string { return l.targetDir }

// containerTrivy runs trivy in a container pinned to a released version.
// targetDir is mounted at /testdata.
type containerTrivy struct {
	ctx       context.Context
	version   string
	targetDir string
}

func (c containerTrivy) BasePath() string { return "/testdata" }

func (c containerTrivy) VersionJSON() ([]byte, error) {
	trivy, err := testcontainer.RunTrivy(c.ctx, "aquasec/trivy:"+c.version,
		[]string{"version", "-f", "json", "-q"},
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				WaitingFor: wait.ForExit(),
			},
		}),
	)
	if err != nil {
		return nil, err
	}
	defer trivy.Terminate(c.ctx)

	rc, err := trivy.Logs(c.ctx)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(rc)
}

func (c containerTrivy) Run(args []string) ([]byte, error) {
	trivy, err := testcontainer.RunTrivy(c.ctx, "aquasec/trivy:"+c.version, args,
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				AlwaysPullImage: false,
			},
		}),
		testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
			hc.NetworkMode = "host"
			hc.Mounts = []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: c.targetDir,
					Target: "/testdata",
				},
			}
		}),
	)
	if err != nil {
		return nil, err
	}
	defer trivy.Terminate(c.ctx)

	rc, err := trivy.Logs(c.ctx)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}

	state, err := trivy.State(c.ctx)
	if err != nil {
		return b, err
	}
	if state.ExitCode != 0 {
		return b, fmt.Errorf("trivy exited with code %d", state.ExitCode)
	}
	return b, nil
}
