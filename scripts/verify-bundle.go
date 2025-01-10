package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var bundlePath = "bundle.tar.gz"
var OrasPush = []string{"--artifact-type", "application/vnd.cncf.openpolicyagent.config.v1+json", fmt.Sprintf("%s:application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip", bundlePath)}
var supportedTrivyVersions = []string{"0.57.1", "0.58.1", "latest", "canary"} // TODO: add more versions

func createRegistryContainer(ctx context.Context) (testcontainers.Container, string) {
	reqReg := testcontainers.ContainerRequest{
		Image:        "registry:2",
		ExposedPorts: []string{"5111:5000/tcp"},
		WaitingFor:   wait.ForExposedPort(),
	}

	regC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: reqReg,
		Started:          true,
	})
	if err != nil {
		panic(err)
	}

	regIP, _ := regC.Host(ctx)
	fmt.Println(regIP)

	return regC, regIP
}

func createOrasContainer(ctx context.Context, regIP string, bundlePath string) testcontainers.Container {
	reqOras := testcontainers.ContainerRequest{
		Image: "bitnami/oras:latest",
		Cmd:   append([]string{"push", fmt.Sprintf("%s:5111/defsec-test:latest", regIP)}, OrasPush...),
		HostConfigModifier: func(config *container.HostConfig) {
			config.NetworkMode = "host"
			config.Mounts = []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: bundlePath,
					Target: "/bundle.tar.gz",
				}}
		},
		WaitingFor: wait.ForLog("Pushed [registry] localhost:5111/defsec-test:latest"),
	}
	orasC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: reqOras,
		Started:          true,
	})
	if err != nil {
		panic(err)
	}

	return orasC
}

func createTrivyContainer(ctx context.Context, trivyVersion string, regIP string) testcontainers.Container {
	testDataPath, err := filepath.Abs("testdata")
	if err != nil {
		panic(err)
	}

	reqTrivy := testcontainers.ContainerRequest{
		Image:           fmt.Sprintf("aquasec/trivy:%s", trivyVersion),
		AlwaysPullImage: true,
		Cmd:             []string{"--debug", "config", "--include-deprecated-checks=false", fmt.Sprintf("--checks-bundle-repository=%s:5111/defsec-test:latest", regIP), "/testdata"},
		HostConfigModifier: func(config *container.HostConfig) {
			config.NetworkMode = "host"
			config.Mounts = []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: testDataPath,
					Target: "/testdata",
				},
			}
		},
		WaitingFor: wait.ForLog("OS is not detected."),
	}
	trivyC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: reqTrivy,
		Started:          true,
	})
	if err != nil {
		panic(err)
	}

	return trivyC
}

func debugLogsForContainer(ctx context.Context, c testcontainers.Container) string {
	r, err := c.Logs(ctx)
	if err != nil {
		panic(err)
	}

	b, _ := io.ReadAll(r)
	return string(b)
}

func LoadAndVerifyBundle() {
	ctx := context.Background()

	bundlePath, err := filepath.Abs("bundle.tar.gz")
	if err != nil {
		panic(err)
	}

	regC, regIP := createRegistryContainer(ctx)
	defer func() {
		if err = regC.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	orasC := createOrasContainer(ctx, regIP, bundlePath)
	defer func() {
		if err = orasC.Terminate(ctx); err != nil {
			panic(err)
		}
	}()

	fmt.Println(debugLogsForContainer(ctx, regC))
	fmt.Println(debugLogsForContainer(ctx, orasC))

	for _, trivyVersion := range supportedTrivyVersions {
		fmt.Println("=======Testing version: ", trivyVersion, "==========")
		trivyC := createTrivyContainer(ctx, trivyVersion, regIP)
		fmt.Println(debugLogsForContainer(ctx, trivyC))

		if !assertInLogs(debugLogsForContainer(ctx, trivyC), `Tests: 1 (SUCCESSES: 0, FAILURES: 1)`) {
			panic("asserting Trivy logs for misconfigurations failed, check Trivy log output")
		}

		if err = trivyC.Terminate(ctx); err != nil {
			panic(err)
		}
	}

}

func assertInLogs(containerLogs, assertion string) bool {
	return strings.Contains(containerLogs, assertion)
}

func main() {
	os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	LoadAndVerifyBundle()
}
