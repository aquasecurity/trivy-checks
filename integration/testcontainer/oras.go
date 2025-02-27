package testcontainer

import (
	"context"
	"fmt"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type OrasContainer struct {
	testcontainers.Container
}

func RunOras(ctx context.Context, cmd []string, opts ...testcontainers.ContainerCustomizer) (*OrasContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:      "bitnami/oras:latest",
		Cmd:        cmd,
		WaitingFor: wait.ForExit(),
	}

	genericReq := testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	}

	for _, opt := range opts {
		if err := opt.Customize(&genericReq); err != nil {
			return nil, err
		}
	}

	c, err := testcontainers.GenericContainer(ctx, genericReq)
	if err != nil {
		return nil, fmt.Errorf("create generic container: %w", err)
	}

	return &OrasContainer{
		Container: c,
	}, err
}
