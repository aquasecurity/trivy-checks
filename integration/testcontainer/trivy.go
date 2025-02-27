package testcontainer

import (
	"context"
	"fmt"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type TrivyContainer struct {
	testcontainers.Container
}

func RunTrivy(ctx context.Context, image string, cmd []string, opts ...testcontainers.ContainerCustomizer) (*TrivyContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:           image,
		Cmd:             cmd,
		AlwaysPullImage: true,
		WaitingFor:      wait.ForExit(),
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

	return &TrivyContainer{Container: c}, nil
}
