//go:build integration && k8s

package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/registry"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/kind/pkg/cluster"

	"github.com/aquasecurity/trivy-checks/pkg/compliance"
)

const (
	k8sTrivyVersion   = "latest"
	k8sComplianceSpec = "k8s-cis-1.23"
	kindClusterName   = "trivy-checks"
)

// expectedNodeFailures lists the checks backed by node commands that fail on
// a default kind cluster. All other such checks must pass.
var expectedNodeFailures = []string{
	"KCV-0059", // kubeadm keeps the etcd data directory owned by root:root
	"KCV-0069", // kubeadm writes 10-kubeadm.conf with 644
	"KCV-0077", // kubeadm writes /var/lib/kubelet/config.yaml with 644

	// TODO: remove once the commands are fixed. They fail here because of bugs
	// in the commands, not because of the cluster setup.
	"KCV-0056", // CMD-0009 stats /etc/cni/net.d and /opt/cni/bin instead of the CNI config files
	"KCV-0075", // CMD-0028 reads --client-ca-file of kube-apiserver because its command line contains "kubelet"
}

// TestK8sCompliance runs a compliance scan against a kind cluster, so the node
// commands are executed by node-collector on a real kubeadm node.
func TestK8sCompliance(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp(".", "trivy-checks-k8s-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	targetDir, err := filepath.Abs(tmpDir)
	require.NoError(t, err)

	createKindCluster(t, filepath.Join(targetDir, "kubeconfig"))

	registryContainer, err := registry.Run(ctx, "registry:2")
	require.NoError(t, err)
	t.Cleanup(func() { registryContainer.Terminate(context.TODO()) })

	registryHost, err := registryContainer.HostAddress(ctx)
	require.NoError(t, err)

	bundleImage := registryHost + "/" + "trivy-checks:latest"

	version := k8sTrivyVersion
	if localTrivyBinary != "" {
		version = "local"
	}

	target := newTrivyTarget(ctx, version, targetDir)
	trivyVer := getActualTrivyVersion(t, target)

	bundlePath := buildBundle(t, targetDir, nil, trivyVer)
	pushBundle(t, ctx, bundlePath, bundleImage)

	// Trivy looks up the spec in the default cache dir rather than --cache-dir,
	// so pass it as a file to avoid scanning with the spec embedded in trivy.
	specFile := k8sComplianceSpec + ".yaml"
	specData := []byte(compliance.GetSpec(k8sComplianceSpec))
	require.NotEmpty(t, specData, "spec %s not found", k8sComplianceSpec)
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, specFile), specData, 0o644))

	args := []string{
		"k8s",
		"--kubeconfig", target.Path("kubeconfig"),
		"--checks-bundle-repository", bundleImage,
		"--compliance", "@" + target.Path(specFile),
		"--report", "all",
		"--format", "json",
		"--output", target.Path(reportFileName),
		"--include-non-failures",
		// kind taints the control plane node once the cluster has a worker
		"--tolerations", "node-role.kubernetes.io/control-plane=:NoSchedule",
		"--rego-error-limit", "0",
		"--timeout", "10m",
	}

	runTrivy(t, target, args)

	var spec complianceSpec
	require.NoError(t, yaml.Unmarshal(specData, &spec))

	report := readComplianceReport(t, filepath.Join(targetDir, reportFileName))

	verifyNodeChecks(t, spec, report)
}

func createKindCluster(t *testing.T, kubeconfigPath string) {
	t.Helper()

	// The worker node has no control plane files, so it covers checks that
	// receive empty values from the master commands.
	config := &v1alpha4.Cluster{
		Nodes: []v1alpha4.Node{
			{Role: v1alpha4.ControlPlaneRole},
			{Role: v1alpha4.WorkerRole},
		},
	}

	provider := cluster.NewProvider()
	require.NoError(t, provider.Create(kindClusterName,
		cluster.CreateWithV1Alpha4Config(config),
		cluster.CreateWithWaitForReady(3*time.Minute),
		cluster.CreateWithKubeconfigPath(kubeconfigPath),
		cluster.CreateWithDisplayUsage(false),
		cluster.CreateWithDisplaySalutation(false),
	))
	t.Cleanup(func() { provider.Delete(kindClusterName, kubeconfigPath) })
}

type complianceSpec struct {
	Spec struct {
		Controls []complianceControl `yaml:"controls"`
	} `yaml:"spec"`
}

type complianceControl struct {
	ID     string `yaml:"id"`
	Checks []struct {
		ID string `yaml:"id"`
	} `yaml:"checks"`
	Commands []struct {
		ID string `yaml:"id"`
	} `yaml:"commands"`
}

type complianceReport struct {
	Results []struct {
		ID      string   `json:"ID"`
		Results []Result `json:"Results"`
	} `json:"Results"`
}

func readComplianceReport(t *testing.T, outputFile string) complianceReport {
	t.Helper()

	out, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	var report complianceReport
	require.NoError(t, json.Unmarshal(out, &report))
	return report
}

// verifyNodeChecks asserts that every check of a control backed by a node
// command was evaluated, and that it fails only if it is listed in
// expectedNodeFailures. A missing result means the check did not load or did
// not match the collected node info.
func verifyNodeChecks(t *testing.T, spec complianceSpec, report complianceReport) {
	t.Helper()

	evaluated := make(map[string]struct{})
	failedOn := make(map[string][]string)
	for _, control := range report.Results {
		for _, result := range control.Results {
			for _, misconf := range result.Misconfigurations {
				evaluated[misconf.ID] = struct{}{}
				if misconf.Status == "FAIL" {
					failedOn[misconf.ID] = append(failedOn[misconf.ID], result.Target)
				}
			}
		}
	}

	var checked int
	for _, control := range spec.Spec.Controls {
		if len(control.Commands) == 0 {
			continue
		}
		for _, check := range control.Checks {
			checked++

			if _, ok := evaluated[check.ID]; !ok {
				t.Errorf("check %s of control %s was not evaluated", check.ID, control.ID)
				continue
			}

			targets, failed := failedOn[check.ID]
			expected := slices.Contains(expectedNodeFailures, check.ID)
			switch {
			case failed && !expected:
				t.Errorf("check %s of control %s failed unexpectedly on %v", check.ID, control.ID, targets)
			case !failed && expected:
				t.Errorf("check %s of control %s was expected to fail", check.ID, control.ID)
			}
		}
	}

	require.NotZero(t, checked, "spec has no checks backed by node commands")
	t.Logf("Verified %d checks backed by node commands", checked)
}
