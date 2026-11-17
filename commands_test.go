package trivy_checks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Execute the shipped audit commands against controlled process listings. A Rego
// fixture alone cannot catch collection failures: the collector sanitizes a
// shell self-match to an empty value before the policy ever sees it.
func TestNodeAuditProcessSelection(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("audit commands require a POSIX shell")
	}

	data, err := EmbeddedConfigCommandsFileSystem.ReadFile("commands/config/node.yaml")
	require.NoError(t, err)
	var config struct {
		Node map[string]struct{ Bins []string }
	}
	require.NoError(t, yaml.Unmarshal(data, &config))

	commands := []struct {
		name, component, flag, value, statFormat string
	}{
		{"kubeletAnonymousAuthArgumentSet", "kubelet", "--anonymous-auth", "false", ""},
		{"kubeletAuthorizationModeArgumentSet", "kubelet", "--authorization-mode", "Webhook", ""},
		{"kubeletClientCaFileArgumentSet", "kubelet", "--client-ca-file", "/etc/kubernetes/ca.crt", ""},
		{"kubeletEventQpsArgumentSet", "kubelet", "--event-qps", "0", ""},
		{"kubeletHostnameOverrideArgumentSet", "kubelet", "--hostname-override", "node-01", ""},
		{"kubeletMakeIptablesUtilChainsArgumentSet", "kubelet", "--make-iptables-util-chains", "true", ""},
		{"kubeletOnlyUseStrongCryptographic", "kubelet", "--TLSCipherSuites", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ""},
		{"kubeletProtectKernelDefaultsArgumentSet", "kubelet", "--protect-kernel-defaults", "true", ""},
		{"kubeletReadOnlyPortArgumentSet", "kubelet", "--read-only-port", "0", ""},
		{"kubeletRotateCertificatesArgumentSet", "kubelet", "--rotate-certificates", "true", ""},
		{"kubeletRotateKubeletServerCertificateArgumentSet", "kubelet", "--feature-gates=RotateKubeletServerCertificate", "true", ""},
		{"kubeletStreamingConnectionIdleTimeoutArgumentSet", "kubelet", "--streamingConnectionIdleTimeout", "5m", ""},
		{"kubeletTlsCertFileTlsArgumentSet", "kubelet", "--tls-cert-file", "/etc/kubernetes/kubelet.crt", ""},
		{"kubeletTlsPrivateKeyFileArgumentSet", "kubelet", "--tls-private-key-file", "/etc/kubernetes/kubelet.key", ""},
		{"certificateAuthoritiesFileOwnership", "kubelet", "--client-ca-file", "/etc/kubernetes/ca.crt", "%U:%G"},
		{"certificateAuthoritiesFilePermissions", "kubelet", "--client-ca-file", "/etc/kubernetes/ca.crt", "%a"},
		{"kubeconfigFileExistsOwnership", "proxy", "--kubeconfig", "/etc/kubernetes/proxy.conf", "%U:%G"},
		{"kubeconfigFileExistsPermissions", "proxy", "--kubeconfig", "/etc/kubernetes/proxy.conf", "%a"},
	}
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			data, err := EmbeddedK8sCommandsFileSystem.ReadFile("commands/kubernetes/" + command.name + ".yaml")
			require.NoError(t, err)
			var definitions []struct{ Audit string }
			require.NoError(t, yaml.Unmarshal(data, &definitions))
			require.Len(t, definitions, 1)
			require.NotEmpty(t, config.Node[command.component].Bins)
			// Exercise every supported signature, including multi-word commands.
			for _, signature := range config.Node[command.component].Bins {
				t.Run(signature, func(t *testing.T) {
					audit := strings.ReplaceAll(definitions[0].Audit, "$"+command.component+".bins", signature)
					// This is the shell process started by exec.Command("sh", "-c", audit).
					self := "/bin/sh -c " + audit
					flag := " " + command.flag + "=" + command.value
					wrongFlag := " " + command.flag + "=wrong"
					process := "/usr/local/bin/" + signature + flag
					parts := strings.Fields(signature)
					unrelatedParts := slices.Clone(parts)
					unrelatedParts[0] += "-helper"
					unrelated := "/usr/bin/" + strings.Join(unrelatedParts, " ") + wrongFlag

					type testCase struct {
						name      string
						processes []string
						want      string
					}
					cases := []testCase{
						{"shell_before_target", []string{self, process}, command.value},
						{"target_before_shell", []string{process, self}, command.value},
						{"unrelated_binary_before_target", []string{unrelated, self, process}, command.value},
						{"binary_name_only_in_arguments", []string{"/bin/echo /usr/local/bin/" + signature + wrongFlag, self, process}, command.value},
						{"target_without_flag", []string{self, "/usr/local/bin/" + signature}, ""},
						{"target_absent", []string{unrelated, self}, ""},
						{"only_shell", []string{self}, ""},
						{"bare_executable_name", []string{self, signature + flag}, command.value},
						{"mixed_whitespace", []string{self, "\t/usr/bin/" + strings.Join(parts, "\t  ") + "\t" + flag}, command.value},
					}
					for i := 1; i < len(parts); i++ {
						wrongParts := slices.Clone(parts)
						wrongParts[i] += "-helper"
						wrong := "/usr/bin/" + strings.Join(wrongParts, " ") + wrongFlag
						incomplete := "/usr/bin/" + strings.Join(parts[:i], " ") + wrongFlag
						cases = append(cases,
							testCase{fmt.Sprintf("wrong_argument_%d_before_target", i), []string{wrong, self, process}, command.value},
							testCase{fmt.Sprintf("wrong_argument_%d_only", i), []string{wrong, self}, ""},
							testCase{fmt.Sprintf("missing_argument_%d", i), []string{incomplete, self}, ""},
						)
					}
					for _, tt := range cases {
						t.Run(tt.name, func(t *testing.T) {
							dir := t.TempDir()
							fixture := filepath.Join(dir, "processes")
							require.NoError(t, os.WriteFile(fixture, []byte(strings.Join(tt.processes, "\n")+"\n"), 0600))
							// Support the original listing too, to demonstrate the pre-fix failure.
							ps := `#!/bin/sh
case "$*" in
  '-ef') awk '{printf "%d root 0:00 %s\n", NR + 100, $0}' "$AUDIT_TEST_PROCESSES" ;;
  '-eo args') cat "$AUDIT_TEST_PROCESSES" ;;
  *) exit 2 ;;
esac
`
							require.NoError(t, os.WriteFile(filepath.Join(dir, "ps"), []byte(ps), 0700))
							statArgs := filepath.Join(dir, "stat-args")
							// Record the selected path without inspecting files on the test host.
							stat := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$AUDIT_TEST_STAT_ARGS\"\nprintf 'root:root\\n'\n"
							require.NoError(t, os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0700))
							cmd := exec.Command("sh", "-c", audit)
							cmd.Env = append(os.Environ(),
								"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
								"AUDIT_TEST_PROCESSES="+fixture,
								"AUDIT_TEST_STAT_ARGS="+statArgs,
							)
							output, err := cmd.CombinedOutput()
							require.NoError(t, err, "%s", output)
							if command.statFormat != "" {
								args, err := os.ReadFile(statArgs)
								require.NoError(t, err)
								want := fmt.Sprintf("-c\n%s\n", command.statFormat)
								if tt.want != "" {
									want += tt.want + "\n"
								}
								require.Equal(t, want, string(args))
							} else {
								require.Equal(t, tt.want, strings.TrimSpace(string(output)))
							}
						})
					}
				})
			}
		})
	}
}
