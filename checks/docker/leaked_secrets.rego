# METADATA
# title: Secrets passed via `build-args` or envs or copied secret files
# description: Passing secrets via `build-args` or envs or copying secret files can leak them out
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/build/building/secrets/
# custom:
#   id: DS031
#   avd_id: AVD-DS-0031
#   severity: CRITICAL
#   short_code: do-not-pass-secrets
#   recommended_action: Use secret mount if secrets are needed during image build. Use volume mount if secret files are needed during container runtime.
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS031

import rego.v1

import data.lib.docker

final_stage := last(input.Stages)

# check if env or arg contains secret env
deny contains res if {
	some instruction in final_stage.Commands
	is_arg_or_env(instruction.Cmd)
	[name, _] := retrive_name_and_default(instruction)
	is_secret_env(name)
	res := result.new(
		sprintf("Possible exposure of secret env %q in %s", [name, upper(instruction.Cmd)]),
		instruction,
	)
}

# check if env or arg contains secret file env
deny contains res if {
	some instruction in final_stage.Commands
	is_arg_or_env(instruction.Cmd)
	[name, path] := retrive_name_and_default(instruction)
	path != ""
	name in secret_file_envs
	is_secret_file_copied(path)
	res := result.new(
		sprintf("Possible exposure of the copied secret env file %q in %s", [name, upper(instruction.Cmd)]),
		instruction,
	)
}

# check if a secret file is copied
deny contains res if {
	some instruction in final_stage.Commands
	instruction.Cmd == "copy"
	count(instruction.Value) == 2
	env := trim_prefix(instruction.Value[1], "$")
	env in secret_file_envs
	res := result.new(
		sprintf("Possible exposure of secret file %q in COPY", [env]),
		instruction,
	)
}

check_args := true

# TODO: Should arguments be checked?
is_arg_or_env(cmd) if {
	check_args
	cmd == "arg"
}

is_arg_or_env(cmd) if cmd == "env"

retrive_name_and_default(instruction) := [instruction.Value[0], ""] if {
	instruction.Cmd == "env"
	count(instruction.Value) == 1
}

retrive_name_and_default(instruction) := [instruction.Value[0], instruction.Value[1]] if {
	instruction.Cmd == "env"
	count(instruction.Value) > 1
}

retrive_name_and_default(instruction) := [parts[0], ""] if {
	instruction.Cmd == "arg"
	parts := split(instruction.Value[0], "=")
	count(parts) == 1
}

retrive_name_and_default(instruction) := [parts[0], parts[1]] if {
	instruction.Cmd == "arg"
	parts := split(instruction.Value[0], "=")
	count(parts) > 1
}

default_envs := {
	"AWS_ACCESS_KEY_ID", # https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AZURE_CLIENT_ID", # https://learn.microsoft.com/en-us/dotnet/api/azure.identity.environmentcredential?view=azure-dotnet
	"AZURE_CLIENT_SECRET",
	"GITHUB_TOKEN", # https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#about-the-github_token-secret
	"OPENAI_API_KEY", # https://platform.openai.com/docs/quickstart/create-and-export-an-api-key
	"HF_TOKEN", # https://huggingface.co/docs/huggingface_hub/en/package_reference/environment_variables#hftoken
}

excluded_envs := set()

included_envs := set()

envs := (default_envs - excluded_envs) | included_envs

is_secret_env(str) if str in envs

env_prefixes := {
	"VITE_", # https://v3.vitejs.dev/guide/env-and-mode.html#env-files
	"REACT_APP_", # https://create-react-app.dev/docs/adding-custom-environment-variables/
}

is_secret_env(str) if {
	some prefix in env_prefixes
	trim_left(str, prefix) in envs
}

secret_file_envs := {
	"AWS_CONFIG_FILE", # https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html
	"HF_TOKEN_PATH", # https://huggingface.co/docs/huggingface_hub/en/package_reference/environment_variables#hftokenpath
	"GOOGLE_APPLICATION_CREDENTIALS", # https://cloud.google.com/docs/authentication/application-default-credentials#GAC
}

last(array) := array[count(array) - 1]

# check only the simple case when the secret file from the copied directory is used
# For example:
# COPY /src /app
# ENV GOOGLE_APPLICATION_CREDENTIALS="./app/google-storage-service.json"
is_secret_file_copied(path) if {
	some instruction in final_stage.Commands
	instruction.Cmd == "copy"
	dst := last(instruction.Value)
	is_sub_path(path, dst)
}

is_sub_path(a, b) if startswith(clean_path(a), clean_path(b))

clean_path(path) := remove_trailing_slash(remove_leading_slash(remove_leading_dot(unquote(path))))

unquote(s) := cut_prefix(cut_suffix(s, "\""), "\"")

remove_leading_dot(path) := cut_prefix(path, ".")

remove_leading_slash(path) := cut_prefix(path, "/")

remove_trailing_slash(path) := cut_suffix(path, "/")

cut_prefix(s, prefix) := substring(s, 1, -1) if {
	startswith(s, prefix)
} else := s

cut_suffix(s, suffix) := substring(s, 0, count(s) - 1) if {
	endswith(s, suffix)
} else := s


deny contains res if {
	some instruction in final_stage.Commands
	instruction.Cmd == "run"
	not has_secret_mount_arg(instruction)
	use_command_to_setup_credentials(instruction)
	res := result.new(
		"Possible exposure of secret in RUN",
		instruction,
	)
}

has_secret_mount_arg(instruction) if {
	some flag in instruction.Flags
	startswith(flag, "--mount=type=secret")
}

setup_creds_commands := {
	"aws configure set aws_access_key_id", # https://docs.aws.amazon.com/cli/latest/reference/configure/set.html
	"aws configure set aws_secret_access_key",
	"gcloud auth activate-service-account", # https://cloud.google.com/sdk/gcloud/reference/auth/activate-service-account
	"az login", # TODO: check flags
}

use_command_to_setup_credentials(instruction) if {
	some val in instruction.Value
	some cmd in setup_creds_commands
	contains(val, cmd)
}