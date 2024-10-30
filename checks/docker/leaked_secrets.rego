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

import data.ds031
import data.lib.docker
import data.lib.path

final_stage := last(input.Stages)

# check if env or arg contains secret env
deny contains res if {
	some instruction in final_stage.Commands
	is_arg_or_env(instruction.Cmd)
	some [name, _] in retrive_name_and_default(instruction)
	is_secret(name)
	res := result.new(
		sprintf("Possible exposure of secret env %q in %s", [name, upper(instruction.Cmd)]),
		instruction,
	)
}

# check if env or arg contains secret file env
deny contains res if {
	some instruction in final_stage.Commands
	is_arg_or_env(instruction.Cmd)
	some [name, def] in retrive_name_and_default(instruction)
	def != ""
	is_secret_file_env(name)
	is_secret_file_copied(def)
	res := result.new(
		sprintf("Possible exposure of the copied secret env file %q in %s", [name, upper(instruction.Cmd)]),
		instruction,
	)
}

is_secret_file_env(name) if name in secret_file_envs

# check if a secret file is copied
deny contains res if {
	some instruction in final_stage.Commands
	instruction.Cmd == "copy"
	count(instruction.Value) == 2
	env := trim_prefix(instruction.Value[1], "$")
	is_secret_file_env(env)
	res := result.new(
		sprintf("Possible exposure of secret file %q in COPY", [env]),
		instruction,
	)
}

is_arg_or_env(cmd) if cmd in {"env", "arg"}

# returns an array of pairs consisting of environment variable names and their default values
retrive_name_and_default(instruction) := vals if {
	instruction.Cmd == "env"

	count(instruction.Value) % 3 == 0
	count_envs = count(instruction.Value) / 3

	vals := [
	[name, def] |
		some idx in numbers.range(0, count_envs - 1)

		# ENV must have two arguments
		# Trivy returns `ENV FOO=bar` as [“FOO”, “bar”, “=”], so we skip the delimiter
		name := instruction.Value[idx * 3]
		def := instruction.Value[(idx * 3) + 1]
	]
}

# returns an array of pairs consisting of the argument names and their default values.
retrive_name_and_default(instruction) := vals if {
	instruction.Cmd == "arg"
	vals := [
	v |
		some val in instruction.Value
		v := split_args(val)
	]
}

split_args(arg) := [name, ""] if {
	parts := split(arg, "=")
	count(parts) == 1
	name := parts[0]
}

split_args(arg) := parts if {
	parts := split(arg, "=")
	count(parts) == 2
}

default_envs := {
	"AWS_ACCESS_KEY_ID", # https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AZURE_CLIENT_ID", # https://learn.microsoft.com/en-us/dotnet/api/azure.identity.environmentcredential?view=azure-dotnet
	"AZURE_CLIENT_SECRET",
	"GITHUB_TOKEN", # https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#about-the-github_token-secret,
	"GH_TOKEN", # https://cli.github.com/manual/gh_help_environment
	"GH_ENTERPRISE_TOKEN",
	"GITHUB_ENTERPRISE_TOKEN",
	"OPENAI_API_KEY", # https://platform.openai.com/docs/quickstart/create-and-export-an-api-key
	"HF_TOKEN", # https://huggingface.co/docs/huggingface_hub/en/package_reference/environment_variables#hftoken
	"DIGITALOCEAN_ACCESS_TOKEN", # https://github.com/digitalocean/doctl?tab=readme-ov-file#authenticating-with-digitalocean
	"DOCKERHUB_PASSWORD", # https://circleci.com/docs/private-images/
	"FIREBASE_TOKEN", # https://firebase.google.com/docs/cli,
	"CI_DEPLOY_PASSWORD", # https://docs.gitlab.com/ee/user/project/deploy_tokens/
	"GOOGLE_API_KEY", # https://python.langchain.com/docs/integrations/tools/google_search/
	"LANGSMITH_API_KEY", # https://docs.smith.langchain.com/how_to_guides/setup/create_account_api_key
	"LANGCHAIN_API_KEY",
	"HEROKU_API_KEY", # https://devcenter.heroku.com/articles/authentication
}

included_envs := included if {
	is_array(ds031.included_envs)
	included := {e | some e in ds031.included_envs}
} else := set()

envs := default_envs | included_envs

is_secret(str) if {
	is_secret_env(str)
}

is_secret(str) if {
	not is_secret_env(str) # to avoid duplication of results
	not is_secret_file_env(str) # files require checking that they have been copied
	is_secret_key(str)
}

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
is_secret_file_copied(p) if {
	some instruction in final_stage.Commands
	instruction.Cmd == "copy"
	dst := last(instruction.Value)
	path.is_sub_path(p, dst)
}

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

cred_setup_commands := {
	"aws configure set aws_access_key_id", # https://docs.aws.amazon.com/cli/latest/reference/configure/set.html
	"aws configure set aws_secret_access_key",
	"gcloud auth activate-service-account", # https://cloud.google.com/sdk/gcloud/reference/auth/activate-service-account
	`az login.*(?:-p|--password|--federated-token)\s`, # https://learn.microsoft.com/en-us/cli/azure/reference-index?view=azure-cli-latest#az-login
	`doctl auth init.*(?:-t|--access-token)\s`, # https://docs.digitalocean.com/reference/doctl/reference/auth/init/
}

use_command_to_setup_credentials(instruction) if {
	some val in instruction.Value
	some cmd in cred_setup_commands
	regex.match(cmd, val)
}

is_secret_key(s) if {
	regex.match(forbidden_secrets_pattern, s)
	not regex.match(allowed_secrets_pattern, s)
}

# adopt https://github.com/moby/buildkit/blob/62bda5c1caae9935a2051e96443d554f7ab7ef2d/frontend/dockerfile/dockerfile2llb/convert.go#L2469
secrets_regex_pattern := `(?i)(?:_|^)(?:%s)(?:_|$)`

build_secrets_pattern(tokens) := sprintf(secrets_regex_pattern, [concat("|", tokens)])

# these tokens cover the following keywords
# https://github.com/danielmiessler/SecLists/blob/master/Discovery/Variables/secret-keywords.txt
forbidden_secret_tokens := {
	"apikey", "auth", "credential",
	"credentials", "key", "password",
	"pword", "passwd", "secret", "token",
	"usr", "psw",
}

forbidden_secrets_pattern := build_secrets_pattern(forbidden_secret_tokens)

allowed_secret_tokens := {"public"}

allowed_secrets_pattern := build_secrets_pattern(allowed_secret_tokens)
