package builtin.dockerfile.DS032_test

import data.builtin.dockerfile.DS032 as check

import rego.v1

test_pipefail_cases[name] if {
	some name, tc in {
		"pipe without pipefail": {
			"stages": [{"Name": "alpine:3.5", "Commands": [
				{"Cmd": "from", "Value": ["alpine:3.5"]},
				{"Cmd": "run", "Value": ["wget -O - https://some.site | wc -l > /number"]},
			]}],
			"expected": 1,
		},
		# deny is a set, so duplicate messages are deduplicated.
		# To ensure uniqueness, we add StartLine to each RUN instruction.
		"multiple runs with pipe": {
			"stages": [{"Name": "alpine:3.5", "Commands": [
				{"Cmd": "from", "Value": ["alpine:3.5"], "StartLine": 1, "EndLine": 1},
				{"Cmd": "run", "Value": ["wget -O - https://some.site | wc -l > /number"], "StartLine": 2, "EndLine": 2},
				{"Cmd": "run", "Value": ["cat /etc/passwd | grep root"], "StartLine": 3, "EndLine": 3},
			]}],
			"expected": 2,
		},
		"pipe with set -o pipefail": {
			"stages": [{"Name": "alpine:3.5", "Commands": [
				{"Cmd": "from", "Value": ["alpine:3.5"]},
				{"Cmd": "run", "Value": ["set -o pipefail && wget -O - https://some.site | wc -l > /number"]},
			]}],
			"expected": 0,
		},
		"shell bash with pipefail flag": {
			"stages": [{"Name": "alpine:3.5", "Commands": [
				{"Cmd": "from", "Value": ["alpine:3.5"]},
				{"Cmd": "shell", "Value": ["/bin/bash", "-o", "pipefail", "-c"]},
				{"Cmd": "run", "Value": ["wget -O - https://some.site | wc -l > /number"]},
			]}],
			"expected": 0,
		},
		"shell bash with -eo pipefail": {
			"stages": [{"Name": "alpine:3.5", "Commands": [
				{"Cmd": "from", "Value": ["alpine:3.5"]},
				{"Cmd": "shell", "Value": ["/bin/bash", "-eo", "pipefail", "-c"]},
				{"Cmd": "run", "Value": ["wget -O - https://some.site | wc -l > /number"]},
			]}],
			"expected": 0,
		},
		"shell bash with -e -o pipefail": {
			"stages": [{"Name": "alpine:3.5", "Commands": [
				{"Cmd": "from", "Value": ["alpine:3.5"]},
				{"Cmd": "shell", "Value": ["/bin/bash", "-e", "-o", "pipefail", "-c"]},
				{"Cmd": "run", "Value": ["wget -O - https://some.site | wc -l > /number"]},
			]}],
			"expected": 0,
		},
		"shell bash without pipefail": {
			"stages": [{"Name": "alpine:3.5", "Commands": [
				{"Cmd": "from", "Value": ["alpine:3.5"]},
				{"Cmd": "shell", "Value": ["/bin/bash", "-c"]},
				{"Cmd": "run", "Value": ["wget -O - https://some.site | wc -l > /number"]},
			]}],
			"expected": 1,
		},
		"shell sh with pipefail": {
			"stages": [{"Name": "alpine:3.5", "Commands": [
				{"Cmd": "from", "Value": ["alpine:3.5"]},
				{"Cmd": "shell", "Value": ["/bin/sh", "-o", "pipefail", "-c"]},
				{"Cmd": "run", "Value": ["wget -O - https://some.site | wc -l > /number"]},
			]}],
			"expected": 1,
		},
		"non posix shell pwsh": {
			"stages": [{"Name": "alpine:3.5", "Commands": [
				{"Cmd": "from", "Value": ["alpine:3.5"]},
				{"Cmd": "shell", "Value": ["pwsh", "-c"]},
				{"Cmd": "run", "Value": ["Get-Variable PSVersionTable | Select-Object -ExpandProperty Value"]},
			]}],
			"expected": 0,
		},
		"no pipe": {
			"stages": [{"Name": "alpine:3.5", "Commands": [
				{"Cmd": "from", "Value": ["alpine:3.5"]},
				{"Cmd": "run", "Value": ["apt-get update && apt-get install -y curl"]},
			]}],
			"expected": 0,
		},
		"pipe in string": {
			"stages": [{"Name": "alpine:3.5", "Commands": [
				{"Cmd": "from", "Value": ["alpine:3.5"]},
				{"Cmd": "run", "Value": ["echo \"foo|bar\""]},
			]}],
			"expected": 0,
		},
		"shell with pipefail reset by new from": {
			"stages": [
				{"Name": "build", "Commands": [
					{"Cmd": "from", "Value": ["alpine:3.5"]},
					{"Cmd": "shell", "Value": ["/bin/bash", "-o", "pipefail", "-c"]},
					{"Cmd": "run", "Value": ["wget -O - https://some.site | wc -l > /number"]},
				]},
				{"Name": "build2", "Commands": [
					{"Cmd": "from", "Value": ["alpine:3.5"]},
					{"Cmd": "run", "Value": ["wget -O - https://some.site | wc -l > /number"]},
				]},
			],
			"expected": 1,
		},
		"shell pipefail reset by new shell": {
			"stages": [{"Name": "build", "Commands": [
				{"Cmd": "from", "Value": ["alpine:3.5"]},
				{"Cmd": "shell", "Value": ["/bin/bash", "-o", "pipefail", "-c"]},
				{"Cmd": "run", "Value": ["wget -O - https://some.site | wc -l > /number"]},
				{"Cmd": "shell", "Value": ["/bin/sh", "-c"]},
				{"Cmd": "run", "Value": ["wget -O - https://some.site | wc -l > /number"], "StartLine": 5, "EndLine": 5},
			]}],
			"expected": 1,
		},
		"non posix shell powershell.exe": {
			"stages": [{"Name": "build", "Commands": [
				{"Cmd": "from", "Value": ["mcr.microsoft.com/powershell:ubuntu-16.04"]},
				{"Cmd": "shell", "Value": ["powershell.exe"]},
				{"Cmd": "run", "Value": ["Get-Variable PSVersionTable | Select-Object -ExpandProperty Value"]},
			]}],
			"expected": 0,
		},
		"non posix shell cmd.exe": {
			"stages": [{"Name": "build", "Commands": [
				{"Cmd": "from", "Value": ["mcr.microsoft.com/powershell:ubuntu-16.04"]},
				{"Cmd": "shell", "Value": ["cmd.exe", "/c"]},
				{"Cmd": "run", "Value": ["Get-Variable PSVersionTable | Select-Object -ExpandProperty Value"]},
			]}],
			"expected": 0,
		},
	}

	r := check.deny with input as {"Stages": tc.stages}
	count(r) == tc.expected
}

test_shell_has_pipefail_cases[name] if {
	some name, tc in {
		"simple -o pipefail": {"values": ["/bin/bash", "-o", "pipefail", "-c"]},
		"combined -eo pipefail": {"values": ["/bin/bash", "-eo", "pipefail", "-c"]},
		"separate -e -o pipefail": {"values": ["/bin/bash", "-e", "-o", "pipefail", "-c"]},
		"errexit and pipefail": {"values": ["/bin/bash", "-o", "errexit", "-o", "pipefail", "-c"]},
		"zsh with pipefail": {"values": ["/bin/zsh", "-o", "pipefail", "-c"]},
	}
	check.shell_has_pipefail(tc.values)
}

test_shell_has_no_pipefail_cases[name] if {
	some name, tc in {
		"no pipefail": {"values": ["/bin/bash", "-c"]},
		"sh with pipefail": {"values": ["/bin/sh", "-o", "pipefail", "-c"]},
	}
	not check.shell_has_pipefail(tc.values)
}
