export CGO_ENABLED=0

SHELL := /bin/bash

OUTDATED_API_DATA_URL := https://raw.githubusercontent.com/aquasecurity/trivy-db-data/refs/heads/main/k8s/api/k8s-outdated-api.json
OUTDATED_API_CHECK := checks/kubernetes/workloads/outdated_api.rego

ORAS_IMAGE := ghcr.io/oras-project/oras:v1.3.0
BUNDLE_FILE := bundle.tar.gz

REGISTRY_NAME := trivy-checks-registry
REGISTRY_PORT := 5111

TRIVY_VERSIONS := latest v0.67.0 v0.63.0

SCHEMAS := cloud.json dockerfile.json kubernetes.json
SCHEMAS_BASE := pkg/iac/rego/schemas

SED ?= sed
ifeq ($(shell uname), Darwin)
	SED = gsed
endif

.PHONY: test
test: download-schemas
	go test -v ./...

.PHONY: integration-test
test-integration:
	go test -v -timeout 5m -tags=integration ./integration/...

.PHONY: download-schemas
download-schemas:
	@for version in $(TRIVY_VERSIONS); do \
		schemas_path="schemas/$$version"; \
		if [ "$$version" = "latest" ]; then \
			base_url="https://raw.githubusercontent.com/aquasecurity/trivy/main/$(SCHEMAS_BASE)"; \
		else \
		    if [ -d "$$schemas_path" ]; then \
				echo "Skipping $$version, schemas already exist"; \
				continue; \
			fi; \
			base_url="https://raw.githubusercontent.com/aquasecurity/trivy/refs/tags/$$version/$(SCHEMAS_BASE)"; \
		fi; \
		echo "Downloading schemas for $$version..."; \
		mkdir -p $$schemas_path; \
		for file in $(SCHEMAS); do \
			url="$$base_url/$$file"; \
			echo "  - $$file"; \
			wget -q -O $$schemas_path/$$file $$url || { echo "Failed to download $$url"; exit 1; }; \
		done; \
	done

.PHONY: rego
rego: fmt-rego check-rego lint-rego test-rego docs

.PHONY: fmt-rego
fmt-rego:
	go run ./cmd/opa fmt -w lib/ checks/ examples/ .regal/rules

.PHONY: test-rego
test-rego:
	go run ./cmd/opa test --explain=fails lib/ checks/ examples/ --ignore '*.yaml'

.PHONY: check-rego
check-rego: download-schemas
	@go run ./cmd/opa check lib checks --v0-v1 --strict -s schemas/latest

.PHONY: check-rego-matrix
check-rego-matrix: download-schemas build-opa
	@for version in $(TRIVY_VERSIONS); do \
		echo "Running OPA check for $$version..."; \
		errors=$$(./opa check lib checks --strict -s schemas/$$version -f json --max-errors -1 2>&1 | jq -c '.errors[]?'); \
		if [ -z "$$errors" ]; then \
			echo "No errors for $$version"; \
			continue; \
		fi; \
		errs=""; \
		while read -r err; do \
			msg=$$(echo $$err | jq -r '.message'); \
			file=$$(echo $$err | jq -r '.location.file'); \
			if echo "$$msg" | grep -q '^undefined ref'; then \
				min_version=$$(./opa parse "$$file" -f json --json-include -comments,-locations \
					| jq -r '.annotations[0]?.custom.minimum_trivy_version'); \
				if [ "$$min_version" != "null" ]; then \
					ver=$${version#v};\
					cmp=$$(printf "%s\n%s\n" "$$ver" "$$min_version" | sort -V | head -n1); \
					if [ "$$cmp" = "$$ver" ]; then \
						echo "Skipping undefined ref in $$file: matrix version $$ver <= minimum required $$min_version"; \
						continue; \
					fi; \
				fi; \
			fi; \
			row=$$(echo $$err | jq -r '.location.row'); \
			code=$$(echo $$err | jq -r '.code'); \
			errs="$$errs$$file:$$row: $$code: $$msg\n"; \
		done <<< "$$errors"; \
		if [ -n "$$errs" ]; then \
			echo "Found remaining errors for $$version:"; \
			echo "$$errs"; \
			exit 1; \
		else \
			echo "No relevant errors for $$version"; \
		fi; \
	done

.PHONY: lint-rego
lint-rego: check-rego
	@regal test .regal/rules
	@regal lint lib checks \
		--config-file .regal/config.yaml \
		--timeout 5m

.PHONY: fmt-examples
fmt-examples:
	go run ./cmd/fmt-examples

.PHONY: id
id:
	@go run ./cmd/id

.PHONY: command-id
command-id:
	@go run ./cmd/command_id

.PHONY: update-outdated-api-data
update-outdated-api-data:
	@outdated_api_data=$$(curl -s ${OUTDATED_API_DATA_URL} | jq -c) ;\
	$(SED) -i -e "s|recommendedVersions :=.*|recommendedVersions := $$outdated_api_data|" $(OUTDATED_API_CHECK) ;\

.PHONY: docs
docs: fmt-examples
	go run ./cmd/avd_generator

.PHONY: docs-test
docs-test:
	go test -v ./cmd/avd_generator/...

.PHONY: create-bundle
create-bundle:
	go run ./cmd/bundle -root . -out ${BUNDLE_FILE}

build-opa:
	go build ./cmd/opa

start-registry:
	docker run --rm -it -d -p ${REGISTRY_PORT}:5000 --name ${REGISTRY_NAME} registry:2

stop-registry:
	docker stop ${REGISTRY_NAME}

push-bundle: create-bundle
	@REPO=localhost:${REGISTRY_PORT}/trivy-checks:latest ;\
	echo "Pushing to repository: $$REPO" ;\
	docker run --rm -it --net=host -v $$PWD/${BUNDLE_FILE}:/workspace/${BUNDLE_FILE} ${ORAS_IMAGE} push \
		$$REPO \
		 --artifact-type application/vnd.cncf.openpolicyagent.config.v1+json \
		"$(BUNDLE_FILE):application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip"
