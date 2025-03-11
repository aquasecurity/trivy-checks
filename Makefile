OUTDATED_API_DATA_URL=https://raw.githubusercontent.com/aquasecurity/trivy-db-data/refs/heads/main/k8s/api/k8s-outdated-api.json
OUTDATED_API_CHECK=checks/kubernetes/workloads/outdated_api.rego
BUNDLE_FILE=bundle.tar.gz
REGISTRY_PORT=5111

SED ?= sed

ifeq ($(shell uname), Darwin)
	SED = gsed
endif

.PHONY: test
test:
	go test -v ./...

.PHONY: integration-test
test-integration:
	go test -v -timeout 5m -tags=integration ./integration/...

.PHONY: rego
rego: fmt-rego check-rego lint-rego test-rego docs

.PHONY: fmt-rego
fmt-rego:
	go run ./cmd/opa fmt -w lib/ checks/ examples/ .regal/rules

.PHONY: test-rego
test-rego:
	go run ./cmd/opa test --explain=fails lib/ checks/ examples/ --ignore '*.yaml'

.PHONY: check-rego
check-rego:
	@go run ./cmd/opa check lib checks --v0-v1 --strict

.PHONY: lint-rego
lint-rego: check-rego
	@regal test .regal/rules
	@regal lint lib checks \
		--config-file .regal/config.yaml \
		--enable deny-rule,naming-convention \
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
	./cmd/bundle/bundle.sh

build-opa:
	go build ./cmd/opa

start-registry:
	docker run --rm -it -d -p ${REGISTRY_PORT}:5000 --name registry registry:2

stop-registry:
	docker stop registry

push-bundle: create-bundle
	@REPO=localhost:${REGISTRY_PORT}/trivy-checks:latest ;\
	echo "Pushing to repository: $$REPO" ;\
	docker run --rm -it --net=host -v $$PWD/${BUNDLE_FILE}:/${BUNDLE_FILE} bitnami/oras:latest push \
		$$REPO \
		 --artifact-type application/vnd.cncf.openpolicyagent.config.v1+json \
		"$(BUNDLE_FILE):application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip"
