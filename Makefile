DYNAMIC_REGO_FOLDER=./rules/kubernetes/policies/dynamic

.PHONY: schema
schema:
	go run ./cmd/schema generate

.PHONY: rego
rego: fmt-rego test-rego

.PHONY: fmt-rego
fmt-rego:
	opa fmt -w rules/cloud/policies

.PHONY: test-rego
test-rego:
	go test --run Test_AllRegoRules ./test

.PHONY: bundle
bundle:
	./scripts/bundle.sh
	cp bundle.tar.gz scripts/bundle.tar.gz
	go run ./scripts/verify-bundle.go
	rm scripts/bundle.tar.gz


.PHONY: docs
docs:
	go run ./cmd/avd_generator

.PHONY: docs-test
docs-test:
	go test -v ./cmd/avd_generator/...

.PHONY: id
id:
	@go run ./cmd/id

outdated-api-updated:
	sed -i.bak "s|recommendedVersions :=.*|recommendedVersions := $(OUTDATE_API_DATA)|" $(DYNAMIC_REGO_FOLDER)/outdated_api.rego && rm $(DYNAMIC_REGO_FOLDER)/outdated_api.rego.bak