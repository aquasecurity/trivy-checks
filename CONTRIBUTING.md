# Contributing

Welcome, and thank you for considering contributing to trivy-checks!

The following guide gives an overview of the project and some directions on how to make common types of contribution. If something is missing, or you get stuck, please [start a discussion](https://github.com/aquasecurity/trivy/discussions/new) and we'll do our best to help.

## Writing Checks

Writing a new rule can be relatively simple, but there are a few things to keep in mind. The following guide will help you get started.

First of all, you should check if the provider your rule targets is supported by _defsec_. If it's not, you'll need to add support for it. See [Adding Support for a New Cloud Provider](https://github.com/aquasecurity/defsec/blob/master/CONTRIBUTING.md#adding-support-for-a-new-cloud-provider) for more information. You can check if support exists by looking for a directory with the provider name in `pkg/providers`.  If you find your provider, navigate into the directory and check for a directory with the name of the service you're targeting. If you can't find that, you'll need to add support for it. See [Adding Support for a New Service](https://github.com/aquasecurity/defsec/blob/master/CONTRIBUTING.md#adding-support-for-a-new-service) for more information.

Next up, you'll need to check if the properties you want to target are supported, and if not, add support for them. The guide on [Adding Support for a New Service](https://github.com/aquasecurity/defsec/blob/master/CONTRIBUTING.md#adding-support-for-a-new-service) covers adding new properties.

At last, it's time to write your rule code! Rules are defined using _OPA Rego_. You can find a number of examples in the `checks/cloud` directory. The [OPA documentation](https://www.openpolicyagent.org/docs/latest/policy-language/) is a great place to start learning Rego. You can also check out the [Rego Playground](https://play.openpolicyagent.org/) to experiment with Rego, and [join the OPA Slack](https://slack.openpolicyagent.org/).

Create a new file in `checks/cloud` with the name of your rule. You should nest it in the existing directory structure as applicable. The package name should be in the format `builtin.PROVIDER.SERVICE.ID`, e.g. `builtin.aws.rds.aws0176`.

Running `make id` will provide you with the next available _ID_ for your rule. You can use this ID in your rule code to identify it.

A simple rule looks like the following example:

```rego
# METADATA
# title: "RDS IAM Database Authentication Disabled"
# description: "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access"
# scope: package
# schemas:
# - input: schema["aws"]
# related_resources:
# - https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html
# custom:
#   id: AVD-AWS-0176
#   avd_id: AVD-AWS-0176
#   provider: aws
#   service: rds
#   severity: MEDIUM
#   short_code: enable-iam-auth
#   recommended_action: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication."
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: rds
#           provider: aws

package builtin.aws.rds.aws0176

deny[res] {
 instance := input.aws.rds.instances[_]
 instance.engine.value == ["postgres", "mysql"][_]
 not instance.iamauthenabled.value
 res := result.new("Instance does not have IAM Authentication enabled", instance.iamauthenabled)
}
```

In fact, this is the code for an actual rule. You can find it in `checks/cloud/aws/rds/enable_iam_auth.rego`.

The metadata is the top section that starts with `# METADATA`, and is fairly verbose. You can copy and paste from another rule as a starting point. This format is effectively _yaml_ within a Rego comment, and is [defined as part of Rego itself](https://www.openpolicyagent.org/docs/latest/policy-language/#metadata).

Let's break the metadata down.

- `title` is fairly self-explanatory - it is a title for the rule. The title should clearly and succinctly state the problem which is being detected.
- `description` is also fairly self-explanatory - it is a description of the problem which is being detected. The description should be a little more verbose than the title, and should describe what the rule is trying to achieve. Imagine it completing a sentence starting with `You should...`.
- `scope` is used to define the scope of the policy. In this case, we are defining a policy that applies to the entire package. _defsec_ only supports using package scope for metadata at the moment, so this should always be the same.
- `schemas` tells Rego that it should use the `AWS` schema to validate the use of the input data in the policy. We currently support [these](https://github.com/aquasecurity/defsec/tree/9b3cc255faff5dc57de5ff77ed0ce0009c80a4bb/pkg/rego/schemas) schemas. Using a schema can help you validate your policy faster for syntax issues.
- `custom` is used to define custom fields that can be used by defsec to provide additional context to the policy and any related detections. This can contain the following:
  - `avd_id` is the ID of the rule in the [AWS Vulnerability Database](https://avd.aquasec.com/). This is used to link the rule to the AVD entry. You can generate an ID to use for this field using `make id`.
  - `provider` is the name of the provider the rule targets. This should be the same as the provider name in the `pkg/providers` directory, e.g. `aws`.
  - `service` is the name of the service the rule targets. This should be the same as the service name in the `pkg/providers` directory, e.g. `rds`.
  - `severity` is the severity of the rule. This should be one of `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
  - `short_code` is a short code for the rule. This should be a short, descriptive name for the rule, separating words with hyphens. You should omit provider/service from this.
  - `recommended_action` is a recommended remediation action for the rule. This should be a short, descriptive sentence describing what the user should do to resolve the issue.
  - `input` tells _defsec_ what inputs this rule should be applied to. Cloud provider rules should always use the `selector` input, and should always use the `type` selector with `cloud`. Rules targeting Kubernetes yaml can use `kubenetes`, RBAC can use `rbac`, and so on.
  - `subtypes` aid the engine to determine if it should load this policy or not for scanning. This can aid with the performance of scanning, especially if you have a lot of checks but not all apply to the IaC that you are trying to scan.
  
Now you'll need to write the rule logic. This is the code that will be executed to detect the issue. You should define a rule named `deny` and place your code inside this.

```rego
deny[res] {
 instance := input.aws.rds.instances[_]
 instance.engine.value == ["postgres", "mysql"][_]
 not instance.iamauthenabled.value
 res := result.new("Instance does not have IAM Authentication enabled", instance.iamauthenabled)
}
```

The rule should return a result, which can be created using `result.new` (this function does not need to be imported, it is defined internally and provided at runtime). The first argument is the message to display, and the second argument is the resource that the issue was detected on.

In the example above, you'll notice properties are being accessed from the `input.aws` object. The full set of schemas containing all of these properties is [available here](https://github.com/aquasecurity/defsec/tree/master/pkg/rego/schemas). You can match the schema name to the type of input you want to scan.

You should also write a test for your rule(s). There are many examples of these in the `checks/cloud` directory.

Finally, you'll want to generate documentation for your newly added rule. Please run `make docs` to generate the documentation for your new policy and submit a PR for us to take a look at.

You can see a full example PR for a new rule being added here: [https://github.com/aquasecurity/defsec/pull/1000](https://github.com/aquasecurity/defsec/pull/1000).

## Writing Compliance reports

To write a compliance report please check the following [compliance guide](./docs/compliance.md)

Supported compliance report IDs include:

### AWS

- aws-cis-1.2
- aws-cis-1.4

### Docker

- docker-cis-1.6.0

## Kubernetes

- eks-cis-1.4
- k8s-cis-1.23
- k8s-nsa-1.0
- k8s-pss-baseline-0.1
- k8s-pss-restricted-0.1
