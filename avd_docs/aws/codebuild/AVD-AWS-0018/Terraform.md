
Enable encryption for CodeBuild project artifacts

```hcl
resource "aws_codebuild_project" "good_example" {
  artifacts {}
}
```
```hcl
resource "aws_codebuild_project" "good_example" {
  artifacts {
    encryption_disabled = false
  }
}
```
```hcl
resource "aws_codebuild_project" "codebuild" {
  secondary_artifacts {
    encryption_disabled = false
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project#encryption_disabled

