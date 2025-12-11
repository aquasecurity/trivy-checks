
Enable encryption for CodeBuild project artifacts

```yaml
Resources:
  GoodProject:
    Type: AWS::CodeBuild::Project
    Properties:
      Artifacts:
        EncryptionDisabled: false
      SecondaryArtifacts:
        - EncryptionDisabled: false
```

#### Remediation Links
 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html

