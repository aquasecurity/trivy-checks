
Enable HTTP token requirement for IMDS

```yaml
Resources:
  GoodExample:
    Properties:
      MetadataOptions:
        HttpEndpoint: enabled
        HttpTokens: required
    Type: AWS::AutoScaling::LaunchConfiguration

```


