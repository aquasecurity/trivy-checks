
Turn on encryption for all block devices

```yaml
Resources:
  GoodExample:
    Type: AWS::AutoScaling::LaunchConfiguration
    Properties:
      BlockDeviceMappings:
        - DeviceName: root
          Ebs:
            Encrypted: true
      ImageId: ami-123456
      InstanceType: t2.small
```


