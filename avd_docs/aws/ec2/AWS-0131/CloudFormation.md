
Turn on encryption for all block devices

```yaml
Resources:
  GoodExample:
    Type: AWS::EC2::Instance
    Properties:
      BlockDeviceMappings:
        - DeviceName: /dev/sdm
          Ebs:
            Encrypted: true
      ImageId: ami-79fd7eee
```


