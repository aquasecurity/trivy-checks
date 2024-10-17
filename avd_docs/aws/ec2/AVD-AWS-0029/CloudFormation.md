
Remove sensitive data from the EC2 instance user-data

```yaml
Resources:
  GoodExample:
    Type: AWS::EC2::Instance
    Properties:
      BlockDeviceMappings:
        - DeviceName: /dev/sdm
          Ebs:
            DeleteOnTermination: "false"
            Iops: "200"
            VolumeSize: "20"
            VolumeType: io1
        - DeviceName: /dev/sdk
      ImageId: ami-79fd7eee
      KeyName: testkey
      UserData: export SSM_PATH=/database/creds
```


