
Turn on encryption for all block devices

```yaml
Resources:
    GoodExample:
        Properties:
            BlockDeviceMappings:
                - DeviceName: /dev/sdm
                  Ebs:
                    DeleteOnTermination: "false"
                    Encrypted: true
                    Iops: "200"
                    VolumeSize: "20"
                    VolumeType: io1
            ImageId: ami-79fd7eee
            KeyName: testkey
            UserData: export SSM_PATH=/database/creds
        Type: AWS::EC2::Instance

```


