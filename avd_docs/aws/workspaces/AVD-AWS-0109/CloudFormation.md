
Root and user volume encryption should be enabled

```yaml
Resources:
    GoodExample:
        Properties:
            RootVolumeEncryptionEnabled: true
            UserName: admin
            UserVolumeEncryptionEnabled: true
        Type: AWS::WorkSpaces::Workspace

```
```yaml
Resources:
    GoodExample:
        Properties:
            RootVolumeEncryptionEnabled: true
            UserName: admin
            UserVolumeEncryptionEnabled: true
        Type: AWS::WorkSpaces::Workspace

```


