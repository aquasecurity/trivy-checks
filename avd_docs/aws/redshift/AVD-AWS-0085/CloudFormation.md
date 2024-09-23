
Switch to VPC resources

```yaml---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of redshift sgr
Resources:
  myCluster:
    Type: "AWS::Redshift::Cluster"
    Properties:
      DBName: "mydb"

```


