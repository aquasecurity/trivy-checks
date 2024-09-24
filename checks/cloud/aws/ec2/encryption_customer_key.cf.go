package ec2

var cloudFormationEncryptionCustomerKeyGoodExamples = []string{
	`---
Resources:
  GoodExample:
    Type: AWS::EC2::Volume
    Properties: 
      Size: 100
      Encrypted: true
      KmsKeyId: "alias/volumeEncrypt"
    DeletionPolicy: Snapshot
`,
	`---
Resources:
  MyKey:
    Type: 'AWS::KMS::Key'
    Properties:
      KeyPolicy:
        Version: 2012-10-17
        Id: key-default-1
  GoodExample:
    Type: AWS::EC2::Volume
    Properties: 
      Size: 100
      Encrypted: true
      KmsKeyId: !Ref MyKey 
    DeletionPolicy: Snapshot
`,
}

var cloudFormationEncryptionCustomerKeyBadExamples = []string{
	`---
Resources:
  BadExample:
    Type: AWS::EC2::Volume
    Properties:
      Size: 100
      AvailabilityZone: !GetAtt Ec2Instance.AvailabilityZone
    DeletionPolicy: Snapshot
`,
}

var cloudFormationEncryptionCustomerKeyLinks = []string{}

var cloudFormationEncryptionCustomerKeyRemediationMarkdown = ``
