package ssm

var cloudFormationSecretUseCustomerKeyGoodExamples = []string{
	`---
Resources:
  GoodSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: "secret"
      KmsKeyId: "my-key-id"
      Name: "blah"
      SecretString: "don't tell anyone"
`,
}

var cloudFormationSecretUseCustomerKeyBadExamples = []string{
	`---
Resources:
  BadSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: "secret"
      Name: "blah"
      SecretString: "don't tell anyone"
`,
}

var cloudFormationSecretUseCustomerKeyLinks = []string{}

var cloudFormationSecretUseCustomerKeyRemediationMarkdown = ``
