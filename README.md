## My Project

## Prerequisites

1.	[Recommended] A separate AWS account containing no customer data or running workloads
2.	GuardDuty, along with GuardDuty Kubernetes Protection
3.	Amazon Inspector must be enabled
4.	[Optional] AWS Security Hub can be enabled to show a consolidated view of security findings generated by GuardDuty and Inspector

## Architecture

![generate_security_services_findings_architecture](generate_security_services_findings.png)

1.	User will specify the type of security findings to generate by passing a CloudFormation parameter.
2.	An SNS topic is created to subscribe to findings for notifications.  Subscribed users are notified of the finding through the deployed Amazon Simple Notification Service (Amazon SNS) topic.
3.	Upon user selection for the CloudFormation parameter, Amazon Elastic Compute Cloud (Amazon EC2) instance(s) are provisioned to run commands to generate security findings.
a.	Note: If the parameter of “inspector” is provided during deployment, only one EC2 instance will be deployed. If the parameter of “guardduty” is provided during deployment, two EC2 instances will be deployed.
4.	For Amazon Inspector findings:
a.	EC2 user data creates a .txt file with vulnerable images, pulls down Docker images from open source vulhub, and creates an Amazon Elastic Container Registry (Amazon ECR) repository with the vulnerable images
b.	EC2 user data pushes and tags the images in the ECR repository which will result in Amazon Inspector findings being generated
c.	An Amazon EventBridge cron-style trigger rule, inspector_remediation_ecr, invokes an AWS Lambda.
d.	The Lambda function, ecr_cleanup_function, will clean up the vulnerable images in the deployed ECR repository based on tags applied and sends a notification to the SNS topic. 
i.	Note: The ecr_cleanup_function Lambda function is also invoked as a custom resource to cleanup vulnerable images during deployment. If there are any issues with cleanup, the EventBridge rule will continually attempt to cleanup vulnerable images.
5.	For GuardDuty, the following actions are taken and resources are deployed:
a.	An AWS Identity and Access Management (IAM) user named guardduty-demo-user is created with an IAM access key that is INACTIVE
b.	An AWS Systems Manager (SSM) parameter stores the IAM access key for guardduty-demo-user
c.	An AWS Secrets Manager secret stores the inactive IAM secret access key for guardduty-demo-user
d.	An Amazon DynamoDB table is created and the table name stored in a SSM parameter to be referenced within the EC2 user data
e.	An Amazon S3 Bucket is created and the bucket name is stored in a SSM parameter to be referenced within the EC2 user data
f.	An AWS Lambda function adds a threat list to Amazon GuardDuty that includes the IP addresses of the EC2 instances deployed as part of the sample
g.	EC2 user data will generate Amazon GuardDuty findings for:
i.	Amazon Elastic Kubernetes Service (Amazon EKS)
1.	Installs eksctl from GitHub 
2.	Creates an EC2 key pair
3.	Creates an EKS cluster (dependent on availability zone capacity)
4.	Updates EKS cluster configuration to make a dashboard public
ii.	DynamoDB
1.	Adds an item to the DynamoDB table for “Joshua Tree”.
iii.	EC2
1.	Creates an AWS CloudTrail trail named guardduty-demo-trail-<GUID> and subsequently deletes the same CloudTrail trail. The <GUID> is randomly generated by using the $RANDOM function 
2.	Runs portscan on 172.31.37.171 (an RFC 1918 private IP address) and private IP of the “EKS Deployment EC2 instance” provisioned as part of the sample. Port scans are primarily used by bad actors to provide for potential vulnerabilities. The target of the port scans are internal IP addresses and do not leave the sample VPC deployed. 
3.	Curls DNS domains that are labeled for bitcoin, command and control, and other domains associated with known threats
iv.	S3
1.	Disables Public Access Block and server access logging for the Amazon Simple Storage Service (Amazon S3) bucket provisioned as part of the solution
v.	IAM
1.	Deletes the account password policy and creates a password policy
6.	The following Amazon EventBridge rules are created:
a.	guardduty_remediation_eks_rule – when a GuardDuty finding for EKS is created, a Lambda function attempts to delete the EKS resources. Subscribed users are notified of the finding through the deployed SNS topic.
b.	guardduty_remediation_credexfil_rule – when a GuardDuty finding for InstanceCredentialExfiltration is created, a Lambda function is used to revoke the IAM role’s temporary security credentials and AWS permissions. Subscribed users are notified of the finding through the deployed SNS topic.
c.	guardduty_respond_IAMUser_rule – when a GuardDuty finding for IAM is created, subscribed users are notified through the deployed SNS topic. There is no remediation activity triggered by this rule.
d.	Guardduty_notify_S3_rule – when a GuardDuty finding for Amazon S3 is created, subscribed users are notified through the deployed SNS topic. There is no remediation activity triggered by this rule.
7.	The following Lambda functions are created:
a.	guardduty_iam_remediation_function – the function will revoke all active sessions and send a notification to the SNS topic.
b.	eks_cleanup_function – the function will delete the EKS resources in the EKS CloudFormation template. 
i.	Note: Upon attempt to delete the overall sample CloudFormation stack, this will run to delete the EKS CloudFormation template.
8.	An Amazon S3 bucket stores all the EC2 user data scripts ran from the EC2 instance(s)


## Build

To build this app, you need to be in the project root folder. Then run the following:

    $ npm install -g aws-cdk
    <installs AWS CDK>

    $ npm install
    <installs appropriate packages found in the package.json>

## Deploy

    $ cdk bootstrap aws://<INSERT_AWS_ACCOUNT>/<INSERT_REGION>
    <build S3 bucket to store files to perform deployment>

    $ cdk deploy SecurityFindingGeneratorStack –parameters securityserviceuserdata=inspector
    <deploys the cdk project into the authenticated AWS account>
    Note: allowed values for securityserviceuserdata are: [guardduty, inspector]

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

