import { CustomResource, CfnParameter, Duration, Stack, StackProps, RemovalPolicy, CfnOutput, aws_dynamodb, CfnCondition, Fn, Tags, CfnCustomResource} from 'aws-cdk-lib';
import * as customresources from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import {readFileSync} from 'fs';
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs"; 
import { Function, Runtime, Code, CfnFunction } from 'aws-cdk-lib/aws-lambda';
import { join } from 'path';
import * as events from 'aws-cdk-lib/aws-events'
import { LambdaFunction, SnsTopic } from 'aws-cdk-lib/aws-events-targets';
import { CfnEIP, CfnInstance, UserData } from 'aws-cdk-lib/aws-ec2';
import { CfnKey, Key } from 'aws-cdk-lib/aws-kms';
import { BlockPublicAccess, Bucket, BucketEncryption, CfnBucket, ObjectOwnership } from 'aws-cdk-lib/aws-s3';
import { BucketDeployment, Source } from 'aws-cdk-lib/aws-s3-deployment';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { AttributeType, BillingMode, CfnTable, Table } from 'aws-cdk-lib/aws-dynamodb';
import { AccessKey, AccessKeyStatus, CfnAccessKey, CfnManagedPolicy, CfnPolicy, CfnRole, CfnUser } from 'aws-cdk-lib/aws-iam';
import { CfnSecret, Secret } from 'aws-cdk-lib/aws-secretsmanager';
import { LambdaSubscription } from 'aws-cdk-lib/aws-sns-subscriptions';
import { CfnSubscription, CfnTopic, Topic } from 'aws-cdk-lib/aws-sns';
import { Rule, RuleTargetInput } from 'aws-cdk-lib/aws-events';

export class SecurityFindingGeneratorStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const latest_ec2_ami_id = new CfnParameter(this, 'latest_ec2_ami_id', {
      type: 'AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>',
      description: 'Latest EC2 AMI from Systems Manager Parameter Store.',
      default: '/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2'
    });

    const cw_vpc_flow_logs_parameter = new CfnParameter(this, 'cw_flow_logs_parameter', {
      type: 'String',
      description: 'The cloudwatch log group name for VPC flow logs.',
      default: '/aws/vpc/securitydemo/flowlogs'
    });

    const cw_flow_logs = new LogGroup(this, 'cw_flow_logs', {
      logGroupName: cw_vpc_flow_logs_parameter.valueAsString,
      removalPolicy: RemovalPolicy.DESTROY,
      retention: RetentionDays.ONE_YEAR
      });

    const security_service_user_data = new CfnParameter(this, 'security_service_user_data', {
      type: 'String',
      description: 'This will determine the EC2 user data script to generate real findings. Allowed values are: inspector or guardduty.',
      default: 'guardduty',
      allowedValues: [
        'inspector',
        'guardduty'
      ]
    });

    // AWS System Manager Parameters 
    const security_demo_parameter = new ssm.StringParameter(this, 'security_demo_parameter', {
      parameterName: '/security-demo-user-data',
      stringValue: security_service_user_data.valueAsString,
      description: 'This will determine the EC2 user data script to generate real findings. Allowed values are: inspector or guardduty.',
      tier: ssm.ParameterTier.STANDARD,
      allowedPattern: '.*',
    });

    // Security demo VPC infrastructure
    const security_demo_vpc = new ec2.Vpc(this, 'security_demo_vpc', {
      natGateways: 1,
      ipAddresses: ec2.IpAddresses.cidr('172.0.0.0/16'),
      maxAzs: 2,
      subnetConfiguration: [
        {cidrMask: 24,
        name: 'demo_public_subnet',
        subnetType: ec2.SubnetType.PUBLIC},
        {cidrMask: 24,
        name: 'demo_private_iso_subnet',
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED},
        {cidrMask: 24,
        name: 'demo_private_nat_subnet',
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS},
      ],
      flowLogs: {
        's3': {
          destination: ec2.FlowLogDestination.toCloudWatchLogs(cw_flow_logs),
          trafficType: ec2.FlowLogTrafficType.ALL,
      }},
    });

    Tags.of(security_demo_vpc).add('security_service', security_service_user_data.valueAsString)

    const security_demo_sg = new ec2.SecurityGroup(this, 'security_demo_sg', {
      vpc: security_demo_vpc,
      description: 'Security demo workload security group.',
      allowAllOutbound: false,
      securityGroupName: 'security_demo_sg'
    });

    security_demo_sg.connections.allowTo(security_demo_sg, ec2.Port.tcp(443), 'Allow HTTPS Outbound for PrivateLink')
    security_demo_sg.connections.allowFrom(security_demo_sg, ec2.Port.tcp(443), 'Allow HTTPS Inbound for PrivateLink')
    security_demo_sg.connections.allowTo(ec2.Peer.anyIpv4(), ec2.Port.tcp(443), 'Allow HTTPS Outbound for Egress internet connectivity')
    security_demo_sg.connections.allowTo(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'Allow HTTP Outbound for Egress internet connectivity')
    security_demo_sg.connections.allowTo(ec2.Peer.anyIpv4(), ec2.Port.tcp(17777), 'Allow BitcoinTool (17777) Outbound for Egress internet connectivity')
    security_demo_sg.connections.allowTo(ec2.Peer.anyIpv4(), ec2.Port.tcp(587), 'Allow DropPoint (587) Outbound for Egress internet connectivity')


    security_demo_vpc.addInterfaceEndpoint('ec2_endpoint',{
      service: ec2.InterfaceVpcEndpointAwsService.EC2,
      privateDnsEnabled: true,
      subnets: {
         subnets: [
          security_demo_vpc.selectSubnets({subnetGroupName: 'demo_private_nat_subnet'}).subnets[0]
         ]
      },
      securityGroups: (
        [security_demo_sg]
      )
    });

    security_demo_vpc.addInterfaceEndpoint('ec2_msg_endpoint',{
      service: ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES,
      privateDnsEnabled: true,
      subnets: {
         subnets: [
          security_demo_vpc.selectSubnets({subnetGroupName: 'demo_private_nat_subnet'}).subnets[0]
         ]
      },
      securityGroups: (
        [security_demo_sg]
      )
    });

    security_demo_vpc.addInterfaceEndpoint('kms_endpoint',{
      service: ec2.InterfaceVpcEndpointAwsService.KMS,
      privateDnsEnabled: true,
      subnets: {
         subnets: [
          security_demo_vpc.selectSubnets({subnetGroupName: 'demo_private_nat_subnet'}).subnets[0]
         ]
      },
      securityGroups: (
        [security_demo_sg]
      )
    });

    security_demo_vpc.addInterfaceEndpoint('ssm_endpoint',{
      service: ec2.InterfaceVpcEndpointAwsService.SSM,
      privateDnsEnabled: true,
      subnets: {
         subnets: [
          security_demo_vpc.selectSubnets({subnetGroupName: 'demo_private_nat_subnet'}).subnets[0]
         ]
      },
      securityGroups: (
        [security_demo_sg]
      )
    });

    security_demo_vpc.addInterfaceEndpoint('ssm_msg_endpoint',{
      service: ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
      privateDnsEnabled: true,
      subnets: {
         subnets: [
          security_demo_vpc.selectSubnets({subnetGroupName: 'demo_private_nat_subnet'}).subnets[0]
         ]
      },
      securityGroups: (
        [security_demo_sg]
      )
    });

    security_demo_vpc.addInterfaceEndpoint('s3_endpoint',{
      service: new ec2.InterfaceVpcEndpointService('com.amazonaws.us-east-1.s3', 443),
      subnets: {
         subnets: [
          security_demo_vpc.selectSubnets({subnetGroupName: 'demo_private_nat_subnet'}).subnets[0]
         ]
      },
      securityGroups: (
        [security_demo_sg]
      )
    });

    // S3 Bucket & KMS key for EC2 instance user data scripts

    // KMS Key for S3 Bucket for User Data scripts
    const security_demo_s3_user_data_key = new Key(this, 'security_demo_s3_user_data_key', {
      removalPolicy: RemovalPolicy.DESTROY,
      pendingWindow: Duration.days(7),
      description: 'KMS key for S3 Bucket for EC2 user data scripts.',
      enableKeyRotation: true,
      alias: 'security_demo_s3_key'
    });

    // S3 Bucket for user data script in security finding demo
    const security_demo_s3_user_data_bucket = new Bucket(this, 'security_demo_s3_user_data_bucket', {
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      bucketKeyEnabled: true,
      encryption: BucketEncryption.KMS,
      encryptionKey: security_demo_s3_user_data_key,
      enforceSSL: true,
      versioned: true,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      objectOwnership: ObjectOwnership.BUCKET_OWNER_PREFERRED,
      publicReadAccess: false,
      bucketName: 'security-demo-user-data-bucket' + this.account + '-' + this.region
    });

    const security_demo_s3_user_data_bucket_parameter = new ssm.StringParameter(this, 'security_demo_s3_user_data_bucket_parameter', {
      parameterName: '/security_demo_s3_user_data_bucket_parameter',
      stringValue: security_demo_s3_user_data_bucket.bucketName,
      description: 'Bucket name to use to enable for CloudTrail.',
      tier: ssm.ParameterTier.STANDARD,
      allowedPattern: '.*',
    });

    const user_data_asset_deployment = new BucketDeployment(this, 'user_data_asset_deployment', {
      sources:[Source.asset(
        join(__dirname,  "../user-data"),
        // {exclude:
        //   ["**', '!' + security_service_user_data + '-user-data.sh"]
        // }
      )],
      destinationKeyPrefix: 'ec2-user-data-demo/',
      destinationBucket: security_demo_s3_user_data_bucket,
      retainOnDelete: false
    });
    
    // EC2 instance IAM role 
    const ec2_instance_module_role = new iam.Role(this, 'ec2_instance_module_role', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      roleName: "ec2-security-demo-role",
      managedPolicies: [
        //CHANGE ME
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'EC2DemoAdminAccess', 'arn:aws:iam::aws:policy/AdministratorAccess'),
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaAmazonEC2RoleforSSMPolicy', 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore')
      ]
    });

    const create_ec2_instance_profile_policy = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "KMSAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "kms:DescribeKey",
            "kms:Decrypt",
            "kms:Encrypt",
            "kms:GenerateDataKey"
          ],
          resources: [
            "arn:" + this.partition + ":kms:" + this.region + ":" + this.account + ":key/*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "EC2Allow",
          effect: iam.Effect.ALLOW,
          actions: [
            "ec2:CreateNetworkInterface",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DeleteNetworkInterface"
          ],
          resources: [
            "arn:" + this.partition + ":ec2:" + this.region + ":" + this.account + ":subnet/*",
            "arn:" + this.partition + ":ec2:" + this.region + ":" + this.account + ":network-interface/*",
            "arn:" + this.partition + ":ec2:" + this.region + ":" + this.account + ":security-group/*",

          ]   
        }),
        new iam.PolicyStatement({
          sid: "SSMAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "ssm:GetParameter",
            "ssm:GetParameters",
            "ssm:PutParameter"
          ],
          resources: [
            security_demo_parameter.parameterArn,
          ]   
        })
      ],
    });

    new iam.ManagedPolicy(this, 'EC2CreateModuleManagedPolicy', {
      description: 'Policy for EC2 instance profile role.',
      document:create_ec2_instance_profile_policy,
      managedPolicyName: 'ec2-inspector-demo-policy',
      roles: [ec2_instance_module_role]
    });


    security_demo_s3_user_data_bucket.addToResourcePolicy(new iam.PolicyStatement({
      actions: [
        's3:GetObject',
        's3:ListBucket',
        's3:PutObject'
      ],
      resources: [
        security_demo_s3_user_data_bucket.bucketArn,
        security_demo_s3_user_data_bucket.arnForObjects('*')
      ],
      principals: [
        ec2_instance_module_role
      ]
    }));

    security_demo_s3_user_data_key.addToResourcePolicy(new iam.PolicyStatement({
      actions: [
        'kms:Describe',
        'kms:Decrypt',
        'kms:GenerateDataKey'
      ],
      resources: [
        '*'
      ],
      principals: [
        ec2_instance_module_role
      ]
    }));

    const demo_ec2_instance = new ec2.Instance(this, 'demo_ec2_instance', {
      vpc: security_demo_vpc,
      instanceName: "security_services_finding_demo",
      role: ec2_instance_module_role,
      securityGroup: security_demo_sg,
      instanceType: ec2.InstanceType.of(
        ec2.InstanceClass.BURSTABLE3,
        ec2.InstanceSize.MEDIUM,
      ),
      machineImage: new ec2.AmazonLinuxImage({
        generation: ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
      }),
      blockDevices: [
        {
          deviceName: '/dev/xvda',
          mappingEnabled: true,
          volume: ec2.BlockDeviceVolume.ebs(30, {
            deleteOnTermination: true,
            volumeType: ec2.EbsDeviceVolumeType.GP2,
            encrypted: true
          })
        }
      ]
    });
    demo_ec2_instance.node.addDependency(user_data_asset_deployment)

    demo_ec2_instance.addUserData(
      'security_service=$(aws ssm get-parameter --name ' + security_demo_parameter.parameterName + ' --region ' + this.region + ' --output text --query Parameter.Value)',
      'sudo aws s3 cp ' + 's3://' + security_demo_s3_user_data_bucket.bucketName + '/ec2-user-data-demo/$security_service-user-data.sh /home/ec2-user/',
      'sudo chmod +x /home/ec2-user/$security_service-user-data.sh',
      'sudo /home/ec2-user/$security_service-user-data.sh'
    )

    // Lambda function to cleanup Inspector demo ECR images
    const lambda_ecr_cleanup_role = new iam.Role(this, 'lambda_ecr_cleanup_role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: "ecr-lambda-cleanup-role",
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaECRCleanupExecutionPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'),
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaAmazonEC2ContainerRegistryFullAccessPolicy', 'arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess'),
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaECRCleanupVPCPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole')
      ]
    });

    const lambda_ecr_cleanup_policy = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "KMSDecrypt",
          effect: iam.Effect.ALLOW,
          actions: [
            "kms:Describe*",
            "kms:Decrypt",
            "kms:GenerateDataKey"
          ],
          resources: [
            "arn:" + this.partition + ":kms:" + this.region + ":" + this.account + ":key/*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "IAMPassRole",
          effect: iam.Effect.ALLOW,
          actions: [
            "iam:PassRole"
          ],
          resources: [
            ec2_instance_module_role.roleArn
          ]   
        }),
        new iam.PolicyStatement({
          sid: "EC2Allow",
          effect: iam.Effect.ALLOW,
          actions: [
            "ec2:AttachNetworkInterface",
            "ec2:CreateNetworkInterface",
            "ec2:DeleteNetworkInterface",
            "ec2:Describe*",
            "ec2:RunInstances",
            "ec2:TerminateInstances"
          ],
          resources: [
            "arn:" + this.partition + ":ec2:" + this.region + ":" + this.account + ":*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "SSMExecute",
          effect: iam.Effect.ALLOW,
          actions: [
            "ssm:SendCommand"
          ],
          resources: [
            "arn:" + this.partition + ":ssm:" + this.region + ":" + this.account + ":document/*",
            "arn:" + this.partition + ":ssm:" + this.region + ":" + this.account + ":managed-instance/*",
            "arn:" + this.partition + ":s3:::*",
            "arn:" + this.partition + ":ec2:" + this.region + ":" + this.account + ":instance/*"

          ]   
        })
      ],
    });

    new iam.ManagedPolicy(this, 'lambdaECRCleanupManagedPolicy', {
      description: 'Cleanup deployed ECR Container image resources',
      document:lambda_ecr_cleanup_policy,
      managedPolicyName: 'ecr-cleanup-policy',
      roles: [lambda_ecr_cleanup_role]
    });

    const ecr_cleanup_function = new Function(this, 'ecr_cleanup_function', {
      runtime: Runtime.PYTHON_3_9,
      code: Code.fromAsset(join(__dirname, "../lambdas/ecr_cleanup")),
      handler: 'ecr_cleanup.lambda_handler',
      description: 'Function to clean up ECR container images built by Inspector demo.',
      timeout: Duration.seconds(300),
      memorySize: 1024,
      role: lambda_ecr_cleanup_role,
      // vpc: security_demo_vpc,
      // securityGroups: [security_demo_sg],
      // vpcSubnets:{
      //   subnetGroupName: 'demo_private_iso_subnet'                                                                                                               
      // }
    });

    const ecr_rule = new events.Rule(this, 'ecr_rule', {
      schedule: events.Schedule.expression('cron(0 2 2 * ? *)'),
      enabled: true,
      description: "EventBridge Rule cron job to invoke lambda function to cleanup images in the vuln-images ECR repository."
    });

    ecr_rule.addTarget(new LambdaFunction(ecr_cleanup_function))

    const ecr_provider = new customresources.Provider(this, 'ecr_ResourceProvider', {
      onEventHandler: ecr_cleanup_function,
      logRetention: RetentionDays.ONE_WEEK
    });

    const ecr_cleanup_custom_action = new CustomResource(this, 'ecr_cleanup_custom_action', {
      serviceToken: ecr_provider.serviceToken,
      resourceType: 'Custom::ActionTarget',
      properties: {
        Action: 'lambda:InvokeFunction',
          Description: 'The custom Resource to cleanup vuln ECR images.',
          ServiceToken: ecr_cleanup_function.functionArn
      }
    });

    // // Custom Resource to delete ENI when stack is deleted
    // const cleanup_custom_resource_role = new iam.Role(this, 'lambda-eni-cleanup_custom_resource_role', {
    //   assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    //   roleName: "lambda-eni-cleanup-custom-resource-role",
    //   managedPolicies: [
    //     iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaENICleanupExecutionPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
    //   ]
    // });

    // const eni_cleanup_custom_resource = new Function(this, 'eni_cleanup_custom_resource', {
    //   runtime: Runtime.PYTHON_3_9,
    //   code: Code.fromAsset(join(__dirname, "../lambdas/custom_resource")),
    //   handler: 'lambda_eni_cleanup.lambda_handler',
    //   description: 'Cleanup lambda ENI during stack destroy.',
    //   timeout: Duration.seconds(900),
    //   memorySize: 512,
    //   role: cleanup_custom_resource_role,
    //   environment:{
    //     VPC_ID: security_demo_vpc.vpcId
    //   },
    //   // vpc: security_demo_vpc,
    //   // securityGroups: [security_demo_sg],
    //   // vpcSubnets:{
    //   //   subnetGroupName: 'demo_private_iso_subnet'                                                                                                               
    //   // }
    // });

    // const eni_cleanup_custom_resource_policy = new iam.PolicyDocument({
    //   statements: [
    //     new iam.PolicyStatement({
    //       sid: "EC2Allow",
    //       effect: iam.Effect.ALLOW,
    //       actions: [
    //         "ec2:AttachNetworkInterface",
    //         "ec2:CreateNetworkInterface",
    //         "ec2:DeleteNetworkInterface",
    //         "ec2:Describe*",
    //         "ec2:RunInstances",
    //         "ec2:TerminateInstances"
    //       ],
    //       resources: [
    //         "*",
    //       ]   
    //     }),
    //   ],
    // });

    // new iam.ManagedPolicy(this, 'lambdaENICleanupManagedPolicy', {
    //   description: 'Deletes ENI when stack is removed.',
    //   document:eni_cleanup_custom_resource_policy,
    //   managedPolicyName: 'custom-resource-eni-cleanup-policy',
    //   roles: [cleanup_custom_resource_role]
    // });

    // const eni_provider = new customresources.Provider(this, 'eni_ResourceProvider', {
    //   onEventHandler: eni_cleanup_custom_resource,
    //   logRetention: RetentionDays.ONE_WEEK
    // });

    // const eni_cleanup_custom_action = new CustomResource(this, 'eni_cleanup_custom_action', {
    //   serviceToken: eni_provider.serviceToken,
    //   resourceType: 'Custom::ActionTarget',
    //   properties: {
    //     Action: 'lambda:InvokeFunction',
    //       Description: 'The custom Resource to cleanup orphaned Lambda ENIs.',
    //       ServiceToken: eni_cleanup_custom_resource.functionArn
    //   }
    // });

    // -------------------------------------------------------------------------------------------
    // -------------------------------------------------------------------------------------------
    // -------------------------------------------------------------------------------------------
    // CONDITIONAL INFRASTRUCTURE deployed if security_service_user_data user input is "guardduty"
    // -------------------------------------------------------------------------------------------
    // -------------------------------------------------------------------------------------------
    // -------------------------------------------------------------------------------------------

    const guardduty_condition = new CfnCondition(this, 'guardduty_condition',{
      expression: Fn.conditionEquals(security_service_user_data, "guardduty")
    });

    const db_pw_parameter = new ssm.StringParameter(this, 'db_pw_parameter', {
      parameterName: 'gd_prod_dbpwd_sample',
      stringValue: 'NA',
      description: 'This is an example secret for generating GuardDuty findings.',
      tier: ssm.ParameterTier.STANDARD,
      allowedPattern: '.*',
    });
    (db_pw_parameter.node.defaultChild as ssm.CfnParameter).cfnOptions.condition = guardduty_condition

    // S3 Bucket & KMS key for security finding demo

    // KMS Key for S3 Bucket for security finding demo
    const security_demo_kms_key = new Key(this, 'security_demo_kms_key', {
      removalPolicy: RemovalPolicy.DESTROY,
      pendingWindow: Duration.days(7),
      description: 'KMS key for security finding demo.',
      enableKeyRotation: true,
      // alias: 'security_demo_key'
    });
    (security_demo_kms_key.node.defaultChild as CfnKey).cfnOptions.condition = guardduty_condition

    // S3 Bucket for security finding demo
    const security_service_demo_bucket = new Bucket(this, 'security_service_demo_bucket', {
      removalPolicy: RemovalPolicy.DESTROY,
      // autoDeleteObjects: Fn.conditionIf('guardduty_condition', true, false).toString() as unknown as boolean,
      bucketKeyEnabled: true,
      encryption: BucketEncryption.KMS,
      encryptionKey: security_demo_kms_key,
      // enforceSSL: true,
      versioned: true,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      objectOwnership: ObjectOwnership.BUCKET_OWNER_PREFERRED,
      publicReadAccess: false,
      serverAccessLogsBucket: security_demo_s3_user_data_bucket,
      serverAccessLogsPrefix: 'security_service_demo_access_logging',
      bucketName: 'guardduty-finding-demo-' + this.account + '-' + this.region
    });
    (security_service_demo_bucket.node.defaultChild as CfnBucket).cfnOptions.condition = guardduty_condition

    security_service_demo_bucket.addToResourcePolicy(new iam.PolicyStatement({
      actions: [
        's3:GetBucketAcl'
      ],
      resources: [
        security_service_demo_bucket.bucketArn,
      ],
      principals: [
        new iam.ServicePrincipal('cloudtrail.amazonaws.com')
      ]
    }));

    security_service_demo_bucket.addToResourcePolicy(new iam.PolicyStatement({
      actions: [
        's3:PutObject'
      ],
      resources: [
        security_service_demo_bucket.bucketArn + '/*',
      ],
      principals: [
        new iam.ServicePrincipal('cloudtrail.amazonaws.com')
      ],
      conditions: {
        'StringEquals': {
          "s3:x-amz-acl": "bucket-owner-full-control",
        },
        'StringLike': {
          "aws:SourceArn": "arn:aws:cloudtrail:" + this.region + ":" + this.account + ":trail/*"
        }
      }
    }));

    const security_service_demo_bucket_parameter = new ssm.StringParameter(this, 'security_service_demo_bucket_parameter', {
      parameterName: '/security_demo_bucket_parameter',
      stringValue: security_service_demo_bucket.bucketName,
      description: 'Bucket name for GuardDuty demo',
      tier: ssm.ParameterTier.STANDARD,
      allowedPattern: '.*',
    });
    (security_service_demo_bucket_parameter.node.defaultChild as ssm.CfnParameter).cfnOptions.condition = guardduty_condition

    const eks_cluster_name_parameter = new ssm.StringParameter(this, 'eks_cluster_name_parameter', {
      parameterName: '/security_demo_eks_name_parameter',
      stringValue: 'GuardDuty-Finding-Demo',
      description: 'EKS Cluster name for GuardDuty demo',
      tier: ssm.ParameterTier.STANDARD,
      allowedPattern: '.*',
    });
    (eks_cluster_name_parameter.node.defaultChild as ssm.CfnParameter).cfnOptions.condition = guardduty_condition

    // Mock DynamoDB table for security finding demo

    const security_demo_dynamodb = new Table(this, 'security_demo_dynamodb', {
      billingMode: BillingMode.PROVISIONED,
      readCapacity: 5,
      writeCapacity: 5,
      removalPolicy: RemovalPolicy.DESTROY,
      partitionKey: {name: 'name', type: AttributeType.STRING},
      //sortKey: {name: 'createdAt', type: AttributeType.NUMBER},
      tableName: 'GuardDuty-example-customer-DB'
    });
    (security_demo_dynamodb.node.defaultChild as CfnTable).cfnOptions.condition = guardduty_condition

    const security_demo_dynamodb_parameter = new ssm.StringParameter(this, 'security_demo_dynamodb_parameter', {
      parameterName: '/security_demo_dynamodb_name',
      stringValue: security_demo_dynamodb.tableName,
      description: 'DynamoDB table name for GuardDuty finding.',
      tier: ssm.ParameterTier.STANDARD,
      allowedPattern: '.*',
    });
    (security_demo_dynamodb_parameter.node.defaultChild as ssm.CfnParameter).cfnOptions.condition = guardduty_condition

    // AWS IAM User for generating GuardDuty findings
    const guardduty_demo_user = new iam.User(this, 'guardduty_demo_user',{
      userName: 'guardduty-demo-user',
    });
    (guardduty_demo_user.node.defaultChild as CfnUser).cfnOptions.condition = guardduty_condition

    const compromised_access_key = new AccessKey(this, 'compromised_access_key',{
      user: guardduty_demo_user,
      status: AccessKeyStatus.INACTIVE
    });
    (compromised_access_key.node.defaultChild as CfnAccessKey).cfnOptions.condition = guardduty_condition

    const compromised_access_key_parameter = new ssm.StringParameter(this, 'compromised_access_key_parameter', {
      parameterName: '/security_demo_access_key',
      stringValue: compromised_access_key.accessKeyId,
      description: 'Demo IAM User access key for '+ guardduty_demo_user.userName +'.',
      tier: ssm.ParameterTier.STANDARD,
      allowedPattern: '.*',
    });
    (compromised_access_key_parameter.node.defaultChild as ssm.CfnParameter).cfnOptions.condition = guardduty_condition

    const compromised_access_key_secret = new Secret(this, 'compromised_access_key_secret', {
      secretName: guardduty_demo_user.userName + '-secret-key',
      secretStringValue: compromised_access_key.secretAccessKey,
      encryptionKey: security_demo_s3_user_data_key
    });
    (compromised_access_key_secret.node.defaultChild as CfnSecret).cfnOptions.condition = guardduty_condition

    const guardduty_demo_user_policy_document = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "EC2Allow",
          effect: iam.Effect.ALLOW,
          actions: [
            "s3:PutBucketPublicAccessBlock",
            "s3:PutBucketLogging"
          ],
          resources: [
            security_service_demo_bucket.bucketArn
          ]   
        }),
      ],
    });

    const guardduty_demo_user_policy = new iam.Policy(this, 'guardduty_demo_user_policy', {
      policyName: 'guardduty_demo_user_policy',
      document: guardduty_demo_user_policy_document,
      users: [guardduty_demo_user]
    });
    (guardduty_demo_user_policy.node.defaultChild as CfnPolicy).cfnOptions.condition = guardduty_condition

    const guardduty_demo_user_key = new iam.AccessKey(this, 'guardduty_demo_user_key', {
      user: guardduty_demo_user
    });
    (guardduty_demo_user_key.node.defaultChild as CfnAccessKey).cfnOptions.condition = guardduty_condition


    // EC2 instances to create EC2/IAM/S3 GuardDuty findings.
    const ec2_general_role = new iam.Role(this, 'ec2_general_role', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      roleName: "ec2-general-demo-role",
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'EC2S3ReadOnlyAccess', 'arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess'),
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'EC2RoleforSSMAccess', 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'),
        //CHANGE ME
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'EC2AdminAccess', 'arn:aws:iam::aws:policy/AdministratorAccess')
      ]
    });
   // (ec2_general_role.node.defaultChild as CfnRole).cfnOptions.condition = guardduty_condition

   security_demo_s3_user_data_bucket.addToResourcePolicy(new iam.PolicyStatement({
    actions: [
      's3:GetObject',
      's3:ListBucket',
      's3:PutObject'
    ],
    resources: [
      security_demo_s3_user_data_bucket.bucketArn,
      security_demo_s3_user_data_bucket.arnForObjects('*')
    ],
    principals: [
      ec2_general_role
    ]
  }));

  security_demo_s3_user_data_key.addToResourcePolicy(new iam.PolicyStatement({
    actions: [
      'kms:Describe',
      'kms:Decrypt',
      'kms:GenerateDataKey'
    ],
    resources: [
      '*'
    ],
    principals: [
      ec2_general_role
    ]
  }));

    const general_ec2_instance_profile_policy = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "SSMWriteAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "ssm:GetParameter",
            "ssm:DescribeParameters",
            "ssm:PutParameter"
          ],
          resources: [
            security_demo_s3_user_data_bucket_parameter.parameterArn,
            security_demo_dynamodb_parameter.parameterArn,
            db_pw_parameter.parameterArn,
            eks_cluster_name_parameter.parameterArn
          ]   
        }),
        new iam.PolicyStatement({
          sid: "DynamoDBWriteAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "dynamodb:PutItem"
          ],
          resources: [
            security_demo_dynamodb.tableArn
          ]   
        }),
        new iam.PolicyStatement({
          sid: "DynamoDBReadAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "dynamodb:DescribeTable",
            "dynamodb:ListTables"
          ],
          resources: [
            "arn:" + this.partition + ":dynamodb:" + this.region + ":" + this.account + ":table/*}"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "S3DemoWriteAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "s3:PutBucketLogging",
            "s3:PutBucketPublicAccessBlock"
          ],
          resources: [
            security_service_demo_bucket.bucketArn
          ]   
        }),
        new iam.PolicyStatement({
          sid: "S3WriteAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "s3:GetAccountPublicAccessBlock",
            "s3:ListBucket",
            "s3:PutAccountPublicAccessBlock"
          ],
          resources: [
            "*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "SecretsManagerReadAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "secretsmanager:GetSecretValue"
          ],
          resources: [
            compromised_access_key_secret.secretArn
          ]   
        }),
      ],
    });

    const ec2_general_managed_policy = new iam.ManagedPolicy(this, 'ec2_general_managed_policy', {
      description: 'Policy for general EC2 instance profile role.',
      document: general_ec2_instance_profile_policy,
      managedPolicyName: 'ec2-guardduty-general-demo-policy',
      roles: [ec2_general_role]
    });
    (ec2_general_managed_policy.node.defaultChild as CfnManagedPolicy).cfnOptions.condition = guardduty_condition

    const compromised_ec2_instance = new ec2.Instance(this, 'compromised_ec2_instance', {
      vpc: security_demo_vpc,
      // vpcSubnets: {
      //   subnetGroupName: 'demo_public_subnet'
      // },
      instanceName: "guardduty_compromised_finding_demo",
      role: ec2_general_role,
      securityGroup: security_demo_sg,
      instanceType: ec2.InstanceType.of(
        ec2.InstanceClass.BURSTABLE2,
        ec2.InstanceSize.MICRO,
      ),
      machineImage: new ec2.AmazonLinuxImage({
        generation: ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
      }),
      blockDevices: [
        {
          deviceName: '/dev/xvda',
          mappingEnabled: true,
          volume: ec2.BlockDeviceVolume.ebs(30, {
            deleteOnTermination: true,
            volumeType: ec2.EbsDeviceVolumeType.GP2,
            encrypted: true
          })
        }
      ]
    });
    (compromised_ec2_instance.node.defaultChild as CfnInstance).cfnOptions.condition = guardduty_condition

    const compromised_ec2_eip = new CfnEIP(this, 'compromised_ec2_eip',{
      domain: 'vpc',
      instanceId: compromised_ec2_instance.instanceId
    })
    compromised_ec2_eip.cfnOptions.condition = guardduty_condition

    // For GuardDuty Finding: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
    compromised_ec2_instance.addUserData(
      'sleep 60',
      'sudo aws s3 cp ' + 's3://' + security_demo_s3_user_data_bucket.bucketName + '/ec2-user-data-demo/guardduty-user-data-credentials.sh /home/ec2-user/',
      'sudo chmod +x /home/ec2-user/guardduty-user-data-credentials.sh',
      'sudo /home/ec2-user/guardduty-user-data-credentials.sh'
    )
    // Lambda function to put GuardDuty Threat IP list

    const lambda_threat_list_role = new iam.Role(this, 'lambda_threat_list_role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: "guardduty-threat-list-lambda-role",
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaGDThreatListExecutionPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'),
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaGDThreatListVPCPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole')
      ]
    });
    //(lambda_threat_list_role.node.defaultChild as CfnRole).cfnOptions.condition = guardduty_condition

    const lambda_threat_list_policy = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "GuardDutyAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "guardduty:CreateThreatIntelSet",
            "guardduty:GetDetector",
            "guardduty:GetThreatIntelSet",
            "guardduty:ListDetectors",
            "guardduty:ListThreatIntelSets",
            "guardduty:UpdateThreatIntelSet",
            "guardduty:UpdateDetector"
          ],
          resources: [
            "arn:" + this.partition + ":guardduty:" + this.region + ":" + this.account + ":detector/*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "IAMAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "iam:PutRolePolicy",
            "iam:DeleteRolePolicy"
          ],
          resources: [
            "arn:" + this.partition + ":iam::" + this.account + ":role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty"
          ]   
        })
      ],
    });

    security_demo_s3_user_data_bucket.addToResourcePolicy(new iam.PolicyStatement({
      actions: [
        's3:GetObject',
        's3:ListBucket',
        's3:PutObject'
      ],
      resources: [
        security_demo_s3_user_data_bucket.bucketArn,
        security_demo_s3_user_data_bucket.arnForObjects('*')
      ],
      principals: [
        lambda_threat_list_role
      ]
    }));

    security_demo_s3_user_data_key.addToResourcePolicy(new iam.PolicyStatement({
      actions: [
        'kms:Describe',
        'kms:Decrypt',
        'kms:GenerateDataKey'
      ],
      resources: [
        '*'
      ],
      principals: [
        lambda_threat_list_role,
        new iam.ArnPrincipal('arn:aws:iam::' + this.account + ':role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty')      
      ]
    }));

    const lambda_threat_list_managed_policy = new iam.ManagedPolicy(this, 'lambdaGDThreatListManagedPolicy', {
      description: 'Add GuardDuty Threat IP list.',
      document:lambda_threat_list_policy,
      managedPolicyName: 'gd-threat-list-policy',
      roles: [lambda_threat_list_role]
    });
    (lambda_threat_list_managed_policy.node.defaultChild as CfnManagedPolicy).cfnOptions.condition = guardduty_condition

    const guardduty_threat_list_function = new Function(this, 'guardduty_threat_list_function', {
      functionName: 'guardduty_threat_list_function',
      runtime: Runtime.PYTHON_3_9,
      code: Code.fromAsset(join(__dirname, "../lambdas/threat_list")),
      handler: 'threat_list.lambda_handler',
      description: 'Function to put GuardDuty Threat IP list for demo.',
      timeout: Duration.seconds(120),
      memorySize: 1024,
      role: lambda_threat_list_role,
      environment:{
        BUCKET_NAME: security_demo_s3_user_data_bucket.bucketName,
        THREAT_LIST: compromised_ec2_instance.instancePrivateIp
        //THREAT_LIST: compromised_ec2_eip.ref
      },
      // vpc: security_demo_vpc,
      // securityGroups: [security_demo_sg],
      // vpcSubnets:{
      //   subnetGroupName: 'demo_private_iso_subnet'                                                                                                               
      // }
    });
    (guardduty_threat_list_function.node.defaultChild as CfnFunction).cfnOptions.condition = guardduty_condition

    const guardduty_threat_list_provider = new customresources.Provider(this, 'guardduty_threat_list_provider', {
      onEventHandler: guardduty_threat_list_function,
      logRetention: RetentionDays.ONE_WEEK
    });

    const guardduty_threat_list_custom_action = new CustomResource(this, 'threat_list_custguardduty_threat_list_custom_actionom_action', {
      serviceToken: guardduty_threat_list_provider.serviceToken,
      resourceType: 'Custom::ActionTarget',
      properties: {
        Action: 'lambda:InvokeFunction',
          Description: 'The custom Resource to add to the GuardDuty threat list.',
          ServiceToken: guardduty_threat_list_function.functionArn
      }
    });
    (guardduty_threat_list_custom_action.node.defaultChild as CfnCustomResource).cfnOptions.condition = guardduty_condition

    // Create GuardDuty SNS topic
    const guardduty_topic = new Topic(this, 'guardduty_topic', {
      displayName: 'GuardDuty Demo IAM SNS topic',
      masterKey: security_demo_s3_user_data_key
    });
    (guardduty_topic.node.defaultChild as CfnTopic).cfnOptions.condition = guardduty_condition

    // Create lambda function to cleanup GD IAM findings
    const guardduty_iam_remediation_role = new iam.Role(this, 'guardduty_iam_remediation_role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: "guardduty-demo-iam-remediation-role",
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaGDIAMRemediationExecutionPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
      ]
    });
    (guardduty_iam_remediation_role.node.defaultChild as CfnRole).cfnOptions.condition = guardduty_condition

    const guardduty_iam_remediation_policy = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "SSMAccess",
          effect: iam.Effect.ALLOW,
          actions: [
            "ssm:DescribeParameters",
            "ssm:GetParameter",
            "ssm:GetParameters"
          ],
          resources: [
            "arn:" + this.partition + ":ssm:" + this.region + ":" + this.account + ":parameter/*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "IAMPassRole",
          effect: iam.Effect.ALLOW,
          actions: [
            "iam:PassRole"
          ],
          resources: [
            ec2_instance_module_role.roleArn
          ]   
        }),
        new iam.PolicyStatement({
          sid: "EC2Allow",
          effect: iam.Effect.ALLOW,
          actions: [
            "ec2:ReplaceIamInstanceProfileAssociation",
            "ec2:DescribeIamInstanceProfileAssociations"
          ],
          resources: [
            "arn:" + this.partition + ":ec2:" + this.region + ":" + this.account + ":instance/*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "IAMAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "iam:AddRoleToInstanceProfile",
            "iam:CreateInstanceProfile",
            "iam:ListInstanceProfilesForRole",
            "iam:RemoveRoleFromInstanceProfile"
          ],
          resources: [
            "arn:" + this.partition + ":iam::" + this.account + ":instance-profile/*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "CompromisedEC2Remediation",
          effect: iam.Effect.ALLOW,
          actions: [
            "iam:DeleteInstanceProfile",
            "iam:PassRole",
            "iam:PutRolePolicy"
          ],
          resources: [
            ec2_general_role.roleArn,
            "arn:" + this.partition + ":iam::" + this.account + ":role/eksctl-GuardDuty-Finding-Demo-addon-iamservi-Role1-*",
            "arn:" + this.partition + ":iam::" + this.account + ":role/eksctl-GuardDuty-Finding-Demo-nod-NodeInstanceRole-*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "SNSAllow",
          effect: iam.Effect.ALLOW,
          actions: [
            "sns:Publish"
          ],
          resources: [
            guardduty_topic.topicArn
          ]   
        })
      ],
    });

    const guardduty_iam_remediation_managed_policy = new iam.ManagedPolicy(this, 'lambdaGDIAMRemediationManagedPolicy', {
      description: 'Remediate GuardDuty IAM findings from the demo.',
      document:guardduty_iam_remediation_policy,
      managedPolicyName: 'gd-iam-remediation-policy',
      roles: [guardduty_iam_remediation_role]
    });
    (guardduty_iam_remediation_managed_policy.node.defaultChild as CfnManagedPolicy).cfnOptions.condition = guardduty_condition

    const guardduty_iam_remediation_function = new Function(this, 'guardduty_iam_remediation_function', {
      functionName: 'guardduty_iam_remediation_function',
      runtime: Runtime.PYTHON_3_9,
      code: Code.fromAsset(join(__dirname, "../lambdas/gd_remediate")),
      handler: 'gd_remediate_iam.lambda_handler',
      description: 'Function to remediate GuardDuty Instance Credential Exfil findings.',
      timeout: Duration.seconds(300),
      memorySize: 1024,
      role: guardduty_iam_remediation_role,
      environment: {
        TOPIC_ARN: guardduty_topic.topicArn
      }
      // vpc: security_demo_vpc,
      // securityGroups: [security_demo_sg],
      // vpcSubnets:{
      //   subnetGroupName: 'demo_private_iso_subnet'                                                                                                               
      // }
    });
    (guardduty_iam_remediation_function.node.defaultChild as CfnFunction).cfnOptions.condition = guardduty_condition

    // Lambda function to cleanup GuardDuty demo EKS CloudFormation templates
    const lambda_eks_cleanup_role = new iam.Role(this, 'lambda_eks_cleanup_role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: "eks-lambda-cleanup-role",
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaEKSCleanupExecutionPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'),
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaEKSCleanupVPCPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole')
      ]
    });
    (lambda_eks_cleanup_role.node.defaultChild as CfnRole).cfnOptions.condition = guardduty_condition

    const lambda_eks_cleanup_policy = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "ELBRead",
          effect: iam.Effect.ALLOW,
          actions: [
            "elasticloadbalancing:Describe*"
          ],
          resources: [
            "*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "ELBWrite",
          effect: iam.Effect.ALLOW,
          actions: [
            "elasticloadbalancing:DeleteLoadBalancer"
          ],
          resources: [
            "arn:" + this.partition + ":elasticloadbalancing:" + this.region + ":" + this.account + ":loadbalancer/*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "SNSWrite",
          effect: iam.Effect.ALLOW,
          actions: [
            "sns:Publish"
          ],
          resources: [
            guardduty_topic.topicArn
          ]   
        }),
        new iam.PolicyStatement({
          sid: "CFNRead",
          effect: iam.Effect.ALLOW,
          actions: [
            "cloudformation:Describe*",
            "cloudformation:ListStacks"
          ],
          resources: [
            "*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "CFNDelete",
          effect: iam.Effect.ALLOW,
          actions: [
            "cloudformation:DeleteStack"
          ],
          resources: [
            "arn:" + this.partition + ":cloudformation:" + this.region + ":" + this.account + ":stack/eksctl-GuardDuty-Finding-Demo-cluster/*",
            "arn:" + this.partition + ":cloudformation:" + this.region + ":" + this.account + ":stack/eksctl-GuardDuty-Finding-Demo-addon-iamserviceaccount-kube-system-aws-node/*",
            "arn:" + this.partition + ":cloudformation:" + this.region + ":" + this.account + ":stack/eksctl-GuardDuty-Finding-Demo-nodegroup-ng-*/*"
          ],
        }),
        new iam.PolicyStatement({
          sid: "EC2Write",
          effect: iam.Effect.ALLOW,
          actions: [
            "ec2:Describe*",
            "ec2:DeleteSecurityGroup",
            "ec2:RevokeSecurityGroupIngress",
            "ec2:DeleteLaunchTemplate",
            "ec2:DeleteRouteTable",
            "ec2:DeleteRoute",
            "ec2:DeleteNatGateway",
            "ec2:DeleteSubnet",
            "ec2:DetachInternetGateway"
          ],
          resources: [
            "arn:" + this.partition + ":ec2:" + this.region + ":" + this.account + ":launch-template/*",
            "arn:" + this.partition + ":ec2:" + this.region + ":" + this.account + ":subnet/*",
            "arn:" + this.partition + ":ec2:" + this.region + ":" + this.account + ":security-group/*",
            "arn:" + this.partition + ":ec2:" + this.region + ":" + this.account + ":route-table/*",
            "arn:" + this.partition + ":ec2:" + this.region + ":" + this.account + ":natgateway/*",
            "arn:" + this.partition + ":ec2:" + this.region + ":" + this.account + ":internet-gateway/*",
            "arn:" + this.partition + ":ec2:" + this.region + ":" + this.account + ":vpc/*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "EC2DisassociateRouteTable",
          effect: iam.Effect.ALLOW,
          actions: [
            "ec2:DisassociateRouteTable",
          ],
          resources: [
            "arn:" + this.partition + ":ec2:" + this.region + ":" + this.account + ":*"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "EKSRead",
          effect: iam.Effect.ALLOW,
          actions: [
            "eks:Describe*",
            "eks:DeleteNodegroup",
            "eks:DeleteCluster"
          ],
          resources: [
            "arn:" + this.partition + ":eks:" + this.region + ":" + this.account + ":nodegroup/GuardDuty-Finding-Demo/*",
            "arn:" + this.partition + ":eks:" + this.region + ":" + this.account + ":cluster/GuardDuty-Finding-Demo"
          ]   
        }),
        new iam.PolicyStatement({
          sid: "IAMWrite",
          effect: iam.Effect.ALLOW,
          actions: [
            "iam:DeleteRole",
            "iam:DeleteRolePolicy",
            "iam:DetachRolePolicy"
          ],
          resources: [
            "arn:" + this.partition + ":iam::" + this.account + ":role/eksctl-GuardDuty-Finding-Demo-addon-iamservi-Role1-*",
            "arn:" + this.partition + ":iam::" + this.account + ":role/eksctl-GuardDuty-Finding-Demo-nod-NodeInstanceRole-*",
            "arn:" + this.partition + ":iam::" + this.account + ":role/eksctl-GuardDuty-Finding-Demo-cluster-ServiceRole-*"
          ]   
        }),
      ],
    });

    const lambdaEKSCleanupManagedPolicy = new iam.ManagedPolicy(this, 'lambdaEKSCleanupManagedPolicy', {
      description: 'Cleanup deployed EKS CloudFormation template resources from GuardDuty demo.',
      document:lambda_eks_cleanup_policy,
      managedPolicyName: 'eks-cleanup-policy',
      roles: [lambda_eks_cleanup_role]
    });
    (lambdaEKSCleanupManagedPolicy.node.defaultChild as CfnManagedPolicy).cfnOptions.condition = guardduty_condition


    const eks_cleanup_function = new Function(this, 'eks_cleanup_function', {
      runtime: Runtime.PYTHON_3_9,
      code: Code.fromAsset(join(__dirname, "../lambdas/eks_cleanup")),
      handler: 'eks_cleanup.lambda_handler',
      description: 'Function to clean up EKS CloudFormation template resources built from GuardDuty demo.',
      timeout: Duration.seconds(900),
      memorySize: 1024,
      role: lambda_eks_cleanup_role,
      // vpc: security_demo_vpc,
      // securityGroups: [security_demo_sg],
      // vpcSubnets:{
      //   subnetGroupName: 'demo_private_iso_subnet'                                                                                                               
      // }
    });

    const eks_provider = new customresources.Provider(this, 'eks_provider', {
      onEventHandler: eks_cleanup_function,
      logRetention: RetentionDays.ONE_WEEK
    });

    const eks_cleanup_custom_action = new CustomResource(this, 'eks_cleanup_custom_action', {
      serviceToken: eks_provider.serviceToken,
      resourceType: 'Custom::ActionTarget',
      properties: {
        Action: 'lambda:InvokeFunction',
          Description: 'The custom Resource to clean up EKS CloudFormation template resources built from GuardDuty demo.',
          ServiceToken: eks_cleanup_function.functionArn
      }
    });

    const guardduty_eks_remediation_function = new Function(this, 'guardduty_eks_remediation_function', {
      functionName: 'guardduty_demo_eks_remediation_function',
      runtime: Runtime.PYTHON_3_9,
      code: Code.fromAsset(join(__dirname, "../lambdas/gd_remediate")),
      handler: 'gd_remediate_eks.lambda_handler',
      description: 'Function to remediate EKS GuardDuty findings.',
      timeout: Duration.seconds(900),
      memorySize: 1024,
      role: lambda_eks_cleanup_role,
      environment: {
        TOPIC_ARN: guardduty_topic.topicArn
      }
      // vpc: security_demo_vpc,
      // securityGroups: [security_demo_sg],
      // vpcSubnets:{
      //   subnetGroupName: 'demo_private_iso_subnet'                                                                                                               
      // }
    });
    (guardduty_eks_remediation_function.node.defaultChild as CfnFunction).cfnOptions.condition = guardduty_condition

    //  GuardDuty CloudWatch Event - For GuardDuty Finding: PrivilegeEscalation:Kubernetes/PrivilegedContainer
    const guardduty_remediation_eks_rule = new events.Rule(this, 'guardduty_remediation_eks_rule', {
      ruleName: 'GuardDuty-Event-EKS-Cleanup',
      eventPattern:{
        source: [
          'aws.guardduty'
        ],
        detail: {
          "type" : ["PrivilegeEscalation:Kubernetes/PrivilegedContainer","Execution:Kubernetes/ExecInKubeSystemPod"]
        }
      },
      enabled: true,
      description: "EventBridge Rule to notify and respond to GuardDuty Event: PrivilegeEscalation:Kubernetes/PrivilegedContainer findings."
    });
    guardduty_remediation_eks_rule.addTarget(new LambdaFunction(guardduty_eks_remediation_function));
    (guardduty_remediation_eks_rule.node.defaultChild as events.CfnRule).cfnOptions.condition = guardduty_condition


    const guardduty_eks_rule_InputTransformer: events.RuleTargetInputProperties = {
      inputPathsMap: {
        cluster: "$.detail.resource.EksClusterDetails.Name",
        gdid: "$.detail.id",
        region: "$.detail.region"
      },
      inputTemplate: '"GuardDuty Finding | ID:<gdid>: An EKS Cluster named <cluster> may be compromised and should be investigated. Go to https://console.aws.amazon.com/guardduty/home?region=<region>#/findings?macros=current&fId=<gdid>"',
    };

    guardduty_remediation_eks_rule.addTarget(new SnsTopic(guardduty_topic,{
      message: RuleTargetInput.fromObject(guardduty_eks_rule_InputTransformer)
    }));

    //  GuardDuty CloudWatch Event - For GuardDuty Finding: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
    const guardduty_remediation_credexfil_rule = new events.Rule(this, 'guardduty_remediation_credexfil_rule', {
      ruleName: 'GuardDuty-Event-IAMUser-InstanceCredentialExfiltration',
      eventPattern:{
        source: ["aws.guardduty"],
        detail: {
          "type" : ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"]
        }
      },
      enabled: true,
      description: "EventBridge Rule to notify and respond to GuardDuty Event: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS findings."
    });
    guardduty_remediation_credexfil_rule.addTarget(new LambdaFunction(guardduty_iam_remediation_function));
    (guardduty_remediation_credexfil_rule.node.defaultChild as events.CfnRule).cfnOptions.condition = guardduty_condition

    const guardduty_credexfil_InputTransformer: events.RuleTargetInputProperties = {
      inputPathsMap: {
        userName: "$.detail.resource.accessKeyDetails.userName",
        gdid: "$.detail.id",
        region: "$.detail.region"
      },
      inputTemplate: '"GuardDuty Finding | ID:<gdid>: An EC2 instance IAM credentials (Role: <userName>) may be compromised and should be investigated. Go to https://console.aws.amazon.com/guardduty/home?region=<region>#/findings?macros=current&fId=<gdid>"',
    };
    guardduty_remediation_credexfil_rule.addTarget(new SnsTopic(guardduty_topic,{
      message: RuleTargetInput.fromObject(guardduty_credexfil_InputTransformer)
    }));

    // GuardDuty CloudWatch Event - For GuardDuty Finding: UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom
    const guardduty_respond_IAMUser_rule = new events.Rule(this, 'guardduty_respond_IAMUser_rule', {
      ruleName: 'GuardDuty-Event-IAMUser-MaliciousIPCaller',
      eventPattern:{
        source: ["aws.guardduty"],
        detail: {
          "type" : ["UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom", "Discovery:S3/MaliciousIPCaller.Custom"]
        }
      },
      enabled: true,
      description: "EventBridge Rule to notify for GuardDuty Event: UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom findings."
    });
    (guardduty_respond_IAMUser_rule.node.defaultChild as events.CfnRule).cfnOptions.condition = guardduty_condition

    const guardduty_IAMUser_InputTransformer: events.RuleTargetInputProperties = {
      inputPathsMap: {
        userName: "$.detail.resource.accessKeyDetails.userName",
        gdid: "$.detail.id",
        region: "$.detail.region"
      },
      inputTemplate: '"GuardDuty Finding | ID:<gdid>: An AWS API operation was invoked (userName: <userName>) from an IP address that is included on your threat list and should be investigated. Go to https://console.aws.amazon.com/guardduty/home?region=<region>#/findings?macros=current&fId=<gdid>"',
    };

    guardduty_respond_IAMUser_rule.addTarget(new SnsTopic(guardduty_topic,{
      message: RuleTargetInput.fromObject(guardduty_IAMUser_InputTransformer)
    }));

    // GuardDuty CloudWatch Event - For GuardDuty Finding: UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom
    const guardduty_respond_S3_rule = new events.Rule(this, 'guardduty_respond_S3_rule', {
      ruleName: 'GuardDuty-Event-S3-Stealth-Policy',
      eventPattern:{
        source: ["aws.guardduty"],
        detail: {
          "type" : ["Policy:S3/BucketBlockPublicAccessDisabled", "Stealth:S3/ServerAccessLoggingDisabled"]
        }
      },
      enabled: true,
      description: "EventBridge Rule to notify for GuardDuty Event: Stealth:S3/ServerAccessLoggingDisabled & Policy:S3/BucketBlockPublicAccessDisabled."
    });
    (guardduty_respond_S3_rule.node.defaultChild as events.CfnRule).cfnOptions.condition = guardduty_condition

    const guardduty_S3_InputTransformer: events.RuleTargetInputProperties = {
      inputPathsMap: {
        userName: "$.detail.resource.accessKeyDetails.userName",
        gdid: "$.detail.id",
        region: "$.detail.region"
      },
      inputTemplate: '"GuardDuty Finding | ID:<gdid>: An AWS S3 related API operation was invoked by user (userName: <userName>) in account <account> . This activity seems suspicious. Please investigate with the user to check if this was expectated behaviour. Go to https://console.aws.amazon.com/guardduty/home?region=<region>#/findings?macros=current&fId=<gdid>"',
    };

    guardduty_respond_S3_rule.addTarget(new SnsTopic(guardduty_topic,{
      message: RuleTargetInput.fromObject(guardduty_S3_InputTransformer)
    }));

    // Subscribe IAM Lambda to GD SNS topic
    const gd_iam_subscription = new CfnSubscription(this, 'gd_iam_subscription', {
      topicArn: guardduty_topic.topicArn,
      protocol: 'lambda',
      endpoint: guardduty_iam_remediation_function.functionArn,
    });
    gd_iam_subscription.cfnOptions.condition = guardduty_condition

    // Subscribe EKS Lambda to GD SNS topic
    const gd_eks_subscription = new CfnSubscription(this, 'gd_eks_subscription', {
      topicArn: guardduty_topic.topicArn,
      protocol: 'lambda',
      endpoint: guardduty_eks_remediation_function.functionArn
    });
    gd_eks_subscription.cfnOptions.condition = guardduty_condition

    // guardduty_topic.addSubscription(new LambdaSubscription(guardduty_remediation_credexfil_function))

    // -------------------------------------------------------------------------------------------
    // -------------------------------------------------------------------------------------------
    // -------------------------------------------------------------------------------------------
    // CONDITIONAL INFRASTRUCTURE deployed if security_service_user_data user input is "guardduty"
    // -------------------------------------------------------------------------------------------
    // -------------------------------------------------------------------------------------------
    // -------------------------------------------------------------------------------------------

  }
}
