from __future__ import print_function
from botocore.exceptions import ClientError
import json
import datetime
import boto3
import os

iam = boto3.client('iam')
ec2 = boto3.client('ec2')
sns = boto3.client('sns')

def lambda_handler(event, context):
    # Log out event
    print("log -- Event: %s " % json.dumps(event))

    # Create generic function response
    response = "Error auto-remediating the finding."

    try:
        # Set Role Variable
        role = event['detail']['resource']['accessKeyDetails']['userName']

        # Current Time
        time = datetime.datetime.utcnow().isoformat()

        # Set Revoke Policy
        policy = """
        {
            "Version": "2012-10-17",
            "Statement": {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {"DateLessThan": {"aws:TokenIssueTime": "%s"}}
            }
        }
        """ % time

        # Add policy to Role to Revoke all Current Sessions
        iam.put_role_policy(
        RoleName=role,
        PolicyName='RevokeOldSessions',
        PolicyDocument=policy.replace('\n', '').replace(' ', '')
        )

        # Send Response Email
        response = "GuardDuty Remediation | ID:%s: GuardDuty discovered EC2 IAM credentials (Role: %s) being used outside of the EC2 service.  All sessions have been revoked.  Please follow up with any additional remediation actions." % (event['detail']['id'], role)
        sns.publish(
        TopicArn=os.environ['TOPIC_ARN'],
        Message=response
        )
    except ClientError as e:
        print(e)

    print("log -- Response: %s " % response)
    return response