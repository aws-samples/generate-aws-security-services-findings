import json
from json import dumps
import boto3
from botocore.exceptions import ClientError
from time import sleep
import urllib3
import logging
import string
import os
import sys

logging.basicConfig(level = logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

http = urllib3.PoolManager()
lower = string.ascii_lowercase
num = string.digits
all = lower + num

VPC_ID = os.getenv("VPC_ID")
MAX_RETRIES = 5
client = boto3.client('ec2')

def eni_cleanup(response):
    try:
        # Get all network intefaces for given vpc which are attached to a lambda function
        interfaces = client.describe_network_interfaces(
            Filters=[
                {
                    'Name': 'description',
                    'Values': ['AWS Lambda VPC ENI*']
                },
                {
                    'Name': 'vpc-id',
                    'Values': [VPC_ID]
                },
            ],
        )
        failed_detach = list()
        failed_delete = list()

        # Detach the above found network interfaces
        for interface in interfaces['NetworkInterfaces']:
            detach_interface(failed_detach, interface)

        # Try detach a second time and delete each simultaneously
        for interface in interfaces['NetworkInterfaces']:
            detach_and_delete_interface(failed_detach, failed_delete, interface)

        if not failed_detach or not failed_delete:
            result = {'result': 'Network interfaces detached and deleted successfully'}
            response = 'SUCCESS'
        else:
            result = {'result': 'Network interfaces couldn\'t be deleted completely'}
            response = 'FAILED'
    except Exception:
        print("Unexpected error:", sys.exc_info())
        result = {'result': 'Some error with the process of detaching and deleting the network interfaces'}
        response = 'FAILED'
    return response

def detach_interface(failed_detach, interface):
    try:

        if interface['Status'] == 'in-use':
            detach_response = client.detach_network_interface(
                AttachmentId=interface['Attachment']['AttachmentId'],
                Force=True
            )
            # Sleep for 1 sec after every detachment
            sleep(1)

            print(f"Detach response for {interface['NetworkInterfaceId']}- {detach_response}")

            if 'HTTPStatusCode' not in detach_response['ResponseMetadata'] or \
                    detach_response['ResponseMetadata']['HTTPStatusCode'] != 200:
                failed_detach.append(detach_response)
    except ClientError as e:
        print(f"Exception details - {sys.exc_info()}")


def detach_and_delete_interface(failed_detach, failed_delete, interface, retries=0):
    detach_interface(failed_detach, interface)
    sleep(retries + 1)
    try:
        delete_response = client.delete_network_interface(
            NetworkInterfaceId=interface['NetworkInterfaceId'])

        print(f"Delete response for {interface['NetworkInterfaceId']}- {delete_response}")
        if 'HTTPStatusCode' not in delete_response['ResponseMetadata'] or \
                delete_response['ResponseMetadata']['HTTPStatusCode'] != 200:
            failed_delete.append(delete_response)
    except ClientError as e:
        print(f"Exception while deleting - {str(e)}")
        print()
        if retries <= MAX_RETRIES:
            sleep(10)
            if e.response['Error']['Code'] == 'InvalidNetworkInterface.InUse' or \
                    e.response['Error']['Code'] == 'InvalidParameterValue':
                retries = retries + 1
                print(f"Retry {retries} : Interface in use, deletion failed, retrying to detach and delete")
                detach_and_delete_interface(failed_detach, failed_delete, interface, retries)
            else:
                raise RuntimeError("Code not found in error")
        else:
            raise RuntimeError("Max Number of retries exhausted to remove the interface")

def send_response(event, context, response):
    '''Send a response to CloudFormation to handle the custom resource lifecycle.'''
    responseBody = { 
        'Status': response,
        'Reason': 'See details in CloudWatch Log Stream: ' + context.log_stream_name,
        'PhysicalResourceId': context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
    }
    print('RESPONSE BODY: \n' + dumps(responseBody))

    responseUrl = event['ResponseURL']
    json_responseBody = json.dumps(responseBody)
    headers = {
          'content-type' : '',
          'content-length' : str(len(json_responseBody))
    }
    try:
        response = http.request('PUT', responseUrl, headers=headers, body=json_responseBody)
        #response = response.send(responseUrl, data=json_responseBody, headers=headers)
        print ("Status code: " +response.reason)
    except Exception as e:
        print ("send(..) failed executing requests.put(..): " + str(e))
    return True

def lambda_handler(event, context):
    logger.info(event)
    response = 'SUCCESS'
    if event['RequestType'] == 'Create':
        send_response(event, context, response)
    if event['RequestType'] == 'Update':
        send_response(event, context, response)
    if event['RequestType'] == 'Delete':
        eni_cleanup(response)
        send_response(event, context, response)