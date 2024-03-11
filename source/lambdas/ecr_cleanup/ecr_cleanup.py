import json
from json import dumps
import string
import time
import boto3
import logging
import urllib3
import os

logging.basicConfig(level = logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

http = urllib3.PoolManager()
lower = string.ascii_lowercase
num = string.digits
all = lower + num

ecr_client = boto3.client('ecr')

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

def ecr_cleanup(response):
    repositories = ecr_client.describe_repositories()    
    logger.info("Checking for ECR repositories...")
    for repository in repositories['repositories']:
        logger.info(repository["repositoryName"])
        if "vuln-images" in repository["repositoryName"]:
            delete = ecr_client.delete_repository(
                repositoryName = repository["repositoryName"],
                force = True
            )
            logger.info(delete)
            response = 'SUCCESS'
        else:
            logger.info("Not an image created by the Inspector demo.")
            response = 'FAILED'
    return response


def lambda_handler(event, context):
    logger.info(event)
    response = 'SUCCESS'
    if 'RequestType' in  event:
        if event['RequestType'] == 'Create':
            send_response(event, context, response)
        if event['RequestType'] == 'Update':
            send_response(event, context, response)
        if event['RequestType'] == 'Delete':
            ecr_cleanup(response)
            send_response(event, context, response)
    else:
        ecr_cleanup(response)