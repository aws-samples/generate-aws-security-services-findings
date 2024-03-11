import json
from json import dumps
import string
import time
import boto3
import logging
import urllib3
import os
import random

logging.basicConfig(level = logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

http = urllib3.PoolManager()
lower = string.ascii_lowercase
num = string.digits
all = lower + num

s3 = boto3.client('s3')
gd = boto3.client('guardduty')

BUCKET_NAME=os.environ['BUCKET_NAME']
THREAT_LIST=os.environ['THREAT_LIST']
BUCKET_URL='https://s3.amazonaws.com/'+BUCKET_NAME+'/threatlist.txt'

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

def getRandom(stringLength=10):
    #Generate a random string of alphanumeric characters
    lettersAndDigits = string.ascii_lowercase + string.digits
    return ''.join((random.choice(lettersAndDigits) for i in range(stringLength)))

def lambda_handler(event, context):
    logger.info(event)
    response = 'SUCCESS'
    if event['RequestType'] == 'Create':
        tmpFn = '/tmp/'+getRandom(20)
        f = open(tmpFn, 'w')
        f.write(THREAT_LIST)
        f.close
        with open(tmpFn, 'rb') as f:
            try:
                s3.upload_fileobj(f, BUCKET_NAME, 'threatlist.txt')
            except Exception as e:
                logger.info(f"Updating S3 Object threat list failed due to {e}")
                response = 'FAILED'
        try:
            id = gd.list_detectors()
            gd.create_threat_intel_set(
            DetectorId=id['DetectorIds'][0],
            Name='GuardDutyDemo_IpAddrList_' + getRandom(5),
            Location=BUCKET_URL,
            Format='TXT',
            Activate=True,
        )
        except Exception as e:
            logger.info(f"Adding GuardDuty Threat List failed due to {e}")
            response = 'FAILED'
        send_response(event, context, response)
    if event['RequestType'] == 'Update':
        tmpFn = '/tmp/'+getRandom(20)
        f = open(tmpFn, 'w')
        f.write(THREAT_LIST)
        f.close
        with open(tmpFn, 'rb') as f:
            try:
                s3.upload_fileobj(f, BUCKET_NAME, 'threatlist.txt')
            except Exception as e:
                logger.info(f"Updating S3 Object threat list failed due to {e}")
                response = 'FAILED'
        send_response(event, context, response)
    if event['RequestType'] == 'Delete':
        send_response(event, context, response)