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

cfn = boto3.client('cloudformation')
elb = boto3.client('elb')

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

def eks_load_balancer_cleanup(response):
    try:
        eks_lb=elb.describe_load_balancers()
        for lb in eks_lb["LoadBalancerDescriptions"]:
            tags = elb.describe_tags(
                LoadBalancerNames=[
                    lb["LoadBalancerName"]
                ]
            )['TagDescriptions'][0]['Tags']
            for tag in tags:
                print(tag)
                if tag["Key"] == 'kubernetes.io/service-name' and tag["Value"] == 'kubernetes-dashboard/kubernetes-dashboard-lb':
                    elb.delete_load_balancer(
                        LoadBalancerName=lb["LoadBalancerName"]
                    )
    except Exception as e:
        logger.info(f"Deleting GuardDuty demo EKS load balancers failed due to {e}.")
        response='FAILED'
    return response    

def eks_node_svcacct_cfn_cleanup(response):
    eks_node_stack=""
    eks_svcacct_stack=""
    eks_cluster_stack=""
    try:
        cfn_stacks = cfn.describe_stacks()
        for stack in cfn_stacks["Stacks"]:
            if stack['Tags']:
               for tags in stack['Tags']:
                if tags["Key"] == 'alpha.eksctl.io/nodegroup-type' and tags["Value"] == 'managed':
                    eks_node_stack=stack['StackName']
                    cfn.delete_stack(
                        StackName=eks_node_stack
                    )
                    logger.info(f"Successfully deleted GuardDuty demo EKS %s CloudFormation template.", eks_node_stack)
                elif tags["Key"] == 'alpha.eksctl.io/iamserviceaccount-name' and tags["Value"] == 'kube-system/aws-node':
                    eks_svcacct_stack=stack['StackName']
                    cfn.delete_stack(
                        StackName=eks_svcacct_stack
                    )
                    logger.info(f"Successfully deleted GuardDuty demo EKS %s CloudFormation template.", eks_svcacct_stack)
                elif tags["Key"] == 'alpha.eksctl.io/cluster-name' and tags["Value"] == 'GuardDuty-Finding-Demo':
                    eks_cluster_stack=stack['StackName']
                    cfn.delete_stack(
                        StackName=eks_cluster_stack
                    )
                    logger.info(f"Successfully deleted GuardDuty demo EKS %s CloudFormation template.", eks_cluster_stack)
    except Exception as e:
        logger.info(f"Deleting GuardDuty demo EKS CloudFormation templates failed due to {e}.")
        response='FAILED'
    return eks_node_stack,eks_cluster_stack,response

def check_eks_cluster_stack_status(response,eks_node_stack,eks_cluster_stack):
    try:
        stack_status = cfn.describe_stacks(
            StackName=eks_node_stack
        )['Stacks'][0]['StackStatus']
        if stack_status == 'DELETE_COMPLETE':
            eks_cluster_cfn_cleanup(eks_cluster_stack,response)
            return True
        else:
            return False
    except Exception as e:
        logger.info(f"Getting status of GuardDuty demo EKS Node CloudFormation template %s failed due to {e}.",eks_node_stack)
        response='FAILED'
    return True,response

def eks_cluster_cfn_cleanup(eks_cluster_stack,response):
    try:
        cfn.delete_stack(
            StackName=eks_cluster_stack
        )
    except Exception as e:
        logger.info(f"Deleting GuardDuty demo EKS Cluster CloudFormation template %s failed due to {e}.",eks_cluster_stack)
        response='FAILED'
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
            response = eks_load_balancer_cleanup(response)
            eks_node_stack,eks_cluster_stack,response = eks_node_svcacct_cfn_cleanup(response)
            if eks_node_stack == "":
                eks_cluster_status=True
            else:
                eks_cluster_status = False
            while not eks_cluster_status:
                eks_cluster_status = check_eks_cluster_stack_status(response,eks_node_stack,eks_cluster_stack)
                time.sleep(10)
            send_response(event, context, response)