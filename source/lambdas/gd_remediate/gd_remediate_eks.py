import time
import boto3
import logging
import os

logging.basicConfig(level = logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

cfn_client = boto3.client('cloudformation')
elb_client = boto3.client('elb')
sns = boto3.client('sns')

def eks_load_balancer_cleanup():
    try:
        eks_lb=elb_client.describe_load_balancers()
        for lb in eks_lb["LoadBalancerDescriptions"]:
            tags = elb_client.describe_tags(
                LoadBalancerNames=[
                    lb["LoadBalancerName"]
                ]
            )['TagDescriptions'][0]['Tags']
            for tag in tags:
                print(tag)
                if tag["Key"] == 'kubernetes.io/service-name' and tag["Value"] == 'kubernetes-dashboard/kubernetes-dashboard-lb':
                    elb_client.delete_load_balancer(
                        LoadBalancerName=lb["LoadBalancerName"]
                    )
    except Exception as e:
        logger.info(f"Deleting GuardDuty demo EKS load balancers failed due to {e}.")


def eks_node_svcacct_cfn_cleanup():
    eks_node_stack=""
    eks_svcacct_stack=""
    eks_cluster_stack=""
    try:
        cfn_stacks = cfn_client.describe_stacks()
        for stack in cfn_stacks["Stacks"]:
            if stack['Tags']:
               for tags in stack['Tags']:
                if tags["Key"] == 'alpha.eksctl.io/nodegroup-type' and tags["Value"] == 'managed':
                    eks_node_stack=stack['StackName']
                    cfn_client.delete_stack(
                        StackName=eks_node_stack
                    )
                    logger.info(f"Successfully deleted GuardDuty demo EKS node group CloudFormation template.")
                elif tags["Key"] == 'alpha.eksctl.io/iamserviceaccount-name' and tags["Value"] == 'kube-system/aws-node':
                    eks_svcacct_stack=stack['StackName']
                    cfn_client.delete_stack(
                        StackName=eks_svcacct_stack
                    )
                    logger.info(f"Successfully deleted GuardDuty demo EKS service account CloudFormation template.")
                elif tags["Key"] == 'alpha.eksctl.io/cluster-name' and tags["Value"] == 'GuardDuty-Finding-Demo':
                    eks_cluster_stack=stack['StackName']
                    cfn_client.delete_stack(
                        StackName=eks_cluster_stack
                    )
                    logger.info(f"Successfully deleted GuardDuty demo EKS cluster account CloudFormation template.")
    except Exception as e:
        logger.info(f"Deleting GuardDuty demo EKS CloudFormation templates failed due to {e}.")
    return eks_node_stack,eks_cluster_stack

def check_eks_cluster_stack_status(eks_node_stack,eks_cluster_stack):
    try:
        stack_status = cfn_client.describe_stacks(
            StackName=eks_node_stack
        )['Stacks'][0]['StackStatus']
        if stack_status == 'DELETE_COMPLETE':
            response = eks_cluster_cfn_cleanup(eks_cluster_stack)
            return response,True
        else:
            return False
    except Exception as e:
        logger.info(f"Getting status of GuardDuty demo EKS Node CloudFormation template %s failed due to {e}.",eks_node_stack)
    return True

def eks_cluster_cfn_cleanup(eks_cluster_stack):
    try:
        cfn_client.delete_stack(
            StackName=eks_cluster_stack
        )
        response = "GuardDuty Remediation | ID:%s: GuardDuty discovered an EKS Cluster deployed using CloudFormation is compromised.  All associated CloudFormation templates associated to the EKS cluster have been deleted.  Please follow up with any additional remediation actions."
    except Exception as e:
        logger.info(f"Deleting GuardDuty demo EKS Cluster CloudFormation template %s failed due to {e}.",eks_cluster_stack)
        response = "Error auto-remediating the GuardDuty EKS finding."
    return response
    
def lambda_handler(event, context):
    logger.info(event)
    response = "Error auto-remediating the GuardDuty EKS finding.."
    eks_load_balancer_cleanup()
    eks_node_stack,eks_cluster_stack = eks_node_svcacct_cfn_cleanup()
    eks_cluster_status = False
    while not eks_cluster_status:
        eks_cluster_status = check_eks_cluster_stack_status(eks_node_stack,eks_cluster_stack)
        time.sleep(10)
    # Send SNS Response Email
    sns.publish(
        TopicArn=os.environ['TOPIC_ARN'],
        Message=response
    )