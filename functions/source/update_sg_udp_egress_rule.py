import json
import boto3
from botocore.vendored import requests
from botocore.exceptions import ClientError

def construct_rule(*,
    acct_id: str,
    target_security_group_id
) -> dict:
    return {
        'FromPort': 1812,
        'ToPort': 1812,
        'UserIdGroupPairs': [{
            'GroupId': target_security_group_id,
            'UserId': acct_id
        }],
        'IpProtocol': 'udp'
    }

def lambda_handler(event, context) -> None:
    """ If event is "Create", add new s/g egress rule
        If event is "Delete", remove existing rule
    """
    security_group_id = event['ResourceProperties']['ds_security_group_id']
    acct_id = event['ResourceProperties']['acct_id']
    radius_security_group_id = event['ResourceProperties']['radius_security_group_id']
    rule = construct_rule(
        acct_id=acct_id,
        target_security_group_id=radius_security_group_id
    )

    ec2 = boto3.client('ec2')

    SUCCESS = 'SUCCESS'
    FAILED = 'FAILED'

    response_body = { 'Status': FAILED }
    response_body['Reason'] = ''

    if event['RequestType'] == 'Create' or event['RequestType'] == 'Update':
        try:
            ec2.authorize_security_group_egress(
                GroupId=security_group_id,
                IpPermissions=[ rule ]
            )
        except ClientError as e:
            # If rule-to-delete not found, that's ok. Move on
            # for anything else, send exceptions tring as response
            if e.response['Error']['Code'] != 'InvalidPermission.Duplicate':
                response_body['Reason'] = e.response['Error']['Message']

    elif event['RequestType'] == 'Delete':
        try:
            ec2.revoke_security_group_egress(
                GroupId=security_group_id,
                IpPermissions= [ rule ]
            )
        except ClientError as e:
            # If rule-to-delete not found, that's ok. Move on
            # for anything else, send exceptions tring as response
            if e.response['Error']['Code'] != 'InvalidPermission.NotFound':
                response_body['Reason'] = e.response['Error']['Message']

    else:
        response_body['Reason'] = f'Unknown RequestType {event["RequestType"]}. Valid RequestTypes are "Create", "Update", "Delete".'


    if response_body['Reason'] == '':
        response_body['Status'] = SUCCESS
        response_body.pop('Reason')

    requests.put(event['ResponseURL'], data=json.dumps(response_body))
