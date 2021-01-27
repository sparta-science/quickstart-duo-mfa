import json
import boto3
from botocore.vendored import requests

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

    if event['RequestType'] == 'Create':
        ec2.authorize_security_group_egress(
            GroupId=security_group_id,
            IpPermissions=[ rule ]
        )

        response_body['Status'] = SUCCESS

    elif event['RequestType'] == 'Delete':
        ec2.revoke_security_group_egress(
            GroupId=security_group_id,
            IpPermissions= [ rule ]
        )

        response_body['Status'] = SUCCESS

    else:
        # Not sure what to do in the case of 'Update'
        # How can I find the previous rule to delete & add a new version of
        # if the parameters of rule has changed?
        # AFAIK, there are no IDs for rules.
        # Rules are matched on their exact parameters.
        response_body['Status'] = FAILED
        response_body['Reason'] = 'I don\'t know how to handle anything except "Create" and "Delete"'

    requests.put(event['ResponseURL'], data=json.dumps(response_body))
