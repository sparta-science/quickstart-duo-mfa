from source import update_sg_outbound_rule as module
import boto3
from botocore.stub import Stubber

def test_lambda_handler_create(monkeypatch):
    """ If lambda_handler called with 'Create'
        expect that it calls ec2.authorize_security_group_egress
        expect that it sends response 'SUCCESS'
    """
    ec2 = boto3.client('ec2')
    stubber = Stubber(ec2)

    monkeypatch.setattr(
        boto3,
        'client',
        lambda svc: stubber if svc == 'ec2' else boto3.client(svc)
    )

    acct_id = '1234567890'
    radius_security_group_id = 'sg-abcdef123456'

    ec2.add_response('authorize_security_group_egress',
        None,
        {
            'FromPort': 111,
            'ToPort': 111,
            'IpProtocol': 'udp',
            'UserIdGroupPairs': [{
                'GroupId': radius_security_group_id,
                'UserId': acct_id
            }]
        })

    module.lambda_handler({
        'RequestType': 'Create',
        'ResourceProperties': {
            'acct_id': acct_id,
            'radius_security_group_id': radius_security_group_id
        }
    }, {})
