import json
from source import update_sg_outbound_rule as module
import boto3
from botocore.stub import Stubber, ANY
from botocore.vendored import requests

def test_lambda_handler_create(monkeypatch, mocker):
    """ If lambda_handler called with 'Create'
        expect that it calls ec2.authorize_security_group_egress
        expect that it sends response 'SUCCESS'
    """
    ec2 = boto3.client('ec2')
    stubber = Stubber(ec2)

    monkeypatch.setattr(
        boto3,
        'client',
        lambda svc: ec2 if svc == 'ec2' else boto3.client(svc)
    )

    response_url = 'http://bucket.nowhere'
    request_type = 'Create'
    acct_id = '1234567890'
    ds_security_group_id = 'sg-123456abcdef'
    radius_security_group_id = 'sg-abcdef123456'
    ip_protocol = 'udp'

    stubber.add_response('authorize_security_group_egress',
        {}, # authorize_security_group_egress method returns None
        {
            'GroupId': ds_security_group_id,
            'IpPermissions': [{
                'FromPort': ANY,
                'ToPort': ANY,
                'IpProtocol': ip_protocol,
                'UserIdGroupPairs': [{
                    'GroupId': radius_security_group_id,
                    'UserId': acct_id
                }]
            }]
        })

    stubber.activate()

    monkeypatch.setattr(requests, 'put', lambda url, *, data: url)
    requests_spy = mocker.spy(requests, 'put')

    # Action!
    module.lambda_handler({
        'RequestType': request_type,
        'ResponseURL': response_url, # This will be a presigned URL from Cfn
        'ResourceProperties': {
            'acct_id': acct_id,
            'ds_security_group_id': ds_security_group_id,
            'radius_security_group_id': radius_security_group_id
        }
    }, {})

    stubber.assert_no_pending_responses()

    requests_spy.assert_called_once_with(response_url, data=json.dumps({ 'Status': 'SUCCESS' }))

def test_lambda_handler_delete(monkeypatch, mocker):
    """ If lambda_handler called with 'Create'
        expect that it calls ec2.authorize_security_group_egress
        expect that it sends response 'SUCCESS'
    """
    ec2 = boto3.client('ec2')
    stubber = Stubber(ec2)

    monkeypatch.setattr(
        boto3,
        'client',
        lambda svc: ec2 if svc == 'ec2' else boto3.client(svc)
    )

    response_url = 'http://bucket.nowhere'
    request_type = 'Delete'
    acct_id = '1234567890'
    ds_security_group_id = 'sg-123456abcdef'
    radius_security_group_id = 'sg-abcdef123456'
    ip_protocol = 'udp'

    stubber.add_response('revoke_security_group_egress',
        {}, # authorize_security_group_egress method returns None
        {
            'GroupId': ds_security_group_id,
            'IpPermissions': [{
                'FromPort': ANY,
                'ToPort': ANY,
                'IpProtocol': ip_protocol,
                'UserIdGroupPairs': [{
                    'GroupId': radius_security_group_id,
                    'UserId': acct_id
                }]
            }]
        })

    stubber.activate()

    monkeypatch.setattr(requests, 'put', lambda url, *, data: url)
    requests_spy = mocker.spy(requests, 'put')

    # Action!
    module.lambda_handler({
        'RequestType': request_type,
        'ResponseURL': response_url, # This will be a presigned URL from Cfn
        'ResourceProperties': {
            'acct_id': acct_id,
            'ds_security_group_id': ds_security_group_id,
            'radius_security_group_id': radius_security_group_id
        }
    }, {})

    stubber.assert_no_pending_responses()

    requests_spy.assert_called_once_with(response_url, data=json.dumps({ 'Status': 'SUCCESS' }))
