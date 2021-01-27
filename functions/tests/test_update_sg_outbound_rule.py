import json
from source import update_sg_udp_egress_rule as module
import boto3
from botocore.stub import Stubber, ANY
from botocore.vendored import requests
from botocore.exceptions import ClientError
import pytest

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

def test_lambda_handler_update(monkeypatch, mocker):
    """ If lambda_handler called with 'Update'
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
    request_type = 'Update'
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

def test_lambda_handler_duplicate_rule(monkeypatch, mocker):
    """ If lambda_handler called with 'Update'
        and ClientError "Duplicate" raised
        expect that it does not crash
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
    request_type = 'Update'
    acct_id = '1234567890'
    ds_security_group_id = 'sg-123456abcdef'
    radius_security_group_id = 'sg-abcdef123456'
    ip_protocol = 'udp'
    service_error_code = 'InvalidPermission.Duplicate'
    service_message = f'the specified rule "peer: {ds_security_group_id}, from port: 1812, to port: 1812, ALLOW" already exists'

    stubber.add_client_error('authorize_security_group_egress',
        service_error_code=service_error_code,
        service_message=service_message,
        expected_params={
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
    """ If lambda_handler called with 'Delete'
        expect that it calls ec2.revoke_security_group_egress
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
        # revoke_security_group_egress docs say it returns True on success
        # but in fact it seems to return only ResponseMetadata
        {},
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

def test_lambda_handler_delete_not_found(monkeypatch, mocker):
    """ If lambda_handler called with 'Delete'
        and rule is not found
        expect that it does not crash
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

    stubber.add_client_error('revoke_security_group_egress',
        service_error_code='InvalidPermission.NotFound',
        service_message='The specified rule does not exist in this security group.',
        expected_params={
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

    requests_spy.assert_called_once_with(response_url, data=json.dumps({ 'Status': 'SUCCESS' }))

def test_lambda_handler_create_client_error_other(monkeypatch, mocker):
    """ If lambda_handler called with 'Create'
        and it raises for any reason other than ClientError: InvalidPermission.NotFound
        expect that it sends response 'FAILED' with exception message as Reason
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

    op_name = 'authorize_security_group_egress'
    java_op_name = ''.join(s.title() for s in op_name.split('_'))
    error_code = 'Whatever.Whatever'
    error_message = 'Something else went wrong.'

    stubber.add_client_error(op_name,
        service_error_code=error_code,
        service_message=error_message,
        expected_params={
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

    requests_spy.assert_called_once_with(response_url, data=json.dumps({
        'Status': 'FAILED',
        'Reason': ClientError.MSG_TEMPLATE.format_map({
            'error_code': error_code,
            'operation_name': java_op_name,
            'retry_info': '',
            'error_message': error_message
        })
    }))

def test_lambda_handler_delete_client_error_other(monkeypatch, mocker):
    """ If lambda_handler called with 'Delete'
        and it raises anything other than InvalidPermission.NotFound
        expect that it sends response 'FAILED' with exception message as Reason
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

    op_name = 'revoke_security_group_egress'
    error_code = 'Whatever.Whatever'
    error_message = 'Something unexpected happened.'

    stubber.add_client_error(op_name,
        service_error_code=error_code,
        service_message=error_message,
        expected_params={
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

    requests_spy.assert_called_once_with(response_url, data=json.dumps({
        'Status': 'FAILED',
        'Reason': ClientError.MSG_TEMPLATE.format_map({
            'error_code': error_code,
            'operation_name': ''.join(s.title() for s in op_name.split('_')),
            'retry_info': '',
            'error_message': error_message
        })
    }))

def test_lambda_handler_unknown_request_type(monkeypatch, mocker):
    """ Expect lambda_handler to send Status: "FAILED" for uknown request type
    """
    response_url = 'http://bucket.nowhere'
    request_type = 'Unknown'
    acct_id = '1234567890'
    ds_security_group_id = 'sg-123456abcdef'
    radius_security_group_id = 'sg-abcdef123456'

    monkeypatch.setattr(requests, 'put', lambda url, *, data: url)
    requests_spy = mocker.spy(requests, 'put')

    module.lambda_handler({
        'RequestType': request_type,
        'ResponseURL': response_url,
        'ResourceProperties': {
            'acct_id': acct_id,
            'ds_security_group_id': ds_security_group_id,
            'radius_security_group_id': radius_security_group_id
        }
    }, {})

    requests_spy.assert_called_once_with(
        response_url,
        data=json.dumps({
            'Status': 'FAILED',
            'Reason': f'Unknown RequestType {request_type}. Valid RequestTypes are "Create", "Update", "Delete".'
        }
    ))
