import boto3

def update_sg_outbound_rule(*,
    security_group_id,
    acct_id: str,
    from_port,
    to_port,
    to_security_group,
    ip_protocol
):
    ec2 = boto3.client('ec2')

    rule = {
        'FromPort': from_port,
        'ToPort': to_port or from_port
    }

    if to_security_group:
        rule['UserIdGroupPairs'] = [{
            'GroupId': to_security_group,
            'UserId': acct_id
        }]

    ec2.authorize_security_group_egress(
        GroupId=security_group_id,
        IpPermissions=[ rule ]
    )

def lambda_handler(event, context):
    """ If event is "Create", add new s/g egress rule
        If event is "Delete", remove existing rule
    """
    security_group_id = event['security_group_id']
    acct_id = event['acct_id'] # is this accessible thru the context object?
    from_port = event['from_port']
    to_port = event['to_port'] or from_port
    radius_security_group_id = event['ResourceProperties']['radius_security_group_id']
    ip_protocol = 'udp'

    update_sg_outbound_rule(

    )
