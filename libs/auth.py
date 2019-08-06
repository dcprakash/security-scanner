import sys
import boto3
import logging

logging.basicConfig(level=logging.INFO)


def setup_session():
    session = boto3.session.Session()
    return session


def setup_sts_session(account_id=None, role_name=None):
    creds = {}
    if account_id and role_name:
        role_arn = "".join(['arn:aws:iam::', account_id, ':role/', role_name])
        logging.info("Using Role {}".format(role_arn))
        sts = boto3.client('sts')
        stsresponse = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=role_name
        )
        creds['aws_access_key_id'] = \
            stsresponse['Credentials']['AccessKeyId']
        creds['aws_secret_access_key'] = \
            stsresponse['Credentials']['SecretAccessKey']
        creds['aws_session_token'] = \
            stsresponse['Credentials']['SessionToken']
    else:
        logging.error("No account_id or role_name passed to setup_session method")
        sys.exit(2)
    session = boto3.session.Session(**creds)
    return session


def setup_clients(session, region, client, *args):
    for arg in args:
        client[arg] = session.client(arg, region_name=region)
    return client
