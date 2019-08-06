import sys
from libs.auth import (
    setup_session,
    setup_sts_session,
    setup_clients
)
import getopt
import logging

logging.basicConfig(level=logging.INFO)


def usage():
    logging.error("Example use cases: \n"
                  "python security-group-scanner.py -i 34.218.234.32/27 \n"
                  "python security-group-scanner.py -s sg-04e33457ab27d2396")


if __name__ == '__main__':
    account_id = None
    role_name = None
    security_group = None
    region = "us-west-2"
    ip = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ha:r:s:i:n", ["account=", "role=", "securitygroup=", "ip=", "region="])
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                usage()
                sys.exit(2)
            elif opt in ("-a", "--account"):
                account_id = arg
            elif opt in ("-r", "--role"):
                role_name = arg
            elif opt in ("-n", "--region"):
                region = arg
            elif opt in ("-s", "--securitygroup"):
                security_group = arg
            elif opt in ("-i", "--ip"):
                ip = arg
            else:
                logging.info("Option unknown, please use -h option for help")
    except getopt.GetoptError as e:
        logging.error("Incorrect parameters passed {}".format(e))
        usage()

    # setup session, clients
    if account_id is not None and role_name is not None:
        session = setup_sts_session(account_id, role_name)
    else:
        session = setup_session()
    global client
    client = {}
    client = setup_clients(session, region, client, 'ec2')

    # setup filters
    Filters = []
    if ip:
        Filters.append({'Name': 'ip-permission.cidr','Values': [ip]})
    elif security_group:
        Filters.append({'Name': 'ip-permission.group-id', 'Values': [security_group]})
    else:
        logging.error("Pass either security group id or ipv4 address as input parameter")
        usage()
        sys.exit(2)

    # scan security groups
    paginator = client['ec2'].get_paginator('describe_security_groups')
    response = paginator.paginate(Filters=Filters)
    for page in response:
        for sg in page['SecurityGroups']:
            logging.info("Security Group {} matches either CIDR or another SG as source".format(sg['GroupName']))


# assumption resgion = us-west-2, otherwise pass region
# ipv4