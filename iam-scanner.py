# This app accepts IAM access key and/or age as input parameter
# scan_iam_key method: Scan for IAM keys that match given input and returns user_name, last_used and age in json format
# scan_old_keys method: Returns all keys that are older than given age as input parameter (in json format)
# returns and prints data in json format


import sys
from libs.auth import (
    setup_session,
    setup_sts_session,
    setup_clients
)
from datetime import (
    date,
    datetime,
    timedelta
)
import getopt
import json
import logging

logging.basicConfig(level=logging.INFO)


##
# @brief Returns all keys that are older than given age as input parameter
# @param [in] client: (object) boto session object in dict format
# @param [in] age: (string) age threshold
# @return (content) json content
#
def scan_old_keys(client, age):
    try:
        threshold = datetime.now() - timedelta(days=age)
        res = client['iam'].list_users()
        content = {}
        for i in res['Users']:
            res_access_keys = client['iam'].list_access_keys(
                UserName=i['UserName']
            )
            if res_access_keys['AccessKeyMetadata']:
                if res_access_keys['AccessKeyMetadata'][0]['CreateDate'].date() <= threshold.date():
                    content.update({res_access_keys['AccessKeyMetadata'][0]['UserName']:
                        [{
                            "AccessKeyId": res_access_keys['AccessKeyMetadata'][0]['AccessKeyId'],
                            "CreateDate": res_access_keys['AccessKeyMetadata'][0]['CreateDate'].strftime(
                                "%m/%d/%Y, %H:%M:%S"),
                            "Status": res_access_keys['AccessKeyMetadata'][0]['Status']
                        }]})
    except Exception as e:
        logging.error("Could not scan IAM keys")
        sys.exit(2)
    return json.dumps(content)


##
# @brief Scan for IAM keys that match given input and returns user_name, last_used and age
# @param [in] client: (object) boto session object in dict format
# @param [in] iam_access_key: (string) access key
# @return (content) json content
#
def scan_iam_key(client, iam_access_key):
    try:
        res_last_used = client['iam'].get_access_key_last_used(
            AccessKeyId=iam_access_key
        )
        res_access_keys = client['iam'].list_access_keys(
            UserName=res_last_used['UserName']
        )

        age = date.today() - res_access_keys['AccessKeyMetadata'][0]['CreateDate'].date()
        last_used_date = res_last_used['AccessKeyLastUsed']['LastUsedDate']

        content = {
            'username': res_last_used['UserName'],
            'last_time_user': last_used_date.strftime("%m/%d/%Y, %H:%M:%S"),
            'age_of_key': age.days
        }
    except Exception as e:
        logging.error("Does not recognise IAM user. Please provide valid user IAM key")
        sys.exit(2)
    return json.dumps(content)


##
# @brief helper method
#
def usage():
    logging.error("Example use cases: \n"
                  "python iam-scanner.py -i AKIATXEBR43QPI3V4568 \n"
                  "python iam-scanner.py -i AKIATXEBR43QPI3V4568 -t 90 \n"
                  "python iam-scanner.py -t 90")


if __name__ == '__main__':
    account_id = None
    role_name = None
    iam_access_key = None
    region = "us-west-2"
    age = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ha:r:i:n:t:", ["account=", "role=", "iam=", "region=", "age="])
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
            elif opt in ("-i", "--iam"):
                iam_access_key = arg
            elif opt in ("-t", "--age"):
                age = arg
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
    client = setup_clients(session, region, client, 'iam')

    if iam_access_key:
        response = scan_iam_key(client, iam_access_key)
        print("Below is information related to access key {}".format(iam_access_key))
        print(response)

    if age:
        response = scan_old_keys(client, int(age))
        print("\n Below is information related to keys that are older than {}".format(age))
        print(response)
    if iam_access_key is None and age is None:
        logging.error("Pass either iam_access_key and/or age as input parameter")
        usage()
        sys.exit(2)
