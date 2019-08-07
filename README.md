# security-scanner
This app has two modules: security-group-scanner.py and iam-scanner.py.
security-group-scanner accepts either ipv4 address or security group id as input parameter; scans aws environment to identify security groups that contains input parameter as source cidr or sg.
iam-scanner accepts iam access key and/or age (number of days) as input parameter; scans aws environment for aws iam access key and returns its contents. If age parameters has passed as input, this will also return all iam keys that are older than given age.


**Prerequisites**
-   python 3+
-   boto3
-   aws cli configured


**Assumptions** 
-   If region is not specified, by default tool will use us-west-2
-   security-group-scanner works only works for IPV4 addresses


**How to run**

`python security-group-scanner.py -i 34.218.234.32/27`

`python security-group-scanner.py -s sg-04e33457ab27d2396`

`python iam-scanner.py -i AKIATXEBR43QPI3V4568`

`python iam-scanner.py -i AKIATXEBR43QPI3V4568 -t 90`

`python iam-scanner.py -t 90`


**secure session**

If -a <account_id> -r <role_name> is passed as input parameter
As long as user has assume permissions to that role, this app will use secure sts session.
