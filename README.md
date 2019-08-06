# security-scanner
Search and return security groups that match input as source; also, search IAM for user activity

**Prerequisites**
-   python 3+
-   boto3
-   aws cli configured


**Assumptions** 
-   If region is not specified, by default tool will use us-west-2
-   security-group-scanner works only works for IPV4 addresses


**How to run**

`python security-group-scanner.py -i 34.218.234.32/27
python security-group-scanner.py -s sg-04e33457ab27d2396
python iam-scanner.py -i AKIATXEBR43QPI3V4568
python iam-scanner.py -i AKIATXEBR43QPI3V4568 -t 90
python iam-scanner.py -t 90`