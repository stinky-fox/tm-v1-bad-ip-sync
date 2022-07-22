# About
Sync malicious IP addresses to AbuseIPDB service. Initially designed for serverless (like AWS Lambda) but can be used on any Virtual Machine with python.

# Requirements

- Cloud One Workload Security reporting IPS detections to the Vision One
- Vision One account
- Abuseip DB account
- Python + dependencies:
  - requests
  - json
  - sys
  - os
  - ipaddress
  - datetime
  - dateutil

# Environment Variables
Following Environment variables must configured
- **TMV1QUERYPERIODTYPE** = acceptable values: days, weeks or months
- **TMV1QUERYPERIODVALUE** = numerical value that comes together with previous, i.e. 1 or 2
The variables will be combined to the single dict **{"months":1}**. Don't overquery, if you run your script once a day - days:1 is a decent scope. If both values not set - the default **days** and **1** will be used.
- **ABUSEIPDB_APIKEY** = your https://www.abuseipdb.com/account/api API key
- **TMV1APIKEY** = Trend Micro Vision One API Key (https://automation.trendmicro.com/xdr/Guides/First-Steps-Toward-Using-the-APIs#Obtain-the-Authentication-Token-of-an--------Account)

# To run the script on any VM server

Uncomment the last line **lambda_handler('a','b')**
