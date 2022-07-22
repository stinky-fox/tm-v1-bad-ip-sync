#!/bin/python

'''
Scripter: Stinky Fox
Version: 0.1
Purpose:
    Report malicious IP address to AbuseIP DB.
    Intel gathered from Trend Micro Vision One API.
    Events are being reported by Trend Micro C1WS/DS IPS module to Vision One.
    Additionally script can pull information IPS rule information from C1WS.
    Script built to run in AWS Lambda.

'''

#################### CODE BELOW THIS LINE #########################

'''
Import necessary libraries
'''
import requests
import json
import sys
import os
import ipaddress
from datetime import datetime
from dateutil.relativedelta import relativedelta


'''
Script starter function
'''

def lambda_handler(event, context):
    
    v1Data = tmv1Caller()
    preparedData = ipExtractor(v1Data)
    pushToAbuseipDb = abusedbipCaller(preparedData)
    print(pushToAbuseipDb)
    
'''
Call Trend Micro Vision One API. API key must not be empty. If API key is empty - exit().
'''

def tmv1Caller():
    
    # Trend Micro Vision One API configuration variables. 
    tmv1Config = {}
    acceptablePeriodTypes = ['days', 'hours', 'weeks', 'months']

    tmv1Config['tmv1ApiEndpoint'] = 'https://api.xdr.trendmicro.com/v3.0/search/detections'
    
    ## Check if TM V1 API Token is defined. If not, then terminate the run
    try:
        tmv1Config['tmv1ApiToken'] = os.environ['TMV1APIKEY']
    except KeyError:
        print('No V1 API Key defined')
        sys.exit(1)
    tmv1Config['queryPeriod'] = {}
    
     ## Check if TMV1QUERYPERIODTYPE variable is in the acceptable type. If non - set the default value that is equal to one day
    if os.environ['TMV1QUERYPERIODTYPE'] in acceptablePeriodTypes:
        try:
            tmv1Config['queryPeriod'][os.environ['TMV1QUERYPERIODTYPE']] = int(os.environ['TMV1QUERYPERIODVALUE'])
        except KeyError:
            tmv1Config['queryPeriod'] = {"days":1}
    else:
        print('Incorrect value ' + os.environ['TMV1QUERYPERIODTYPE'])
        tmv1Config['queryPeriod'] = {"days":1}

    ## Call a function to convert date to Zulu time accepted by Vision One API.
    dtCalculated = dateCalculator(tmv1Config['queryPeriod'])
    
    ## Glueing API headers and query parameters together
    tmv1Config['apiQueryParams'] = {'startDateTime': dtCalculated}
    tmv1Config['apiheaders'] = {'Authorization': 'Bearer ' + tmv1Config['tmv1ApiToken'], 'TMV1-Query': 'eventName:DEEP_PACKET_INSPECTION_EVENT'}

    # Try to run TM V1 API call. If error - terminate the run
    try:
        apiCall = requests.get(tmv1Config['tmv1ApiEndpoint'], params=tmv1Config['apiQueryParams'], headers= tmv1Config['apiheaders'])
    except Exception as errText:
        print("Error communicating with API: " + str(errText))
        sys.exit(1)
    
    # Terminate the script if the code returned is not equal to 200
    if apiCall.status_code != 200:
        print("API returned code: " + str(apiCall.status_code) + " with message: " + str(apiCall.content))
        sys.exit(1)
    else:
        apiOut = json.loads(apiCall.content)
    
    return(apiOut)

'''
Check current date and return date/time in UTC to query Vision One API
'''

def dateCalculator(period):
    dtNow = datetime.now()
    dtFormat = "%Y-%m-%d"+"T"+"%H:%M:%S"+"Z"
    dtQuery = dtNow - relativedelta(**period)
    return(dtQuery.strftime(dtFormat))

'''
Extract IP address and Reason (Rule Name) from Vision One's data. 
Check if the IP address is public. Only Public IPs are a subject to report.
Dedup of attack vectors by "ruleName".
'''

def ipExtractor(rawData):
    formattedDict = {}

    # For cycle to iterate through the returned data by TM V1 API and extract IP address and IPS Rule Name

    for x in range(len(rawData['items'])):
        ## excluding events that has no rule assigned
        if 'ruleName' not in rawData['items'][x].keys():
            continue
        else:
            ## events with internal IP addresses as a source can be considered as internal issue and/or test issue. Must not be reported
            publicIpCheck = ipaddress.ip_address(rawData['items'][x]['src'][0]).is_global
            if publicIpCheck is True:
                if rawData['items'][x]['src'][0] in formattedDict.keys() and rawData['items'][x]['ruleName'] not in formattedDict[rawData['items'][x]['src'][0]]:
                    formattedDict[rawData['items'][x]['src'][0]].append(rawData['items'][x]['ruleName'])
                elif rawData['items'][x]['src'][0] in formattedDict.keys() and rawData['items'][x]['ruleName'] in formattedDict[rawData['items'][x]['src'][0]]:
                    print('Duplicate: ' + str(rawData['items'][x]['ruleName']) + ' already recorded for IP: ' + str(rawData['items'][x]['src'][0]))
                    continue
                else:
                    print('Creating dict for IP: ' + str(rawData['items'][x]['src'][0]) )
                    formattedDict[rawData['items'][x]['src'][0]] = []
                    print('Adding ' + rawData['items'][x]['ruleName'] + 'to ' + str(rawData['items'][x]['src'][0]))
                    formattedDict[rawData['items'][x]['src'][0]].append(rawData['items'][x]['ruleName'])
            else:
                continue
    return(formattedDict)

'''
Report to Abuseip DB as Web App Attack(as for now - hardcoded).
Require Abuseip DB API key.
'''
def abusedbipCaller(data):
    
    # Abuseip DB configuration variables. 
    abuseIpDbConfig = {}
    abuseIpDbConfig['url'] = 'https://api.abuseipdb.com/api/v2/report'
    ## Verify that Abuseip DB API key is configured, else - terminate the script.
    try:
        abuseIpDbConfig['apiKey'] = os.environ['ABUSEIPDB_APIKEY']
    except KeyError:
        print('No Abuseip DB API Key defined')
        sys.exit(1)

    ## Hardcoded variable :(  
    abuseIpDbConfig['abuseCategory'] = 21
    
    # Create a dictionary to track the record status
    reportStatus = {}

    # for cycle to iterate through the supplied dict and call Abuseip DB API
    for ipAddr in data.keys():
        
        ## Comment field will be equal to ruleName(-s).
        apiParams = {
                    'ip': str(ipAddr),
                    'categories': str(abuseIpDbConfig['abuseCategory']),
                    'comment': str(data[ipAddr])
                    }
        apiHeaders = {'Accept': 'application/json', 'Key': abuseIpDbConfig['apiKey']}
    
        ## Perform AbuseIP DB API call to report IP address. Terminate if Exception happens.
        try:
            apiCall = requests.post(abuseIpDbConfig['url'], headers=apiHeaders, params=apiParams)
            apiData = json.loads(apiCall.content)
        except Exception as errText:
            print("An error occured: " + str(errText))
            sys.exit(1)
    
        ## Check if 'errors' and 'data' keys in the response. If errors is in the response - print an error
        if 'errors' in apiData:
            print('AbuseIP DB had returned an error: ' + str(apiData['errors']))
            reportStatus[ipAddr] = str(apiData['errors'])
        elif 'data' in apiData:
            print('The IP was reported: ' + str(apiData['data']))
            reportStatus[ipAddr] = str(apiData['data'])
    # Return dict
    return(reportStatus)

################### TEST CODE BELOW ###########
'''
Test Code is below. Uncomment if needed to run tests
'''
#lambda_handler('a','b')