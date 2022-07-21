#!/bin/python

'''
Scripter: Stinky Fox
Version: 0.1
Purpose:
    Report malicious IP address to Abuseip DB.
    Intel gathered from Trend Micro Vision One API.
    Events are being reported by Trend Micro C1WS/DS IPS module.
    Script built to run in AWS Lambda

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
    print(preparedData)

    
'''
Call Trend Micro Vision One API. API key must not be empty. If API key is empty - exit().
'''

def tmv1Caller():
    
    tmv1Config = {}
    acceptablePeriodTypes = ['days', 'hours', 'weeks', 'months']

    tmv1Config['tmv1ApiEndpoint'] = 'https://api.xdr.trendmicro.com/v3.0/search/detections'

    try:
        tmv1Config['tmv1ApiToken'] = os.environ['TMV1APIKEY']
    except KeyError:
        print('No V1 API Key defined')
        sys.exit()
    tmv1Config['queryPeriod'] = {}
    
    if os.environ['TMV1QUERYPERIODTYPE'] in acceptablePeriodTypes:
        try:
            tmv1Config['queryPeriod'][os.environ['TMV1QUERYPERIODTYPE']] = int(os.environ['TMV1QUERYPERIODVALUE'])
        except KeyError:
            tmv1Config['queryPeriod'] = {"days":1}
    else:
        print('Incorrect value ' + os.environ['TMV1QUERYPERIODTYPE'])
    dtCalculated = dateCalculator(tmv1Config['queryPeriod'])
    tmv1Config['apiQueryParams'] = {'startDateTime': dtCalculated}

    tmv1Config['apiheaders'] = {'Authorization': 'Bearer ' + tmv1Config['tmv1ApiToken'], 'TMV1-Query': 'eventName:DEEP_PACKET_INSPECTION_EVENT'}

    try:
        apiCall = requests.get(tmv1Config['tmv1ApiEndpoint'], params=tmv1Config['apiQueryParams'], headers= tmv1Config['apiheaders'])
    except Exception as errText:
        print("Error communicating with API: " + str(errText))
        sys.exit()
    
    if apiCall.status_code != 200:
        print("API returned code: " + str(apiCall.status_code) + " with message: " + str(apiCall.content))
        sys.exit()
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
    for x in range(len(rawData['items'])):
        if 'ruleName' not in rawData['items'][x].keys():
            continue
        else:
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


def abusedbipCaller():
    pass

#################### TEST CODE BELOW ###########
lambda_handler('a','b')