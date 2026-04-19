import requests
import json

from config_parser import ABUSEIPDB_KEY, URL_ABUSEIPDB

querystring = {
    'ipAddress': '83.168.89.181',
    'maxAgeInDays': '90',
    'verbose': ''
}

headers = {
    'Accept': 'application/json',
    'Key': ABUSEIPDB_KEY
}

response = requests.request(method='GET',
                            url=URL_ABUSEIPDB,
                            headers=headers,
                            params=querystring)

decodedResponse = json.loads(response.text)

with open('abuseipdb-data.json', 'w') as outfile:
    json.dump(decodedResponse, outfile)