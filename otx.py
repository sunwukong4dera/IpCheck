import requests
import json

from config_parser import OTX_KEY, URL_OTX

ip_address = '83.168.89.181'
section = 'general'
#  section: required (one of general, reputation, geo, malware, url_list, passive_dns)
additional_string = f'indicators/IPv4/{ip_address}/{section}'

headers = {
    'X-OTX-API-KEY': OTX_KEY,
    'Content-Type': 'application/json'
}
response = requests.request(method='GET',
                            url=URL_OTX + additional_string,
                            headers=headers)

decodedResponse = json.loads(response.text)

with open('otx-data.json', 'w') as outfile:
    json.dump(decodedResponse, outfile)
