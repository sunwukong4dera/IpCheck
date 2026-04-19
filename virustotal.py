import requests
import json

from config_parser import VIRUSTOTAL_API_KEY, URL_VIRUSTOTAL

ip_address = '83.168.89.181'
additional_string = f'ip_addresses/{ip_address}'

headers = {
    "accept": "application/json",
    "x-apikey": VIRUSTOTAL_API_KEY
}

response = requests.get(URL_VIRUSTOTAL + additional_string, headers=headers)

decodedResponse = json.loads(response.text)

with open('virustotal-data.json', 'w') as outfile:
    json.dump(decodedResponse, outfile)
