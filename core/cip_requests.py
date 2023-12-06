import requests
import sys
import time
import json
from config import *


API_KEY = CRIMINAL_API_KEY
BASE_URL = CIP_BASE_URL
HEADERS = {"x-api-key": API_KEY}
COUNT = 0
       


class CIPResultData():
    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.get_exploits_call_count = 0 

    def cip_request(self,ip):
        global COUNT
        payload ={}
        
        if COUNT == 0:
            endpoint =f"v1/asset/ip/report?ip={ip}&full=true" 
            url =BASE_URL + endpoint
            res = requests.get(url, headers=HEADERS, data= payload)
            COUNT += 1

        else:
            endpoint =f"v1/feature/ip/malicious-info?ip={ip}" 
            url =BASE_URL + endpoint
            res = requests.get(url,headers=HEADERS, data= payload)
            COUNT = 0
        try:
            data = res.json()
            # print(data)
            assert data['status'] == 200

        except AssertionError:
            self.error_massage(data,url)
            sys.exit(1)

        return data
    
    # exploit db api request
    def get_exploits(self, cve_id):
        """Get exploits by CVE ID."""
        
        self.get_exploits_call_count += 1 
        # print(self.get_exploits_call_count)
        params = {"cve_id": cve_id}
        exploits = []
        offset = 0
        
        params["offset"] = offset
        response = self._request(f"v1/exploit/search?query=cve_id:{cve_id}", params)
        try:
            data = response.get('data', {})
            result = data.get('result', [])
            exploits.extend(result)
            return exploits
        except json.JSONDecodeError as e:
            logging.error(e)
            return []
            
        
        
    
    def _request(self, endpoint, params):
        """Make a GET request and return the JSON response."""
        url = BASE_URL + endpoint
        response = self.session.get(url, params=params)
        try:
            data = response.json()
            assert data['status'] == 200
            return data
        except AssertionError:
            self.error_massage(data,url)
            sys.exit(1)
    
    
    def error_massage(self,data,url):
        if data['message'] == 'invalid api key':
            print(f"[-] Invalid URL : {url}, Error message : Your Criminal IP api key is invalid\n")
        elif data['status'] == 500:
            print(f"[-] Invalid URL : {url}, Error message : An unexpected error occured\n")
        elif data['message'] == 'Invalid IP Address.':
            print(f"[-] Invalid URL : {url}, Error message : The target must be an IP address\n")
        elif data['message'] == 'unable to call api at the same time':
            print(f"[-] Invalid URL : {url}, Error message :{data['message']}\n")
        elif data['message'] == "limit exceeded":
            print(f"[-] Invalid URL : {url}, Error message :{data['message']}\n")