import time
import json
import sys
import requests
import logging
from datetime import datetime
from tenable.io import TenableIO
from config import *

access_key = ACCESS_KEY
secret_key = SECRET_KEY

COUNT = 0
CHECK_COUNT = 0  # Count to see if it's the last time
assets_import_ip = set()
source = 'Criminal IP'

tenable_setup_logging()
logger = logging.getLogger()

class TenableData:
    def __init__(self):
        self.tio = TenableIO(access_key, secret_key, vendor='Criminal IP', product='Import Criminal IP Assets Data', build='0.0.1')
        self.cache = []
        self.vendor = 'Criminal IP'

    def drain_import_cache(self):
        
            job = self.tio.assets.asset_import(self.vendor, *self.cache)
            logger.debug(f'Tenable Import Job: {job}')
            
            while self.tio.assets.import_job_details(job)['status'] != 'COMPLETE':
                print(f'Tenable Asset Import Job {job} still processing....')
                time.sleep(5)
            
            print(f'Tenable Asset Import Job {job} completed.')
            self.cache = []
            
    def add_to_import(self, item: dict):
            new_item = {
                "mac_address": item.get('mac_address', [])[:100],
                "netbios_name": item.get('netbios_name', [])[0],  # Assuming netbios_name is a list with a single item
                "fqdn": item.get('fqdn', [])[:100],  # Assuming fqdn is a list with a single item
                "ipv4": item.get('ipv4', []),
                "hostname": item.get('hostname', [])[:100],  # Assuming hostname is a list with a single item
                "operating_system": [', '.join(item.get('operating_system',[]))],
                "ssh_fingerprint": item.get('ssh_fingerprint', [])[0],  # Assuming ssh_fingerprint is a list with a single item
                "installed_software": item.get('installed_software', [])[:100],
                'system_type': item.get('system_type', [])[0]
            }
            return new_item
        
    def tenable_bulk_main(self,ips_data):

        for item in ips_data:
            
            dict_length = len(item)
            # print(dict_length)
            new_item = self.add_to_import(item)
            self.cache.append(new_item)
        # print(len(self.cache))
        if len(self.cache) >= 100:
            self.drain_import_cache()   
        else:
            self.drain_import_cache() 
        
        
 
'''
Uncomment below is available.
The annotated part is the code that moves the network of the information in the imported data.
If the network is set to BASIC_NETWORK_UUID when inserting multiple data, there is a possibility that the existing value will be overwritten
Uncomment the code below to improve data overlap.
'''        
        # if  CHECK_COUNT == len(data):
        #     print(ip)
        #     assets_to_move = [ip]
        #     logger.debug(f'assets_to_move: {assets_to_move}')
        #     move_data = self.tio.assets.move_assets(BASIC_NETWORK_UUID, CHAGE_NETWORK_UUID, assets_to_move)
        #     logger.debug(f'move_assets result: {move_data}')
        #     while move_data['response']['data']['asset_count'] == 0:
        #         move_data = self.tio.assets.move_assets(BASIC_NETWORK_UUID, CHAGE_NETWORK_UUID, assets_to_move)
        #         logger.debug(f'move_assets result: {move_data}')
        #         if move_data['response']['data']['asset_count'] == 1:
        #             CHECK_COUNT = 0
        #             break
        #         time.sleep(10)
        # CHECK_COUNT = 0
                
