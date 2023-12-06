import re
import sys
import time
import requests
import json
import urllib.parse
from config import *
from core.cip_requests import CIPResultData

class ParseData():
    exploit_cache = {}
    
    def __init__(self) -> None:
        self.request_cip = CIPResultData()
        # 다음과 같이 캐시 변수를 추가합니다.
        
        self.target_prefix = "http"
    
    def extract_software(self,port_number,product,protocol,product_version,check_vuln,vuln_info):
        cveid_list = [vuln['cve_id'] for vuln in vuln_info] if check_vuln else []
        exploit_db_data = self.process_cve_list(cveid_list)
        # print(exploit_db_data)
        if cveid_list:
            cveid_str = ', '.join(s for s in cveid_list)
            exploitdb_str = ''
            
            for cve in cveid_list:
                if cve in exploit_db_data and exploit_db_data[cve]:
                    link = list(exploit_db_data[cve])[0]  # 링크가 여러 개면 첫 번째 링크 사용
                    exploitdb_str += f"{cve}: {link}, "

            # 맨 마지막 ", " 제거
            exploitdb_str = exploitdb_str.rstrip(', ')
            
            final_software = f"{product}/{product_version}({protocol}/{port_number})| CVE_ID: {cveid_str}| Link: {exploitdb_str}"
        else:
            final_software = f"{product}/{product_version}({protocol}/{port_number})"
    
        # print(final_software)        
        return final_software
    
    def extract_url_from_exploit_content(self,exploit_content):
        # 'Advisory:' 뒤의 URL을 추출하기 위한 정규식 패턴
        pattern = r'\b((?:https?|ftps?|ftp):\/\/(?:[a-zA-Z]|[0-9]|[$\-@\.&+:/?=]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)\b'
        match = re.search(pattern, exploit_content)
        if match:
            url = match.group(1)
            return url
        else:
            return None
        
    def process_cve_list(self, cve_list):
        
        for vuln in cve_list:
            # print(self.exploit_cache)
            if vuln not in ParseData.exploit_cache:
                data = self.request_cip.get_exploits(vuln)
                ParseData.exploit_cache[vuln] = data
                if len(data) > 0:
                    exploits = set()
                    for entry in data:
                        exploit_content = entry.get('edb_content')
                        if exploit_content and self.target_prefix in exploit_content:
                            url = self.extract_url_from_exploit_content(exploit_content)
                            # print(url)
                            if url:
                                exploits.add(url)
                    
                    # exploit DB가 존재하는 경우에만 값을 추가합니다.
                    if exploits:
                        ParseData.exploit_cache[vuln] = exploits
                    else:
                        ParseData.exploit_cache[vuln] = None# 클래스 변수 사용
                else:
                    ParseData.exploit_cache[vuln] = None
                        
        
        return ParseData.exploit_cache
    
    
    # tag
    def tags_info(self, scanner_count, tags = None):
        if tags and "Embeded" in tags :
            system_type = "embedded"
        elif tags and "Switch" in tags and "Embeded" not in tags:
            system_type = "router"
        elif isinstance(scanner_count, list) and len(scanner_count) > 0:
            system_type = "scanning_record"
        elif tags:
            tags_str = ', '.join(s for s in tags)
            system_type = tags_str
        else:
            system_type = "general-purpose"
            
        return system_type
     
     # ssh fingerprint       
    def check_ssh_banner(self,banner):
        if "Fingerprint: " in banner:
            ssh_fingerprint = banner.split("Fingerprint: ")[1].split()[0]
        else:
            ssh_fingerprint = "Unknown"
            
        return ssh_fingerprint

    # netbios name
    def netbios(self,banner):

        if "NetBIOS_Computer_Name: " in banner:
            netbios_computer_name = banner.split("NetBIOS_Computer_Name: ")[1].split()[0]
        elif "NetBIOS Computer Name: " in banner:
            netbios_computer_name = banner.split("NetBIOS Computer Name: ")[1].split()[0]
        elif "NetBIOS name: " in banner:
            netbios_computer_name = banner.split("NetBIOS name: ")[1].split()[0]
        else:
            netbios_computer_name = "Unknown"

        return netbios_computer_name
    
    #mac address
    
    def mac_address(self,banner):
        mac_addresses = self.extract_mac_addresses(banner)
        filetered_mac_addresses = []
        # print(mac_addresses)
        if mac_addresses: 
            for mac_address in mac_addresses:
                if 'Mac address : ' not in mac_address.lower():
                    filetered_mac_addresses.append(self.format_mac_address(mac_address))

            if filetered_mac_addresses:
                mac_address = ', '.join(filetered_mac_addresses)
        else:
            mac_address = '00:00:00:00'
        return mac_address
    

    def extract_mac_addresses(self,banner):
        mac_address_pattern = r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b|\b[0-9A-Fa-f]{12}\b"
        mac_addresses = re.findall(mac_address_pattern,banner)

        return mac_addresses

    def format_mac_address(self,mac_address):
        if ':' in mac_address:
            return mac_address
        mac_parts = [mac_address[i:i+2] for i in range(0, len(mac_address), 2)]
        formatted_mac_address = ":".join(mac_parts)
        
        return formatted_mac_address


    #operating_system_parser
    def banner_parser(self,banner):
        result = []
        processed_data = []
        current_item = []
        doc_pattern = r'\b(\w+\.(?:xlsx|docs|pdf|pptx|txt))\b'
        url_pattern = r'\b((?:https?|ftps?|ftp):\/\/(?:[a-zA-Z]|[0-9]|[$\-@\.&+:/?=]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)\b'
        file_pattern = r'((?:http[s]?://\S+/)?\S+\.exe)\b'
        zip_pattern = r'((?:http[s]?://\S+/)?\S+\.zip)\b'
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
        md5_pattern = r'\b[A-Fa-f0-9]{32}\b'
        sha_pattern = r'\b[A-Fa-f0-9]{64}\b'
        btc_patterns = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        eth_pattern = r'\b0x[0-9A-Fa-f]{40}'
        xmr_pattenr = r'\b4[0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}\b'
        darkweb_pattern = r"(?:https?://)?(?:www\.)?([a-z0-9]+\.(?:onion))"       
        
        doc_files = self.extract_strings(doc_pattern, banner)
        urls = self.extract_strings(url_pattern, banner)
        zip_files = self.extract_strings(zip_pattern, banner)
        exe_files = self.extract_strings(file_pattern, banner)
        emails = self.extract_strings(email_pattern, banner)
        md5s = self.extract_strings(md5_pattern, banner)
        shas= self.extract_strings(sha_pattern, banner)
        darkwebs = self.extract_strings(darkweb_pattern, banner)
        eths = self.extract_strings(eth_pattern, banner)
        xmrs = self.extract_strings(xmr_pattenr, banner)
        
        btcs = self.extract_strings(btc_patterns, banner)
        
        for btc in btcs:
            doc = {
                'BTC': btc
            }
            result.append(doc)
            
        
        for doc_file in doc_files:
            doc = {
                'docfile':doc_file
            }
            result.append(doc)
        
        for zipfile in zip_files:
            doc = {
                'zip': zipfile
            }
            result.append(doc)
            
        for url in urls:
            doc = {
                'url':url
            }
            result.append(doc)
            
        for exe_file in exe_files:
            doc = {
                'exefile':exe_file
            }
            result.append(doc)
            
        for email in emails:
            doc = {
                'email':email
            }
            result.append(doc)
        
        for sha_256 in shas:
            doc = {
                'sha256':sha_256
            }
            result.append(doc)
        
        for md5 in md5s:
            doc = {
                'md5':md5
            }
            result.append(doc)
        
        for eth in eths:
            doc = {
                'ETH':eth
            }
            result.append(doc)
            
        for xmr in xmrs:
            doc = {
                'XMR':xmr
            }
            result.append(doc)
        
        for darkweb in darkwebs:
            doc = {
                'darkweb':darkweb
            }
            result.append(doc)
        key_value_dict = {}
        for item in result:
            for key in keys_to_extract:
                if key in item:
                    key_value_dict[key] = item[key]
        
        key_value_pairs = [f"{key}: {value}" for key, value in key_value_dict.items()]
        return key_value_pairs
    
    def extract_strings(self,pattern, string):
        matches = re.findall(pattern, string)
        if pattern == r'\b(\w+\.(xlsx|docx|pdf|pptx))\b':
            return [filename for filename, _ in matches]
        return matches