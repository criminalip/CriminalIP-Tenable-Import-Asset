import logging
import argparse
import time
import ipaddress
from core.cip_requests import CIPResultData
from core.tenable_asset_import import TenableData
from core.process.process_ip_data import ProcessFlow
from config import *

asset_data_list = []
COUNT = 1

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def read_ips_from_file(file_path):
    with open(file_path, 'r') as f:
        ips = {line.strip() for line in f if line.strip()}
    return ips

def process_ip(ip, cip_data, tenable_data,process_flow,ip_len):
    if is_private_ip(ip):
        logging.info(f"Skipping private IP address: {ip}")
        return

    ip_data_json_result = cip_data.cip_request(ip)
    malicious_data_json_result = cip_data.cip_request(ip)
    # print(malicious_data_json_result)
    final = process_flow.process_ip_data(ip_data_json_result, malicious_data_json_result)

    global asset_data_list, COUNT
    asset_data_list.append(final)
    
    COUNT += 1
    if COUNT > ip_len:
        print("Final asset data",asset_data_list)
        
        tenable_data.tenable_bulk_main(asset_data_list)
            
def object_creation():
    return CIPResultData(), TenableData(), ProcessFlow()


def main():
    setup_logging()
    parser = create_parser()
    args = parser.parse_args()
    logging.debug("This is a debug message.")

    cip_data, tenable_data, process_flow = object_creation()

    args.input == 'bulk' and args.file
    ips = read_ips_from_file(args.file)
    for ip in ips:
        print(f"Start :{ip}")
        ip_len = len(ips)
        process_ip(ip, cip_data, tenable_data,process_flow,ip_len)
    print("")
    


def create_parser():
    parser = argparse.ArgumentParser(description='Process IP addresses and send data to Tenable')
    parser.add_argument('input', choices=['bulk'], help='Enter the ip in ip_list.txt and run it using the bulk option.')
    parser.add_argument('--file', help='File containing list of IP addresses')
    return parser



if __name__ == "__main__":
    main()