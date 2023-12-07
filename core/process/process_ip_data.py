from datetime import datetime, timedelta
from config import *
from core.process.data_parsing import ParseData

class ProcessFlow():
    def __init__(self) -> None:
        self.parser = ParseData()
    
    def process_ip_data(self,ip_data_json_result, malicious_data_json_result):
        #list,variable
        input_dicts = []
        os_data = []
        connected_domain = []
        recent_ports = []
        install_software_list = []
        
        abuse_counts = {}
        ids_counts  = {}
        processed_ports = set()
        
        # change malicious_data
        scanner_count = malicious_data_json_result['scanning_record']['count']
        
        
        # change ip_data and initialize
        mac_address = '00:00:00:00'
        systemtype = "general-purpose"
        ssh_fingerprints = "Unknown"
        
        out_score = ip_data_json_result['score']['outbound']
        in_score = ip_data_json_result['score']['outbound']    
        os_data.append(f"Inbound({in_score})/Outbound({out_score})")
        
        ipv4 = ip_data_json_result['ip']
        hostname = ip_data_json_result['hostname']['data'][0]['domain_name_rep'] if 'hostname' in ip_data_json_result and 'data' in ip_data_json_result['hostname'] and ip_data_json_result['hostname']['data'] else 'Unknown'
        vuln_info = ip_data_json_result['vulnerability']['data']
        
        #check value data for os_data
        # Insert the information about "abuse recode" into the list.
        if ip_data_json_result['ip_category']['count'] != 0:
            for abuse in ip_data_json_result['ip_category']['data']:
                if (abuse['type'] != "cloud service") and (abuse['type'] != "proxy"):
                    abuse_type = abuse['type']
                    if abuse_type in abuse_counts:
                        abuse_counts[abuse_type] += 1
                    else:
                        abuse_counts[abuse_type] = 1

            abuse_strs = []
            for abuse_type, count in abuse_counts.items():
                abuse_strs.append(f"{abuse_type}: {count}")

            if abuse_counts: 
                abuse_strs = ', '.join(f"{abuse_type}: {count}" for abuse_type, count in abuse_counts.items())
                os_data.append(f'Abuse Record: {sum(abuse_counts.values())} ({abuse_strs})')
                
        # Insert the list of detected IDS information.     
        if ip_data_json_result['ids']['count'] != 0:
            for ids in ip_data_json_result['ids']['data']:
                classification = ids['classification']
                if classification in ids_counts:
                    ids_counts[classification] += 1
                else:
                    ids_counts[classification] = 1
            ids_strs = []
            for classification, count in ids_counts.items():
                ids_strs.append(f"{classification}: {count}")
            if ids_counts:
                ids_strs = ', '.join(f"{classification}: {count}" for classification, count in ids_counts.items())
                os_data.append(f'Snort signature: {sum(ids_counts.values())}({ids_strs})')
        
        # Insert information about the connected domain into the list.      
        if ip_data_json_result['domain']['count'] > 0:
            for url in ip_data_json_result['domain']['data']:
                connected_domain.append(url['domain'])
        
        
        # Retrieve only the data from ports that have been opened within 30 days
        if ip_data_json_result['port']['count']!=0:
            for info in ip_data_json_result["port"]['data']:
                confirmed_time = datetime.strptime(info['confirmed_time'], "%Y-%m-%d %H:%M:%S")
                if confirmed_time >= one_month_ago:
                    recent_ports.append(info)

        # Retrieve data from the last 30 days and parse it.
        for info in sorted(recent_ports, key=lambda info: info["confirmed_time"], reverse=True):
        
            product = info['app_name']
            product_version = info['app_version']
            protocol = info['protocol']
            banner = info['banner']
            port_number = info['open_port_no']
            tags = info['tags']
            socket = info["socket"]
            fqdn_domain = info['sdn_common_name']
            check_vuln = info['is_vulnerability']       
            
            if port_number in processed_ports:
                continue

            if fqdn_domain is not None:
                connected_domain.append(fqdn_domain)
             
            netbios_name = self.parser.netbios(banner)
            install_software_list.append(self.parser.extract_software(port_number,product,socket,product_version,
                                                                 check_vuln,vuln_info))
            os_data.extend(self.parser.banner_parser(banner))
            mac_address = self.parser.mac_address(banner)
            systemtype = self.parser.tags_info(scanner_count, tags)
            if protocol == "SSH":
                ssh_fingerprints = self.parser.check_ssh_banner(banner)
            
            if len(connected_domain) == 0:
                connected_domain.append("Unknown")
            elif len(os_data) == 0:
                os_data.append('Unknown')
            elif len(install_software_list) == 0:
                install_software_list.append("Unknown")
                
            port_info = {
                    'ipv4': ipv4,
                    'fqdn': connected_domain,
                    'hostname': hostname,
                    'installed_software': install_software_list,
                    'netbios_name': netbios_name,
                    'mac_address': mac_address,            
                    'operating_system': os_data,
                    'ssh_fingerprint': ssh_fingerprints,
                    'system_type' : systemtype
                }
            input_dicts.append(port_info)
            processed_ports.add(port_number) 
        
        if input_dicts == []:
            exceped_data = self.exception_handling(scanner_count, ipv4, hostname, mac_address,systemtype)
            input_dicts.append(exceped_data)
        # print(input_dicts)
        final_dict = self.merge_duplicate_dicts(input_dicts)
        final_result = self.remove_list_duplicates(final_dict)
        cleaned_final_dict = self.remove_unknown_and_keep_single(final_result)  # 리스트 내 'Unknown' 값 제거 추가

        return cleaned_final_dict

    # Delete Unknown
    def remove_unknown_and_keep_single(slef,input_dict):
        for key, value in input_dict.items():
            if isinstance(value, list):
                if "Unknown" in value and len(value) > 1:
                    value.remove("Unknown")
                elif "Unknown" in value and len(value) == 1:
                    continue
        return input_dict
    
    # Remove duplicates
    def remove_list_duplicates(self,input_dict):
        for key, value in input_dict.items():
            if isinstance(value, list):
                unique_values = []
                for v in value:
                    if v not in unique_values:
                        unique_values.append(v)
                input_dict[key] = unique_values
        return input_dict

    # Merge into a single object    
    def merge_duplicate_dicts(self, input_dicts):
        merged_dict = {}

        for item in input_dicts:
            for key, value in item.items():
                if key in merged_dict:
                    if isinstance(value, list):
                        # Add only non-duplicate items.
                        for v in value:
                            if v not in merged_dict[key]:
                                merged_dict[key].append(v)
                    else:
                        if value not in merged_dict[key]:
                            merged_dict[key].append(value)
                else:
                    merged_dict[key] = [value] if isinstance(value, str) else value

        return merged_dict
            
            
    def exception_handling(self,scanner_count,ipv4,hostname,mac_address,systemtype):
        if scanner_count > 0:
            check_scanning_system_type = self.parser.tags_info(scanner_count)
            port_info = {
                    'ipv4': ipv4,
                    'fqdn': "Unknown",
                    'hostname': hostname,
                    'installed_software': "Unknown",
                    'netbios_name': "Unknown",
                    'mac_address': mac_address,            
                    'operating_system': "Unknown",
                    'ssh_fingerprint': "Unknown",
                    'system_type' : check_scanning_system_type
                }
                
        else:
            port_info = {
                    'ipv4': ipv4,
                    'fqdn': "Unknown",
                    'hostname': hostname,
                    'installed_software': "Unknown",
                    'netbios_name': "Unknown",
                    'mac_address': mac_address,            
                    'operating_system': "Unknown",
                    'ssh_fingerprint': "Unknown",
                    'system_type' : systemtype
                }
        return port_info       
            
            
