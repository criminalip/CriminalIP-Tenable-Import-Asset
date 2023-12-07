from datetime import datetime,timedelta
import logging

# UUID
BASIC_NETWORK_UUID ='${Tenable_BASIC_NETWORK_UUID}'
CHAGE_NETWORK_UUID = '${Tenable_NETWORK_UUID}'


# API KEY
ACCESS_KEY = '${Tenable_ACCESS_API_KEY}'
SECRET_KEY = '${Tenable_SECRET_API_KEY}'
CRIMINAL_API_KEY = "${CRIMINALIP_API_KEY}"



# Constants
target_prefix = 'https://www.exploit-db.com/download/'
CIP_BASE_URL = "https://api.criminalip.io/"
TENABLE_BASE_URL = 'https://cloud.tenable.com/'
FILE_PATH = "${download_file_path}ip_list.txt"


#log

now_string = datetime.today().strftime('%Y-%m-%d')

def setup_logging():
    logging.basicConfig(level=logging.DEBUG,
                        filename=f'{now_string}_cip_debug.log',
                        filemode='a',
                        format='%(asctime)s - %(levelname)s - %(message)s')


def tenable_setup_logging():    
    logging.basicConfig(
        level=logging.DEBUG,  
        format='%(asctime)s - %(levelname)s - %(message)s', 
        filename=f'{now_string}_tenable_debug.log', 
        filemode='a'
    )
# LOGGER = logging.getLogger()


#TIME
current_date = datetime.now()
one_month_ago = current_date - timedelta(days=30)

#target
keys_to_extract = ['ETH', 'BTC', 'docfile', 'zip', 'url', 'exefile', 'email', 'sha256', 'md5', 'XMR', 'darkweb']
value_order = ['inbound/outbound', 'abuse', 'ids', 'url', 'sha', 'md5', 'email']