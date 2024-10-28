#!/usr/bin/env python3
"""
Script to retrieve a list of switches from a Netbox instance and sync
port mode, untagged VLAN and tagged VLANs back to Netbox. Switches are
assumed to be running Extreme Networks Switch Engine. Requires a .env file
with the following variables defined:

netbox_token = API token for Netbox
netbox_url = Netbox URL
mail_server = SMTP server
exos_uname = Admin username for switches
exos_pwd = Admin password for switches
log_file = Desired log file name
email_from = From email address for log
email_to = To email address for log

Args:
    --dryrun: Log and email changes but do not write them to Netbox
    --site {saddledome | mcmahon}: Netbox site to query data from

Author: Brendan Sheedy
"""

import argparse
import os
import re
import sys
import logging
import smtplib
from email.message import EmailMessage

import requests
from dotenv import load_dotenv

def get_netbox(path, params):
    """Perform GET request to Netbox and return api data
    
    Args:
        path (str): the api endpoint, e.g. /api/dcim/sites/
        params (dict): any query string parameters
    Returns:
        dict containing data returned from api
    """
    url = netbox_base_url + path
    response = requests.get(url, params=params, headers=netbox_headers, verify=False)
    response.raise_for_status()
    api_data = response.json()['results']
    while response.json()['next'] != None: # Fetch data from additional pages if needed
        response = requests.get(response.json()['next'], params=params, headers=netbox_headers, verify=False)
        response.raise_for_status()
        api_data.extend(response.json()['results'])
    return api_data

def get_netbox_devices():
    """Get Extreme Networks switches from Netbox
    
    Returns:
        list containing switch name, device_id, ip and virtual chassis id if applicable
    """
    path = '/api/dcim/devices/'
    # Filter to extreme networks switches at specified site
    params = {'manufacturer': 'extreme-networks', 'role': 'switch', 'site': netbox_site}
    api_data = get_netbox(path, params)
    device_collector = []
    for switch in api_data:
        device = {}
        # Only add switch to dict if single switch or first in stack
        if switch['virtual_chassis'] == None or switch['vc_position'] == 1:
            device = {'name': switch['name'], 'device_id': switch['id'],
                      'ip': switch['primary_ip']['address'].split('/')[0]}
            # If part of stack, add virtual chassis id to dict
            if switch['vc_position'] == 1:
                device['vc_id'] = switch['virtual_chassis']['id']
            device_collector.append(device)
    return device_collector

def get_netbox_vlans():
    """Get VLANs and their ids from Netbox
    
    Returns:
        dict of vlan ids with corresponding netbox ids
    """
    path = '/api/ipam/vlans/'
    params = {'brief': 1, 'site': [netbox_site, 'null']}
    api_data = get_netbox(path, params)
    vlan_collector = {}
    for vlan in api_data:
        vlan_collector[vlan['vid']] = vlan['id']
    return vlan_collector

def get_netbox_interfaces(info):
    """Get interface VLAN information for specified switch from Netbox
    
    Args:
        info (dict): values for specified switch, requires device_id or vc_id keys
    Returns:
        dict of interfaces with interface id, mode, tagged vlans and untagged vlan
    """
    path = '/api/dcim/interfaces/'
    params = {'enabled': True} # Filter to enabled interfaces only
    # If part of stack, retrieve interfaces based on virtual chassis id
    if 'vc_id' in info:
        params['virtual_chassis_id'] = info['vc_id']
    else:
        params['device_id'] = info['device_id']
    api_data = get_netbox(path, params)
    int_collector = {}
    for interface in api_data:
        # Only return interfaces with slot:port naming convention, e.g. 1:19 or 1:53:1
        if re.search(r'\d:\d+:?\d?', interface['name']):
            mode = interface['mode']['value'] if interface['mode'] else None
            untagged = interface['untagged_vlan']['vid'] if interface['untagged_vlan'] else None
            tagged = [vlan['vid'] for vlan in interface['tagged_vlans']]
            int_collector[interface['name']] = {'int_id': interface['id'],
                                                'mode': mode,
                                                'tagged_vlans': sorted(tagged),
                                                'untagged_vlan': untagged}
    return int_collector

def exos_auth(ip):
    """Authenticate to switch and return headers containing auth token
    
    Args:
        ip (str): ip address of switch to connect to
    Returns:
        dict with headers for authentication to restconf api on switch
    """
    headers = {'Content-Type': 'application/json'}
    body = {'username': os.environ.get('exos_uname'),
            'password': os.environ.get('exos_pwd')}
    url = f'https://{ip}/auth/token'
    try:
        response = requests.post(url, json=body, headers=headers, verify=False)
        response.raise_for_status()
        headers['Cookie'] = f'x-auth-token={response.json()['token']}'
        return headers
    except requests.exceptions.RequestException as err:
        logger.error(f'Unable to retrieve RESTCONF token, {err}')
        raise

def get_exos_interfaces(ip, headers):
    """Get interface VLAN information from switch
    
    Args:
        ip (str): ip address of switch to connect to
        headers (dict): headers with restconf auth token
    Returns:
        dict of interfaces with mode, tagged vlans and untagged vlan
    """
    # JSONPath filter to filter results (https://jsonpath.com/)
    filter = '?filter=$.openconfig-interfaces:interfaces.interface[?(@.state.type == "ethernetCsmacd")]'
    # RESTCONF url for yang model 
    # https://documentation.extremenetworks.com/EXOS/api/ProgramInterfaces/RESTCONF/RESTCONF.html
    url = f'https://{ip}/rest/restconf/data/openconfig-interfaces:interfaces'
    try:
        response = requests.get(url + filter, headers=headers, verify=False)
        response.raise_for_status()
        int_collector = {}
        for int in response.json():
            if int['state']['oper-status'] != 'NOT_PRESENT': # Do not include not present interfaces
                int_state = int['openconfig-if-ethernet:ethernet']['openconfig-vlan:switched-vlan']['state']
                int_collector[int['name']] = {'mode': int_state['interface-mode'].lower(),
                                              'tagged_vlans': sorted(int_state.get('trunk-vlans', []))}
                if int_collector[int['name']]['mode'] == 'trunk':
                    int_collector[int['name']]['mode'] = 'tagged'
                    int_collector[int['name']]['untagged_vlan'] = int_state.get('native-vlan', None)
                if int_collector[int['name']]['mode'] == 'access':
                    int_collector[int['name']]['untagged_vlan'] = int_state.get('access-vlan', None)
                if not int_collector[int['name']]['untagged_vlan'] and not int_collector[int['name']]['tagged_vlans']:
                    int_collector[int['name']]['mode'] = None
        return int_collector
    except requests.exceptions.RequestException as err:
        logger.error(f'Unable to retrieve RESTCONF data, {err}')
        raise

def get_int_updates(netbox_interfaces, exos_interfaces):
    """Compare interface information from Netbox and switch and return updates
    needed within Netbox

    Args:
        netbox_interfaces (dict): interfaces from netbox with VLAN information
        exos_interfaces (dict): interfaces from switch with VLAN information
    Returns:
        list of interfaces with VLAN information that needs updating in Netbox
    """
    update_collector = []
    for int, info in exos_interfaces.items():
        try:
            update = {}
            flag_tagged = False
            flag_untagged = False
            if info['tagged_vlans'] != netbox_interfaces[int]['tagged_vlans']:
                flag_tagged = True
            if info['untagged_vlan'] != netbox_interfaces[int]['untagged_vlan']:
                flag_untagged = True
            if flag_tagged == True or flag_untagged == True:
                update = {'port': int,
                          'int_id': netbox_interfaces[int]['int_id'],
                          'mode': info['mode']}
                if flag_tagged == True:
                    update['tagged_vlans'] = info['tagged_vlans']
                if flag_untagged == True:
                    update['untagged_vlan'] = info['untagged_vlan']
                update_collector.append(update)
        except KeyError:
            logger.error(f'Interface {int} not found in Netbox')
    return update_collector

def set_netbox_interface(int):
    """Update VLAN information for a single interface in Netbox 
    
    Args:
        int (dict): VLAN information for one interface
    """
    int_id = int.pop('int_id')
    # Replace VLAN ids with their Netbox id if necessary
    if 'untagged_vlan' in int and int['untagged_vlan']:
        int['untagged_vlan'] = netbox_vlan_ids[int['untagged_vlan']]
    if 'tagged_vlans' in int and int['tagged_vlans']:
        int['tagged_vlans'] = [netbox_vlan_ids[i] for i in int['tagged_vlans']]
    path = f'/api/dcim/interfaces/{int_id}/'
    url = netbox_base_url + path
    try:
        response = requests.patch(url, json=int, headers=netbox_headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        logger.error(f'Unable to make change, {err}')

def send_log():
    """Email log file"""
    try:
        with open(log_file) as file:
            log_msg = EmailMessage()
            log_msg.set_content(file.read())
        log_msg['Subject'] = 'VLAN Sync Log'
        log_msg['From'] = os.environ.get('email_from')
        log_msg['To'] = os.environ.get('email_to')
        smtp = smtplib.SMTP(mail_server, timeout=20)
        smtp.send_message(log_msg)
        smtp.quit()
    except Exception as err:
        logger.error(f'Unable to email log, {err}', exc_info=True)

# Main body starts here
# Load variables from .env file and parse arguments
load_dotenv()
parser = argparse.ArgumentParser()
parser.add_argument('--dryrun', help='do not write changes to Netbox if included', action='store_true')
parser.add_argument('--site', choices=['saddledome', 'mcmahon'], default='saddledome')
args = parser.parse_args()
netbox_base_url = os.environ.get('netbox_url')
mail_server = os.environ.get('mail_server')
log_file = os.path.join(os.path.dirname(__file__), os.environ.get('log_file'))
netbox_site = args.site

# Set logger configuration
logging.basicConfig(level=logging.INFO, filename=log_file, filemode='w', 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    netbox_headers = {'Accept': 'application/json',
                      'Content-Type': 'application/json',
                      'Authorization': f'Token {os.environ.get('netbox_token')}'}
    switches = get_netbox_devices() # Get list of switches from Netbox
    netbox_vlan_ids = get_netbox_vlans() # Get list of VLANs with ids
except Exception as err:
    logger.error(f'Unable to connect to Netbox, {err}', exc_info=True)
    send_log()
    sys.exit(1)

for switch in switches:
    try:
        logger.info(f'Connecting to switch {switch['name']}')
        exos_headers = exos_auth(switch['ip']) # Authenticate to switch
        exos_interfaces = get_exos_interfaces(switch['ip'], exos_headers) # Get VLAN info from switch
        netbox_interfaces = get_netbox_interfaces(switch) # Get VLAN info from Netbox
        interface_updates = get_int_updates(netbox_interfaces, exos_interfaces) # Compare VLAN info
        if interface_updates:
            for int in interface_updates:
                port = int.pop('port')
                log_msg = (f'Setting interface {port} ') # Generate log message
                if 'untagged_vlan' in int:
                    log_msg += (f'- Untagged VLAN to {int['untagged_vlan']} -')
                if 'tagged_vlans' in int:
                    log_msg += (f'- Tagged VLAN to {', '.join(map(str, int['tagged_vlans'])) or 'None'} -')
                logger.info(log_msg)
                if not args.dryrun:
                    set_netbox_interface(int) # Update VLAN info in Netbox for each interface
            break
        else:
            logger.info('No updates found')
            break
    except Exception as err:
        logger.error(err, exc_info=True)
        break

logger.info('Sync complete')
send_log()