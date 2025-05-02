#!/usr/bin/env python3
"""
Script to retrieve a list of switches from a Netbox instance and sync
port mode, untagged VLAN and tagged VLANs back to Netbox. Switches are
assumed to be running Extreme Networks Switch Engine or Dell Network OS
6.x (N-series). Requires a .env file with the following variables defined:

netbox_token = API token for Netbox
netbox_url = Netbox URL
netbox_sites = Valid site objects in Netbox, first will be default
mail_server = SMTP server
exos_uname = Admin username for Extreme switches
exos_pwd = Admin password for Extreme switches
dell_uname = Admin username for Dell switches
dell_pwd = Admin password for Dell switches
log_file = Desired log file name
email_from = From email address for log
email_to = To email address for log

Args:
    --dryrun: Log and email changes but do not write them to Netbox
    --site {a site listed in .env file}: Netbox site to query data from, 
        if unspecified first site listed in .env will be used

Author: Brendan Sheedy
"""

import argparse
import logging
import os
import re
import smtplib
import sys
from email.message import EmailMessage

import requests
from dotenv import load_dotenv
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

def get_netbox(path, params):
    """
    Perform GET request to Netbox and return api data
    
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
    # Fetch data from additional pages if needed
    while response.json()['next'] != None:
        response = requests.get(response.json()['next'], params=params,
                                headers=netbox_headers, verify=False)
        response.raise_for_status()
        api_data.extend(response.json()['results'])
    return api_data

def get_netbox_devices():
    """
    Get compatible switches from Netbox
    Platform ID #1 = Extreme Networks Switch Engine
    Platform ID #2 = Dell Network Operating System 6.x (N-series)
    
    Returns:
        list of dictionaries containing switch name, device_id, platform_id,
        ip and virtual chassis id if applicable
    """
    path = '/api/dcim/devices/'
    # Filter to compatible platforms at specified site
    params = {'platform_id': [1,2],
              'role': 'switch',
              'site': netbox_site.lower()}
    api_data = get_netbox(path, params)
    device_collector = []
    for switch in api_data:
        device = {}
        # Only add switch to dict if single switch or first in stack
        if switch['virtual_chassis'] == None or switch['vc_position'] == 1:
            device = {'name': switch['name'],
                      'device_id': switch['id'],
                      'platform_id': switch['platform']['id'],
                      'ip': switch['primary_ip']['address'].split('/')[0]}
            # If part of stack, add virtual chassis id to dict
            if switch['vc_position'] == 1:
                device['vc_id'] = switch['virtual_chassis']['id']
            device_collector.append(device)
    return device_collector

def get_netbox_vlans():
    """
    Get VLANs and their ids from Netbox
    
    Returns:
        dict of vlan ids with corresponding netbox ids
    """
    path = '/api/ipam/vlans/'
    params = {'brief': 1, 'site': [netbox_site.lower(), 'null']}
    api_data = get_netbox(path, params)
    vlan_collector = {}
    for vlan in api_data:
        vlan_collector[vlan['vid']] = vlan['id']
    return vlan_collector

def get_netbox_interfaces(info):
    """
    Get interface VLAN information for specified switch from Netbox
    
    Args:
        info (dict): values for specified switch, requires device_id or vc_id keys
    Returns:
        dict of interfaces with interface id, mode, tagged vlans and untagged vlan
    """
    path = '/api/dcim/interfaces/'
    # Filter to enabled interfaces only
    params = {'enabled': True}
    # If part of stack, retrieve interfaces based on virtual chassis id
    if 'vc_id' in info:
        params['virtual_chassis_id'] = info['vc_id']
    else:
        params['device_id'] = info['device_id']
    api_data = get_netbox(path, params)
    int_collector = {}
    for interface in api_data:
        # Filter by interface name, e.g. 1:19, 1:53:1, or Gi1/0/19
        if re.search(r'(\d:\d+:?\d?)|(\w{2}\d/\d/\d+)', interface['name']):
            mode = interface['mode']['value'] if interface['mode'] else None
            untagged = interface['untagged_vlan']['vid'] if interface['untagged_vlan'] else None
            tagged = [vlan['vid'] for vlan in interface['tagged_vlans']]
            int_collector[interface['name']] = {'int_id': interface['id'],
                                                'mode': mode,
                                                'tagged_vlans': sorted(tagged),
                                                'untagged_vlan': untagged}
    return int_collector

def exos_auth(ip):
    """
    Authenticate to switch and return headers containing auth token
    
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
    """
    Get interface VLAN information from switch running Extreme Switch Engine
    
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
        for interface in response.json():
            # Do not include not present interfaces
            if interface['state']['oper-status'] != 'NOT_PRESENT':
                int_state = interface['openconfig-if-ethernet:ethernet']['openconfig-vlan:switched-vlan']['state']
                int_collector[interface['name']] = {'mode': int_state['interface-mode'].lower(),
                                              'tagged_vlans': sorted(int_state.get('trunk-vlans', []))}
                if int_collector[interface['name']]['mode'] == 'trunk':
                    int_collector[interface['name']]['mode'] = 'tagged'
                    int_collector[interface['name']]['untagged_vlan'] = int_state.get('native-vlan', None)
                if int_collector[interface['name']]['mode'] == 'access':
                    int_collector[interface['name']]['untagged_vlan'] = int_state.get('access-vlan', None)
                if (not int_collector[interface['name']]['untagged_vlan'] and
                    not int_collector[interface['name']]['tagged_vlans']):
                    int_collector[interface['name']]['mode'] = None
        return int_collector
    except requests.exceptions.RequestException as err:
        logger.error(f'Unable to retrieve RESTCONF data, {err}')
        raise

def get_dnos6_interfaces(ip):
    """
    Get interface VLAN information from switch running Dell Network OS 6.x
    
    Args:
        ip (str): ip address of switch to connect to
    Returns:
        dict of interfaces with mode, tagged vlans and untagged vlan
    """
    device = {"device_type": "dell_os6",
              "host": ip,
              "username": os.environ.get('dell_uname'),
              "password": os.environ.get('dell_pwd')}
    try:
        with ConnectHandler(**device) as connect:
            response = connect.send_command('show interfaces status', use_textfsm=True, raise_parsing_error=True)
        int_collector = {}
        for interface in response:
            if interface['mode'] == 'A':
                int_collector[interface['interface']] = {'mode': 'access',
                                                         'untagged_vlan': int(interface['vlan_id'][0]),
                                                         'tagged_vlans': []}
            if interface['mode'] == 'T' or interface['mode'] == 'G':
                tagged_vlans = ''.join(interface['vlan_id']).split(',')
                if interface['mode'] == 'G':
                    logger.warning(f'Interface {interface['interface']} set to General mode')
                if tagged_vlans[0] == '2-4093':
                    logger.warning(f'Interface {interface['interface']} set to Trunk All mode')
                    int_collector[interface['interface']] = {'mode': 'tagged-all',
                                                             'untagged_vlan': int(interface['native_vid']),
                                                             'tagged_vlans': []}
                else:
                    for vlan in tagged_vlans:
                        #Expand VLAN ranges
                        if re.search(r'\d+-\d+', vlan):
                            vlan_split = [int(i) for i in re.split('-', vlan)]
                            vlan_range = list(range(vlan_split[0], vlan_split[1]+1))
                            tagged_vlans.remove(vlan)
                            tagged_vlans = sorted([int(i) for i in tagged_vlans + vlan_range])
                    int_collector[interface['interface']] = {'mode': 'tagged',
                                                             'untagged_vlan': int(interface['native_vid']),
                                                             'tagged_vlans': [int(i) for i in tagged_vlans]}
        return int_collector
    except NetmikoAuthenticationException as err:
        logger.error(f'Connection failed, incorrect credentials')
        raise
    except NetmikoTimeoutException as err:
        logger.error(f'Connection failed, timed out')
        raise

def get_int_updates(netbox_interfaces, switch_interfaces):
    """
    Compare interface information from Netbox and switch and return updates
    needed within Netbox

    Args:
        netbox_interfaces (dict): interfaces from netbox with VLAN information
        switch_interfaces (dict): interfaces from switch with VLAN information
    Returns:
        list of interfaces with VLAN information that needs updating in Netbox
    """
    update_collector = []
    for interface, info in switch_interfaces.items():
        try:
            update = {}
            flag_mode = False
            flag_tagged = False
            flag_untagged = False
            if info['mode'] != netbox_interfaces[interface]['mode']:
                flag_mode = True
            if info['tagged_vlans'] != netbox_interfaces[interface]['tagged_vlans']:
                flag_tagged = True
            if info['untagged_vlan'] != netbox_interfaces[interface]['untagged_vlan']:
                flag_untagged = True
            if flag_tagged == True or flag_untagged == True or flag_mode ==True:
                update = {'port': interface,
                          'int_id': netbox_interfaces[interface]['int_id']}
                if flag_mode == True:
                    update['mode'] = info['mode']
                if flag_tagged == True:
                    update['tagged_vlans'] = info['tagged_vlans']
                if flag_untagged == True:
                    update['untagged_vlan'] = info['untagged_vlan']
                update_collector.append(update)
        except KeyError:
            logger.error(f'Interface {interface} not found in Netbox')
    return update_collector

def set_netbox_interface(interface):
    """
    Update VLAN information for a single interface in Netbox 
    
    Args:
        interface (dict): VLAN information for one interface
    """
    try:
        int_id = interface.pop('int_id')
        # Replace VLAN ids with their Netbox id if necessary
        if 'untagged_vlan' in interface and interface['untagged_vlan']:
            interface['untagged_vlan'] = netbox_vlan_ids[interface['untagged_vlan']]
        if 'tagged_vlans' in interface and interface['tagged_vlans']:
            interface['tagged_vlans'] = [netbox_vlan_ids[i] for i in interface['tagged_vlans']]
        path = f'/api/dcim/interfaces/{int_id}/'
        url = netbox_base_url + path
        response = requests.patch(url, json=interface, headers=netbox_headers, verify=False)
        response.raise_for_status()
    except Exception as err:
        logger.error(f'Unable to make change, {err}')

def send_log():
    """
    Email log file
    """
    try:
        with open(log_file) as file:
            log_msg = EmailMessage()
            log_msg.set_content(file.read())
        log_msg['Subject'] = f'{netbox_site} VLAN Sync Log'
        log_msg['From'] = os.environ.get('email_from')
        log_msg['To'] = os.environ.get('email_to')
        smtp = smtplib.SMTP(mail_server, timeout=20)
        smtp.send_message(log_msg)
        smtp.quit()
    except Exception as err:
        logger.error(f'Unable to email log, {err}')

# Main body starts here
# Process environment variables and parse arguments
load_dotenv()
local_path = os.path.dirname(__file__)
netbox_base_url = os.environ.get('netbox_url')
mail_server = os.environ.get('mail_server')
log_file = os.path.join(local_path, os.environ.get('log_file'))
netbox_sites = [site.strip() for site in os.environ.get('netbox_sites').split(',')]
os.environ['NET_TEXTFSM'] = os.path.join(local_path, 'templates')
parser = argparse.ArgumentParser()
parser.add_argument('--dryrun', help='do not write changes to Netbox if included', action='store_true')
parser.add_argument('--site', help='Netbox site', choices=[*netbox_sites], default=netbox_sites[0])
args = parser.parse_args()
netbox_site = args.site

# Set logger configuration
logging.basicConfig(level=logging.INFO, filename=log_file, filemode='w', 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.WARNING)

try:
    netbox_headers = {'Accept': 'application/json',
                      'Content-Type': 'application/json',
                      'Authorization': f'Token {os.environ.get('netbox_token')}'}
    switches = get_netbox_devices()
    netbox_vlan_ids = get_netbox_vlans()
except Exception as err:
    logger.error(f'Unable to connect to Netbox, {err}')
    send_log()
    sys.exit(1)

for switch in switches:
    try:
        logger.info(f'Connecting to switch {switch['name']}')
        # Get switch info from EXOS switches
        if switch['platform_id'] == 1:
            exos_headers = exos_auth(switch['ip'])
            switch_interfaces = get_exos_interfaces(switch['ip'], exos_headers)
        # Get switch info from DNOS6 switches
        if switch['platform_id'] == 2:
            switch_interfaces = get_dnos6_interfaces(switch['ip'])
        # Get info from Netbox and compare
        netbox_interfaces = get_netbox_interfaces(switch)
        interface_updates = get_int_updates(netbox_interfaces, switch_interfaces)
        if interface_updates:
            for interface in interface_updates:
                port = interface.pop('port')
                # Generate log message
                log_msg = (f'Setting interface {port} ')
                if 'mode' in interface:
                    log_msg += (f'- {interface['mode'].capitalize()} mode -')
                if 'untagged_vlan' in interface:
                    log_msg += (f'- Untagged VLAN to {interface['untagged_vlan']} -')
                if 'tagged_vlans' in interface:
                    log_msg += (f'- Tagged VLAN to {', '.join(map(str, interface['tagged_vlans'])) or 'None'} -')
                logger.info(log_msg)
                # Update VLAN info in Netbox for each interface if not dry-run
                if not args.dryrun:
                    set_netbox_interface(interface)
        else:
            logger.info('No updates found')
    except (NetmikoAuthenticationException, NetmikoTimeoutException) as err:
        continue
    except Exception as err:
        logger.error(err, exc_info=True)

logger.info('Sync complete')
send_log()