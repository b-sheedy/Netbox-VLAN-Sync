import requests
import re
import os
import sys
import logging
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

def get_netbox(path,params):
    url = netbox_base_url + path
    response = requests.get(url, params=params, headers=netbox_headers, verify=False)
    response.raise_for_status()
    api_data = response.json()['results']
    while response.json()['next'] != None:
        response = requests.get(response.json()['next'], params=params, headers=netbox_headers, verify=False)
        response.raise_for_status()
        api_data.extend(response.json()['results'])
    return api_data

def get_netbox_devices():
    path = '/api/dcim/devices/'
    params = {'manufacturer': 'extreme-networks', 'role': 'switch', 'site': netbox_site}
    api_data = get_netbox(path, params)
    device_collector = {}
    for switch in api_data:
        if switch['virtual_chassis'] == None or switch['vc_position'] == 1:
            device_collector[switch['name']] = {'device_id': switch['id'],
                                                'ip': switch['primary_ip']['address'].split('/')[0]}
            if switch['vc_position'] == 1:
                device_collector[switch['name']]['vc_id'] = switch['virtual_chassis']['id']
    return device_collector

def get_netbox_vlans():
    path = '/api/ipam/vlans/'
    params = {'brief': 1, 'site': [netbox_site, 'null']}
    api_data = get_netbox(path, params)
    vlan_collector = {}
    for vlan in api_data:
        vlan_collector[vlan['vid']] = vlan['id']
    return vlan_collector

def get_netbox_interfaces(info):
    path = '/api/dcim/interfaces/'
    params = {'enabled': True}
    if 'vc_id' in info:
        params['virtual_chassis_id'] = info['vc_id']
    else:
        params['device_id'] = info['device_id']
    api_data = get_netbox(path, params)
    int_collector = {}
    for interface in api_data:
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
    headers = {'Content-Type': 'application/json'}
    body = {'username': os.environ.get('exos_uname'),
            'password': os.environ.get('exos_pwd')}
    url = f'https://{ip}/auth/token'
    try:
        response = requests.post(url, json=body, headers=headers, verify=False)
        response.raise_for_status()
        headers['Cookie'] = f'x-auth-token={response.json()['token']}'
        return headers
    except requests.exceptions.RequestException as excpt:
        logger.error(f'Unable to retrieve RESTCONF token, {excpt}')
        raise

def get_exos_interfaces(ip, headers):
    filter = '?filter=$.openconfig-interfaces:interfaces.interface[?(@.state.type == "ethernetCsmacd")]'
    url = f'https://{ip}/rest/restconf/data/openconfig-interfaces:interfaces'
    try:
        response = requests.get(url + filter, headers=headers, verify=False)
        response.raise_for_status()
        int_collector = {}
        for int in response.json():
            if int['state']['oper-status'] != 'NOT_PRESENT':
                int_state = int['openconfig-if-ethernet:ethernet']['openconfig-vlan:switched-vlan']['state']
                int_collector[int['name']] = {'mode': int_state['interface-mode'].lower(),
                                              'tagged_vlans': sorted(int_state.get('trunk-vlans', []))}
                if int_collector[int['name']]['mode'] == 'trunk':
                    int_collector[int['name']]['mode'] = 'tagged'
                    int_collector[int['name']]['untagged_vlan'] = int_state.get('native-vlan', None)
                if int_collector[int['name']]['mode'] == 'access':
                    int_collector[int['name']]['untagged_vlan'] = int_state.get('access-vlan', None)
        return int_collector
    except requests.exceptions.RequestException as excpt:
        logger.error(f'Unable to retrieve RESTCONF data, {excpt}')
        raise

def get_int_updates(netbox_interfaces, exos_interfaces):
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
    int_id = int.pop('int_id')
    port = int.pop('port')
    logger.info(f'Setting interface {port} untagged VLAN to {int.get('untagged_vlan', 'None')} and tagged VLAN(s) to {int.get('tagged_vlans', 'None')}')
    if 'untagged_vlan' in int:
        int['untagged_vlan'] = netbox_vlan_ids[int['untagged_vlan']]
    if 'tagged_vlans' in int:
        int['tagged_vlans'] = [netbox_vlan_ids[i] for i in int['tagged_vlans']]
    path = f'/api/dcim/interfaces/{int_id}/'
    url = netbox_base_url + path
    try:
        response = requests.patch(url, json=int, headers=netbox_headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as excpt:
        logger.error(f'Unable to make change, {excpt}')

def send_log():
    with open(log_file) as file:
        log_msg = EmailMessage()
        log_msg.set_content(file.read())
    log_msg['Subject'] = 'VLAN Sync Log'
    log_msg['From'] = os.environ.get('email_from')
    log_msg['To'] = os.environ.get('email_to')
    smtp = smtplib.SMTP(mail_server)
    smtp.send_message(log_msg)
    smtp.quit()


netbox_base_url = os.environ.get('netbox_url')
mail_server = os.environ.get('mail_server')
log_file = os.environ.get('log_file')
netbox_site = os.environ.get('netbox_site')

logging.basicConfig(level=logging.INFO, filename=log_file, filemode='w', 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

netbox_headers = {'Accept': 'application/json',
                  'Content-Type': 'application/json',
                  'Authorization': f'Token {os.environ.get('netbox_token')}'}

try:
    switches = get_netbox_devices()
    netbox_vlan_ids = get_netbox_vlans()
except Exception as excpt:
    logger.error(f'Unable to connect to Netbox, {excpt}', exc_info=True)
    send_log()
    sys.exit(1)

for name, info in switches.items():
    try:
        logger.info(f'Connecting to switch {name}')
        exos_headers = exos_auth(info['ip'])
        exos_interfaces = get_exos_interfaces(info['ip'], exos_headers)
        netbox_interfaces = get_netbox_interfaces(info)
        interface_updates = get_int_updates(netbox_interfaces, exos_interfaces)
        if interface_updates:
            for int in interface_updates:
                set_netbox_interface(int)
            break
        else:
            logger.info('No updates found')
            break
    except Exception as excpt:
        logger.error(excpt, exc_info=True)
        break

logger.info('Sync complete')
send_log()