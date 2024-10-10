import requests
import re
#import json
from pprint import pprint
import urllib3
urllib3.disable_warnings()

def get_netbox(path,params):
    token = '3d84ffc0a07a42c7ee3284ad8fce487f78f1e042'
    url = 'https://netbox.calgaryflames.com' + path
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Authorization': f'Token {token}'}
    response = requests.get(url, params=params, headers=headers, verify=False)
    return response.json()['results']

def get_netbox_devices():
    path = '/api/dcim/devices/'
    params = {'manufacturer': 'extreme-networks', 'role': 'switch'}
    api_data = get_netbox(path, params)
    collector = {}
    for switch in api_data:
        if switch['virtual_chassis'] == None or switch['vc_position'] == 1:
            collector[switch['name']] = {'id': switch['id'],
                                         'ip': switch['primary_ip']['address']}
    return collector

def get_netbox_interfaces(id):
    path = '/api/dcim/interfaces/'
    params = {'device_id': id}
    api_data = get_netbox(path, params)
    collector = {}
    for interface in api_data:
        if re.search(r'\d:\d+', interface['name']):
            collector[interface['name']] = {'id': interface['id'],
                                            'tagged_vlans': interface['tagged_vlans'],
                                            'untagged_vlan': interface['untagged_vlan']}
    return collector


switches = get_netbox_devices()
for name, info in switches.items():
    netbox_interfaces = get_netbox_interfaces(info['id'])

    pprint(netbox_interfaces)
    break