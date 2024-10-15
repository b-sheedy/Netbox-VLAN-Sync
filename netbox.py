import requests
import re
import json
import urllib3
import os
from pprint import pprint
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings()

base_url = 'https://netbox.calgaryflames.com'
netbox_headers = {'Accept': 'application/json',
           'Content-Type': 'application/json',
           'Authorization': f'Token {os.environ.get('netbox_token')}'}

def get_netbox(path,params):
    url = base_url + path
    response = requests.get(url, params=params, headers=netbox_headers, verify=False)
    return response.json()['results']

def get_netbox_devices():
    path = '/api/dcim/devices/'
    params = {'manufacturer': 'extreme-networks', 'role': 'switch'}
    api_data = get_netbox(path, params)
    collector = {}
    for switch in api_data:
        if switch['virtual_chassis'] == None:
            collector[switch['name']] = {'device_id': switch['id'],
                                         'ip': switch['primary_ip']['address'][:-3]}
        elif switch['vc_position'] == 1:
            collector[switch['name']] = {'device_id': switch['id'],
                                         'vc_id': switch['virtual_chassis']['id'],
                                         'ip': switch['primary_ip']['address'][:-3]}
    return collector

def get_netbox_interfaces(info):
    path = '/api/dcim/interfaces/'
    if info.get('vc_id'):
        params = {'virtual_chassis_id': info['vc_id']}
    else:
        params = {'device_id': info['device_id']}
    api_data = get_netbox(path, params)
    collector = {}
    for interface in api_data:
        if re.search(r'\d:\d+', interface['name']):
            mode = interface['mode']['value'] if interface['mode'] else None
            untagged =  interface['untagged_vlan']['vid'] if interface['untagged_vlan'] else None
            tagged = [vlan['vid'] for vlan in interface['tagged_vlans']]
            collector[interface['name']] = {'int_id': interface['id'],
                                            'mode': mode,
                                            'tagged_vlans': sorted(tagged),
                                            'untagged_vlan': untagged}
    return collector

def exos_auth(ip):
    headers = {'Content-Type': 'application/json',}
    json = {'username': os.environ.get('exos_uname'),
            'password': os.environ.get('exos_pwd')}
    url = f'https://{ip}/auth/token'
    token = requests.post(url, json=json, headers=headers, verify=False).json()['token']
    headers['Cookie'] = f'x-auth-token={token}'
    return headers

switches = get_netbox_devices()
#pprint(switches)

for name, info in switches.items():
    exos_headers = exos_auth(info['ip'])
    netbox_interfaces = get_netbox_interfaces(info)
    pprint(exos_headers)
    pprint(netbox_interfaces)
    break