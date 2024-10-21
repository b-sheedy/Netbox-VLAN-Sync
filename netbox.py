import requests
import re
import urllib3
import os
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
    api_data = response.json()['results']
    while response.json()['next'] != None:
        response = requests.get(response.json()['next'], params=params, headers=netbox_headers, verify=False)
        api_data.extend(response.json()['results'])
    return api_data

def get_netbox_devices():
    path = '/api/dcim/devices/'
    params = {'manufacturer': 'extreme-networks', 'role': 'switch'}
    api_data = get_netbox(path, params)
    collector = {}
    for switch in api_data:
        if switch['virtual_chassis'] == None:
            collector[switch['name']] = {'device_id': switch['id'],
                                         'ip': switch['primary_ip']['address'].split('/')[0]}
        elif switch['vc_position'] == 1:
            collector[switch['name']] = {'device_id': switch['id'],
                                         'vc_id': switch['virtual_chassis']['id'],
                                         'ip': switch['primary_ip']['address'].split('/')[0]}
    return collector

def get_netbox_vlans():
    path = '/api/ipam/vlans/'
    params = {'brief': 1, 'site': ['saddledome', 'null']}
    api_data = get_netbox(path, params)
    collector = {}
    for vlan in api_data:
        collector[vlan['vid']] = vlan['id']
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
    try:
        response = requests.post(url, json=json, headers=headers, verify=False)
        response.raise_for_status()
        token = response.json()['token']
        headers['Cookie'] = f'x-auth-token={token}'
        return headers
    except requests.exceptions.RequestException as excpt:
        print(f'Unable to retrieve RESTCONF token, {excpt}')
        raise

def get_exos_interfaces(ip, headers):
    filter = '?filter=$.openconfig-interfaces:interfaces.interface[?(@.state.type == "ethernetCsmacd")]'
    url = f'https://{ip}/rest/restconf/data/openconfig-interfaces:interfaces'
    try:
        response = requests.get(url + filter, headers=headers, verify=False)
        response.raise_for_status()
        collector = {}
        for int in response.json():
            if int['state']['oper-status'] != 'NOT_PRESENT':
                collector[int['name']] = {'mode': int['openconfig-if-ethernet:ethernet']['openconfig-vlan:switched-vlan']['state']['interface-mode'].lower(),
                                        'tagged_vlans': sorted(int['openconfig-if-ethernet:ethernet']['openconfig-vlan:switched-vlan']['state'].get('trunk-vlans', []))}
                if collector[int['name']]['mode'] == 'trunk':
                    collector[int['name']]['mode'] = 'tagged'
                    collector[int['name']]['untagged_vlan'] = int['openconfig-if-ethernet:ethernet']['openconfig-vlan:switched-vlan']['state'].get('native-vlan', None)
                if collector[int['name']]['mode'] == 'access':
                    collector[int['name']]['untagged_vlan'] = int['openconfig-if-ethernet:ethernet']['openconfig-vlan:switched-vlan']['state'].get('access-vlan', None)
        return collector
    except requests.exceptions.RequestException as excpt:
        print(f'Unable to retrieve RESTCONF data, {excpt}')
        raise

def get_int_updates(netbox_interfaces, exos_interfaces):
    collector = []
    for interface, info in exos_interfaces.items():
        update = {}
        flag_tagged = False
        flag_untagged = False
        if info['tagged_vlans'] != netbox_interfaces[interface]['tagged_vlans']:
            flag_tagged = True
        if info['untagged_vlan'] != netbox_interfaces[interface]['untagged_vlan']:
            flag_untagged = True
        if flag_tagged == True or flag_untagged == True:
            update = {'port': interface, 'int_id': netbox_interfaces[interface]['int_id'], 'mode': info['mode']}
            if flag_tagged == True:
                update['tagged_vlans'] = info['tagged_vlans']
            if flag_untagged == True:
                update['untagged_vlan'] = info['untagged_vlan']
            collector.append(update)
    return collector

def set_netbox_interface(int):
    int_id = int.pop('int_id')
    port = int.pop('port')
    print(f'Setting interface {port} untagged VLAN to {int.get('untagged_vlan', 'None')} and tagged VLAN(s) to {int.get('tagged_vlans', 'None')}')
    if 'untagged_vlan' in int:
        int['untagged_vlan'] = netbox_vlan_ids[int['untagged_vlan']]
    if 'tagged_vlans' in int:
        int['tagged_vlans'] = [netbox_vlan_ids[i] for i in int['tagged_vlans']]
    path = f'/api/dcim/interfaces/{int_id}/'
    url = base_url + path
    try:
        response = requests.patch(url, json=int, headers=netbox_headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as excpt:
        print(f'Unable to make change, {excpt}')


switches = get_netbox_devices()
netbox_vlan_ids = get_netbox_vlans()
for name, info in switches.items():
    try:
        print('Connecting to switch', name)
        exos_headers = exos_auth(info['ip'])
        exos_interfaces = get_exos_interfaces(info['ip'], exos_headers)
        netbox_interfaces = get_netbox_interfaces(info)
        interface_updates = get_int_updates(netbox_interfaces, exos_interfaces)
        for int in interface_updates:
            set_netbox_interface(int)
            break
        break
    except:
        break