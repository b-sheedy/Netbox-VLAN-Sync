
# EXOS VLAN Sync to Netbox

This script is intended to get port mode, untagged VLAN and tagged VLAN information from switches running Extreme Networks EXOS/Switch Engine and sync it to a Netbox instance. The list of switches to sync is obtained from Netbox. RESTCONF is used to get the information from the switch and Netbox's REST API is used to sync the information to Netbox.

## Prerequisites

- RESTCONF must be enabled on the switches. Refer to Extreme documentation to do so.
- Switch interfaces should be using slot:port naming scheme (e.g. 1:20), even for a single switch.
- Switches, interfaces and VLANs should be created in Netbox in advance.
- Interface names in Netbox must match switch interface names
- Switches and VLANs must belong to the same site object in Netbox

## Installation

1. Clone repository into a chosen directory.
```
git clone https://github.com/b-sheedy/Netbox-VLAN-Sync.git .
```

2. Create new virtual environment in chosen directory.
```
python3 -m venv .venv
```

3. Activate virtual environment.
```
source .venv/bin/activate
```

4. Install requests and python-dotenv libraries then deactivate virtual environment.
```
pip install requests python-dotenv
deactivate
```

5. Create .env file based on below template. All values are mandatory.
```Dotenv
netbox_token = API token for Netbox
netbox_url = Netbox URL
netbox_sites = Valid site objects in Netbox, first will be default
mail_server = SMTP server for emailing logs
exos_uname = Admin username for switches
exos_pwd = Admin password for switches
log_file = Desired log file name
email_from = From email address for log
email_to = To email address for log
```

6. Modify .env permissions to restrict access to root.
```
chmod 600 .env
```

7. Add script to crontab if desired. Example below will run every day at 1:00 AM.
```
crontab -e
00 01 * * *    /<your path here>/.venv/bin/python    /<your path here>/netbox_vlan_sync.py
```

## Manual Usage

The script can be run manually from within the virtual environment as well.
```
python3 netbox_vlan_sync.py [--dryrun] [--site {a site listed in .env file}]
```

`--dryrun`
Runs and logs potential changes without writing any changes to Netbox.

`--site {a site listed in .env file}`
Filters by specified site when retrieving switches and VLANs from Netbox. Site must be one of those listed in .env file. If not specified, first site listed in .env file will be used as default.

