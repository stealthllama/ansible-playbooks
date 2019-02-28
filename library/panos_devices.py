#!/usr/bin/env python

#  Copyright 2019 Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

DOCUMENTATION = '''
---
module: panos_devices
short_description: List the PAN-OS devices managed by Panorama
description:
    - List the PAN-OS devices managed by Panorama
author: "Robert Hagen (@stealthllama)"
version_added: "2.7"
requirements:
    - pan-python
    - pandevice
options:
    ip_address:
        description:
            - IP address (or hostname) of PAN-OS device
        required: true
    username:
        description:
            - username for authentication
        default: "admin"
    password:
        description:
            - password for authentication
    api_key:
        description:
            - API key to be used instead of I(username) and I(password).
    only_connected:
        description:
            - only list the firewalls that are connected to Panorama.
        default: false
'''

EXAMPLES = '''
# Check Panorama for all managed devices
- name: check if ready
  panos_check:
    ip_address: '{{ panorama_hostname }}'
    username: '{{ panorama_username }}'
    password: '{{ panorama_password }}'

# Check Panorama for only connected devices
- name: check if ready
  panos_check:
    ip_address: '{{ panorama_hostname }}'
    api_key: '{{ panorama_key }}'
    only_connected: True
'''

RETURN = '''
# Default return values
'''

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import get_exception

try:
    from pandevice.base import PanDevice
    from pandevice.panorama import Panorama
    from pandevice.firewall import Firewall
    from pandevice.errors import PanDeviceError

    HAS_LIB = True
except ImportError:
    HAS_LIB = False


def main():
    # Initialize the module vars
    argument_spec = dict(
        ip_address=dict(required=True),
        username=dict(default='admin'),
        password=dict(no_log=True),
        api_key=dict(no_log=True),
        only_connected=dict(default=False)
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        mutually_exclusive=[
            ['api_key', 'password']
        ]
    )
    auth = (
        module.params["ip_address"],
        module.params['username'],
        module.params["password"],
        module.params["api_key"]
    )
    only_connected = module.params["only_connected"]

    # Fail if the requirements are not installed
    if not HAS_LIB:
        module.fail_json(msg='pan-python and pandevice are required for this module')

    # Open the connection to the PAN-OS device
    device = None
    try:
        device = PanDevice.create_from_device(*auth)
    except PanDeviceError:
        e = get_exception()
        module.fail_json(msg=e.message)

    # Ensure we're not connected to a firewall
    if isinstance(device, Firewall):
        module.fail_json(msg='This module is only supported on Panorama instances')

    # Set our change flag
    changed = False

    try:
        devlist = device.refresh_devices(only_connected=only_connected, include_device_groups=False)
    except PanDeviceError:
        e = get_exception()
        module.fail_json(msg=e.message)
    else:
        devices = []
        for x in devlist:
            devices.append(x.serial)
        module.exit_json(changed=changed, devices=devices)


if __name__ == '__main__':
    main()
