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
extends_documentation_fragment:
    - panos.transitional_provider
options:
    only_connected:
        description:
            - only list the firewalls that are connected to Panorama.
        default: false
'''

EXAMPLES = '''
# Check Panorama for all managed devices
- name: show Panorama devices
  panos_devices:
    provider: '{{ provider }}'


# Check Panorama for only connected devices
- name: show Panorama connected devices
  panos_devices:
    provider: '{{ provider }}'
    only_connected: True
'''

RETURN = '''
# Default return values
'''

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.panos.panos import get_connection

try:
    from pandevice.base import PanDevice
    from pandevice.panorama import Panorama
    from pandevice.firewall import Firewall
    from pandevice.errors import PanDeviceError
except ImportError:
    pass


def main():
    helper = get_connection(
        argument_spec = dict(
            only_connected=dict(default=False)
    )

    module = AnsibleModule(
        argument_spec=helper.argument_spec,
        supports_check_mode=False,
        required_one_of=helper.required_one_of,
    )


    parent = helper.get_pandevice_parent(module)


    # Ensure we're not connected to a firewall
    if isinstance(parent, Firewall):
        module.fail_json(msg='This module is only supported on Panorama instances')

    try:
        devlist = parent.refresh_devices(only_connected=only_connected, include_device_groups=False)
    except PanDeviceError as e:
        module.fail_json(msg='Failed to restart: {0}'.format(e))
    else:
        devices = []
        for x in devlist:
            devices.append(x.serial)
        module.exit_json(changed=False, devices=devices)


if __name__ == '__main__':
    main()
