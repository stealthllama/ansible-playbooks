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

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: panos_commit
short_description: Commit a PAN-OS device's candidate configuration.
description:
    - Module that will commit the candidate configuration of a PAN-OS device.
    - The new configuration will become active immediately.
author:
    - "Michael Richardson (@mrichardson03)"
    - "Robert Hagen (@stealthllama)"
version_added: "2.3"
requirements:
    - pan-python can be obtained from PyPI U(https://pypi.python.org/pypi/pan-python)
    - pandevice can be obtained from PyPI U(https://pypi.python.org/pypi/pandevice)
options:
    ip_address:
        description:
            - IP address or hostname of PAN-OS device.
        required: true
    username:
        description:
            - Username for authentication for PAN-OS device.  Optional if I(api_key) is used.
        default: 'admin'
    password:
        description:
            - Password for authentication for PAN-OS device.  Optional if I(api_key) is used.
    api_key:
        description:
            - API key to be used instead of I(username) and I(password).
    devicegroup:
        description:
            - If I(ip_address) is a Panorama device, perform a commit-all to the devices in this
              device group in addition to commiting to Panorama.
        type: str
    include_template:
        description:
            - If I(ip_address) is a Panorama device, include template changes in this device push.
        type: bool
        default: 'False'
    devices:
        description:
            - If I(ip_address) is a Panorama device, push the specific devices by serial number.
        type: list
'''

EXAMPLES = '''
- name: commit candidate config on firewall
  panos_commit:
    ip_address: '{{ ip_address }}'
    username: '{{ username }}'
    password: '{{ password }}'

- name: commit devicegroup candidate config on Panorama using api_key
  panos_commit:
    ip_address: '{{ ip_address }}'
    api_key: '{{ api_key }}'
    devicegroup: 'Cloud-Edge'
    include_template: True

- name: commit devicegroup config on Panorama to specific devices
  panos_commit:
    ip_address: '{{ ip_address }}'
    api_key: '{{ api_key }}'
    devicegroup: 'Internet FWs'
    devices:
      - 007C0000001
      - 007C0000002
'''

RETURN = '''
# Default return values
'''

try:
    from pandevice.base import PanDevice
    from pandevice.firewall import Firewall
    from pandevice.panorama import Panorama, DeviceGroup, TemplateStack
    from pandevice.errors import PanDeviceError

    HAS_LIB = True
except ImportError:
    HAS_LIB = False

from ansible.module_utils.basic import AnsibleModule


def get_devicegroup(device, devicegroup):
    DeviceGroup.refreshall(device, add=True)
    d = device.find(devicegroup)
    return d


def check_commit_result(module, result):
    if result['result'] == 'FAIL':
        if 'xml' in result:
            result.pop('xml')

        module.fail_json(msg='Commit failed', result=result)


def main():
    argument_spec = dict(
        ip_address=dict(required=True),
        username=dict(default='admin'),
        password=dict(no_log=True),
        api_key=dict(no_log=True),
        devicegroup=dict(type='str'),
        include_template=dict(type='bool', default=False),
        devices=dict(type='list', default=None)
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_one_of=[['api_key', 'password']]
    )

    if not HAS_LIB:
        module.fail_json(msg='pan-python and pandevice are required for this module.')

    # Get the authentication params
    auth = (
        module.params['ip_address'],
        module.params['username'],
        module.params['password'],
        module.params['api_key'],
    )

    # Define local vars
    devicegroup = module.params['devicegroup']
    include_template = module.params['include_template']
    devices = module.params['devices']
    changed = False
    results = []

    try:
        device = PanDevice.create_from_device(*auth)

        if devicegroup:
            if devicegroup.lower() == 'shared':
                devicegroup = None
            else:
                if not get_devicegroup(device, devicegroup):
                    module.fail_json(msg='Could not find {} device group.'.format(devicegroup))

        if isinstance(device, Firewall):
            result = device.commit(sync=True)

            if result:
                check_commit_result(module, result)

                changed = True
                results.append(result)

        elif isinstance(device, Panorama):
            # Panorama commit is two potential steps, one to Panorama itself, and one to the
            # device group.
            result = device.commit(sync=True)

            if result:
                check_commit_result(module, result)

                changed = True
                results.append(result)

            if devicegroup:
                result = device.commit_all(
                    sync=True,
                    sync_all=True,
                    devicegroup=devicegroup,
                    include_template=include_template,
                    serials=devices
                )

                if result:
                    check_commit_result(module, result)

                    changed = True
                    results.append(result)

        # Clean XML out of results becasue Ansible doesn't like it.
        for result in results:
            if 'xml' in result:
                result.pop('xml')

    except PanDeviceError as e:
        module.fail_json(msg=e.message)

    module.exit_json(changed=changed, result=results)


if __name__ == '__main__':
    main()
