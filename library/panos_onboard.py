#!/usr/bin/env python

#  Copyright (c) 2019, Palo Alto Networks, Inc
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

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: panos_onboard
short_description: Onboard a new firewall in Panorama
description:
    - Register a firewall serial number with Panorama and assign it to the appropriate Device Group and Template Stack.
author: "Robert Hagen (@stealthllama)"
version_added: "2.7"
requirements:
    - pan-python
    - pandevice
options:
    ip_address:
        description:
            - IP address (or hostname) of the Panorama management console
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
            - the PAN-OS API key
    serialnum:
        description:
            - the serial number of the firewall
        required: true
    devicegroup:
        description:
            - the devicegroup of the firewall
    templatestack:
        description:
            - the template used for the the firewall
    state:
        description:
            - The state of the serial number in Panorama.  Can be either I(present)/I(absent).
        default: 'present'
'''

EXAMPLES = '''
- name: Onboard firewall
  panos_onboard:
    ip_address: panorama.mydomain.internal
    username: admin
    password: S3cr3t!
    serialnum: 007200004214
    devicegroup: Lab Firewalls
    templatestack: Corp Standard
    state: present
'''

RETURN = ''' # '''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import get_exception

try:
    import pan.xapi
    from pandevice.base import PanDevice
    from pandevice.panorama import Panorama, DeviceGroup, TemplateStack
    from pandevice.firewall import Firewall
    from pandevice.errors import PanDeviceError

    HAS_LIB = True
except ImportError:
    HAS_LIB = False


def get_firewall(device, serialnum):
    Firewall.refreshall(device, add=True)
    f = device.find(serialnum)
    return f


def get_devicegroup(device, devicegroup):
    DeviceGroup.refreshall(device, add=True)
    d = device.find(devicegroup)
    return d


def get_templatestack(device, templatestack):
    TemplateStack.refreshall(device, add=True)
    t = device.find(templatestack)
    return t

def listify(t):
    if t.devices is None:
        t.devices = []
    return t


def main():
    argument_spec = dict(
        ip_address=dict(required=True),
        username=dict(default='admin'),
        password=dict(default='admin', no_log=True),
        api_key=dict(no_log=True),
        serialnum=dict(required=True),
        devicegroup=dict(),
        templatestack=dict(),
        state=dict(default='present')
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ['api_key', 'password']
        ]
    )

    if not HAS_LIB:
        module.fail_json(msg='pan-python and pandevice are required for this module')

    serialnum = module.params["serialnum"]
    devicegroup = module.params['devicegroup']
    templatestack = module.params['templatestack']
    state = module.params['state']

    # Get the authentication params
    auth = (
        module.params['ip_address'],
        module.params['username'],
        module.params['password'],
        module.params['api_key'],
    )

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

    # Add to Panorama if not already connected
    fw = get_firewall(device, serialnum)
    if fw is None and state == 'present' and not module.check_mode:
        fw = Firewall(serial=serialnum)
        device.add(fw)
        fw.create()
        changed = True

    # Process the DeviceGroup
    if devicegroup:
        dg = get_devicegroup(device, devicegroup)
        if dg is None:
            module.fail_json(msg="DeviceGroup not found: {0}".format(devicegroup))
        elif dg.find(fw.serial, Firewall) is None and state == 'present' and not module.check_mode:
            dg.add(fw)
            fw.create()
            changed = True
        elif dg.find(fw.serial, Firewall) and state == 'absent' and not module.check_mode:
            dg.remove(dg.find(fw.serial))
            dg.apply()
            changed = True

    # Add to the Template Stack
    if templatestack:
        ts = get_templatestack(device, templatestack)
        if ts is None:
            module.fail_json(msg="TemplateStack not found: {0}".format(templatestack))
        else:
            listify(ts)
        if fw.serial not in ts.devices and state == 'present' and not module.check_mode:
            ts.devices.append(serialnum)
            ts.create()
            changed = True
        elif fw.serial in ts.devices and state == 'absent' and not module.check_mode:
            ts.devices.remove(fw.serial)
            ts.apply()
            changed = True

    # Remove from Panorama
    if (device.find(fw.serial, Firewall)) and (state == 'absent'):
        device.remove(fw)
        device.apply()
        changed = True

    module.exit_json(changed=changed)


if __name__ == '__main__':
    main()
