#!/usr/bin/env python3


import sys
import os
import logging
import re
import json
from io import StringIO
from pathlib import Path

from rekall import plugins, session

NT_KRNL_PDB = 'ntkrnlmp.pdb'
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

def find_ntoskrnl(version_modules):
    for entry in version_modules:
        e_type, e_data = entry[0], entry[1]
        if e_type == 'r' and e_data['pdb'] == NT_KRNL_PDB:
            return (e_data['pdb'], e_data['guid'])
    raise RuntimeError('Cannot find {} with version_modules '
                       'plugin'.format(NT_KRNL_PDB))

def extract_offsets(domain, url):
    s = session.Session(
            filename=url,
            autodetect=["rsds"],
            logger=logging.getLogger(),
            autodetect_build_local='none',
            format='data',
            profile_path=[
                "http://profiles.rekall-forensic.com"
            ])

    strio = StringIO()
    s.RunPlugin("version_modules", output=strio)
    version_modules = json.loads(strio.getvalue())

    pdbase = s.profile.get_obj_offset('_KPROCESS', 'DirectoryTableBase')
    tasks = s.profile.get_obj_offset('_EPROCESS', 'ActiveProcessLinks')
    name = s.profile.get_obj_offset('_EPROCESS', 'ImageFileName')
    pid = s.profile.get_obj_offset('_EPROCESS', 'UniqueProcessId')

    # find ntoskrnl guid
    ntos_pdb, ntos_guid = find_ntoskrnl(version_modules)
    ntos_module = Path(ntos_pdb).stem
    rekall_profile_path = os.path.join(SCRIPT_DIR,
                                       "{}-profile.json".format(domain))

    # create a new session with a text format
    # allowing us to write files
    s = session.Session(
            filename=url,
            autodetect=["rsds"],
            logger=logging.getLogger(),
            autodetect_build_local='none',
            format='text',
            profile_path=[
                "http://profiles.rekall-forensic.com"
            ])
    # build the Rekall JSON profile from PDB
    s.RunPlugin("build_local_profile", module_name=ntos_module,
                guid=ntos_guid, dumpfile=rekall_profile_path)

    config = {
        "ostype": "Windows",
        "win_pdbase": pdbase,
        "win_pid": pid,
        "win_tasks": tasks,
        "win_pname": name,
        "rekall_profile": rekall_profile_path
    }

    return config

def format_config(domain, config):
    formatted_config = """
%s {
    ostype = "Windows";
    rekall_profile = "%s";
}
""" % (domain, config['rekall_profile'])

    # uncomment this if you want to use the old
    # config format, instead of the rekall profile
#     formatted_config = """
# %s {
#     ostype = "Windows";
#     win_pdbase = %s;
#     win_pid = %s;
#     win_tasks = %s;
#     win_pname = %s;
# }
# """ % (domain,
#         hex(config['win_pdbase']),
#         hex(config['win_pid']),
#         hex(config['win_tasks']),
#         hex(config['win_pname'])
#       )
    return formatted_config



if __name__ == '__main__':
    # check args
    if len(sys.argv) != 2:
        print('Usage: ./auto_config.py vmi:///domain')
        print('(alt) Usage: ./auto_config.py vmi://kvm|xen/domain')
        sys.exit(1)

    url = sys.argv[1]
    pattern = 'vmi://((?P<hypervisor>xen|kvm))?/(?P<domain>.*)'
    m = re.match(pattern, url)
    domain = m.group('domain')
    config = extract_offsets(domain, url)
    formatted_config = format_config(domain, config)
    print(formatted_config)
