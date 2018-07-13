#!/usr/bin/env python3

"""
Rekall offset finder.

Usage:
    rekall_offset_finder.py [options] <domain> [<url>]

Options:
    -d --debug              Enable debug output
    -u URI, --uri=URI       Specify Libvirt URI [Default: qemu:///system]
    -o --old                Use the old config format
    -h --help               Show this screen.
    --version               Show version.
"""

import sys
import os
import logging
import json
import stat
from io import StringIO
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory

import libvirt
from docopt import docopt
from rekall import plugins, session


NT_KRNL_PDB = ['ntkrnlmp.pdb', 'ntkrpamp.pdb']
SCRIPT_DIR = str(Path(__file__).resolve().parent)

def find_ntoskrnl(version_modules):
    for entry in version_modules:
        e_type = entry[0]
        if e_type == 'r':
            e_data = entry[1]
            if e_data['pdb'] in NT_KRNL_PDB:
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


def format_config(domain, config, old_format=False):
    if not old_format:
        formatted_config = """
%s {
    ostype = "Windows";
    rekall_profile = "%s";
}
""" % (domain, config['rekall_profile'])
    else:
        formatted_config = """
%s {
    ostype = "Windows";
    win_pdbase = %s;
    win_pid = %s;
    win_tasks = %s;
    win_pname = %s;
}
""" % (domain,
        hex(config['win_pdbase']),
        hex(config['win_pid']),
        hex(config['win_tasks']),
        hex(config['win_pname'])
      )
    return formatted_config


def main(args):
    # delete rekall's BasicConfig
    # we want to configure the root logger
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    debug = args['--debug']
    # configure root logger
    log_level = logging.INFO
    if debug:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)
    logging.debug(args)

    domain_name = args['<domain>']
    uri = args['--uri']
    old_format = args['--old']
    url = args['<url>']


    config = None
    if not url:
        # take temporary memory dump
        # we need to create our own tmp_dir
        # otherwise the dumpfile will be owned by libvirt
        # and we don't have the permission to remove it in /tmp
        with TemporaryDirectory() as tmp_dir:
            with NamedTemporaryFile(dir=tmp_dir) as ram_dump:
                # chmod to be r/w by everyone
                # before libvirt takes ownership
                os.chmod(ram_dump.name,
                         stat.S_IRUSR | stat.S_IWUSR |
                         stat.S_IRGRP | stat.S_IWGRP |
                         stat.S_IROTH | stat.S_IWOTH)
                con = libvirt.open(uri)
                domain = con.lookupByName(domain_name)
                # take dump
                logging.info('Dumping %s physical memory to %s', domain.name(),
                             ram_dump.name)
                flags = libvirt.VIR_DUMP_MEMORY_ONLY
                dumpformat = libvirt.VIR_DOMAIN_CORE_DUMP_FORMAT_RAW
                domain.coreDumpWithFormat(ram_dump.name, dumpformat, flags)
                ram_dump.flush()
                # extract offsets
                config = extract_offsets(domain.name(), ram_dump.name)

    else:
        config = extract_offsets(domain_name, url)
    formatted_config = format_config(domain_name, config, old_format)
    logging.info(formatted_config)


if __name__ == '__main__':
    args = docopt(__doc__)
    exit_code = main(args)
    sys.exit(exit_code)
