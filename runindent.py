#!/usr/bin/env python
"""
Runs indent over all .c and .h files in libvmi.  This is run such that
the files are not actually changed.  Instead, this will report a failure
if indent would have changed any files.

The idea here is to use this as a tool for developers to see if their
code complies with the style guidelines.  Rather than just reformatting
code automatically, we can show the developers where the problems are
and let the developers take the most appropriate corrective action.

This is the same code that will be used as a gate for PR's on libvmi.
The PR tester will require that this script exists with an exit code
of zero.
"""

import sys
from subprocess import Popen, PIPE


EXCLUSIONS = [
        './config.h',
        '',
        ]


def run_cmd(cmd):
    """ Runs a command and returns stdout.
    """
    return Popen([cmd], shell=True, stdout=PIPE).communicate()[0]


def run_indent_check(filename):
    """ See if the specified file changes when we run indent on it.
    """
    tmpfile = '/tmp/libvmi-indent.tmp'
    run_cmd('indent {0} -o {1}'.format(filename, tmpfile))
    output = run_cmd('diff {0} {1}'.format(filename, tmpfile))
    if output == '':
        return True, None
    else:
        return False, output


def check_files(blob):
    """ Runs indent on the file(s) specified by blob.
    """
    status = True
    problems = {}

    files = run_cmd("find . -iname '{0}' -print".format(blob))
    for filename in files.split('\n'):
        if filename not in EXCLUSIONS:
            tmp_status, output = run_indent_check(filename)
            status = status and tmp_status
            if not tmp_status:
                problems.update({filename: output})
    return status, problems


success1, issues1 = check_files('*.c')
success2, issues2 = check_files('*.h')
success = success1 and success2
issues = dict(issues1.items() + issues2.items())

if success:
    sys.exit(0)
else:
    for item in issues.keys():
        print '---------- {0} ----------'.format(item)
        print issues[item]
        print
    sys.exit(1)
