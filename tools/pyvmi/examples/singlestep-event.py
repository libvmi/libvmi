#!/usr/bin/env python3


import sys
import signal

from libvmi import Libvmi, INIT_DOMAINNAME, INIT_EVENTS
from libvmi.event import SingleStepEvent

from pprint import pprint


# catch SIGINT
# we cannot rely on KeyboardInterrupt when we in
# the call to vmi.listen()
interrupted = False
def signal_handler(signal, frame):
    global interrupted
    interrupted = True

def callback(vmi, event):
    pprint(event.to_dict())
    # increment
    event.data += 1


def main(args):
    if len(args) != 2:
        print('./singlestep-event.py <vm_name>')
        return 1

    vm_name = args[1]

    # register SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    with Libvmi(vm_name, INIT_DOMAINNAME | INIT_EVENTS) as vmi:
        num_vcpus = vmi.get_num_vcpus()
        counter = 0
        ss_event = SingleStepEvent(range(num_vcpus), callback, data=counter)
        vmi.register_event(ss_event)
        # listen
        while not interrupted:
            print("Waiting for events")
            vmi.listen(500)
        print("Stop listening")



if __name__ == '__main__':
    ret = main(sys.argv)
    sys.exit(ret)
