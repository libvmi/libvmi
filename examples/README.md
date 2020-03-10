# examples

This folder contains a few examples of code using the LibVMI library.

Note: some of them take an optional `[<socket>]` parameter. This refers to the
`KVMi socket`, which needs to be specified when using the KVM driver.

Not all examples have been modified to accept this `[<socket>]` parameter,
and therefore are not compatible with the new KVM driver.

## breakpoint-emulate-example

Recoiling on a software breakpoint via instruction emulation.

Reads the opcode at the specified location in memory (using the `opcode_size`
parameter) and sets a software breakpoint by writing `int3` interrupt.

When the breakpoint is hit, use the `VMI_EVENT_RESPONSE_SET_EMUL_INSN` event response
to emulate the instruction stored in `event->emul_insn`.

_Note: Not compatible with the new KVM driver_

## cr3-event-example

Intercepts and displays `CR3` events.

## vmi-dump-memory

Dumps the VM's physical memory to the given filepath.

## event-example

A demo of the event API using `MSRs`, `memory access` and `CR3` events.

## interrupt-event-example

A simple interrupt interception example that will display `int3` events.

## map-addr

Display a page in hexadecimal at the given virtual address.

_Note: Not compatible with the new KVM driver_

## map-symbol

Display a page in hexadecimal at the given symbol.

_Note: Not compatible with the new KVM driver_

## mem-event-example

A simple execute memory access interception, configured on the current RIP.

## vmi-module-list

Displays the list of loaded modules, for Windows and linux.

## msr-event-example

A simple MSR event interception.

## vmi-process-list

Displays the VM's process list.

## singlestep-event-example

A simple singlestep event interception. Also demonstrate how to manually toggle the singlestep once enabled.

_Note: Not compatible with the new KVM driver_

## va-pages

Displays the current process page tables upon each `CR3` load.

_Note: Not compatible with the new KVM driver_

## wait-for-domain-example

A Simple example monitoring for domain creation and deletion.

_Note: Not compatible with the new KVM driver_

## vmi-win-guid

Print the `GUID` and the `PE_HEADER` of the Windows kernel.

_Note: Not compatible with the new KVM driver_

## vmi-win-offsets

Displays Windows kernel offsets based on a Rekall profile.

_Note: Not compatible with the new KVM driver_

## xen-emulate-response

Sets an execute memory access trap on a virtual address and emulate the instruction to continue execution.

_Note: Not compatible with the new KVM driver_
