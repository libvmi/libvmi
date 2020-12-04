/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Mathieu Tarral (mathieu.tarral@ssi.gouv.fr)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>

#include <bddisasm/disasmtypes.h>
#include <bddisasm/bddisasm.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <glib.h>

// maximum size of an x86 instruction
#define MAX_SIZE_X86_INSN 15
#define KISERVICE_ENTRY_SIZE sizeof(uint32_t)

// x86 breakpoint opcode
static uint8_t x86_bp[] = { 0xCC };

// These definitions are required by libbddisasm
int nd_vsnprintf_s(
    char *buffer,
    size_t sizeOfBuffer,
    size_t count,
    const char *format,
    va_list argptr
)
{
    (void)count;
    return vsnprintf(buffer, sizeOfBuffer, format, argptr);
}

void* nd_memset(void *s, int c, size_t n)
{
    return memset(s, c, n);
}

// free helper for ghastable
void free_gint64(gpointer p)
{
    g_slice_free(gint64, p);
}

// Data struct to define a breakpointed syscall
typedef struct _bp_syscall {
    // did we managed to breakpoint this syscall
    bool present;
    // syscall virtual address
    addr_t syscall_addr;
    // syscall physical address
    addr_t syscall_paddr;
    // syscall gfn
    addr_t syscall_gfn;
    // syscall number
    unsigned int syscall_number;
    // saved opcode to be emulated
    emul_insn_t emul_insn;
    emul_read_t emul_read;
    // instruction as string
    char insn_str[ND_MIN_BUF_SIZE];
} bp_syscall_t;

// Data struct to be passed as void* to the callback
typedef struct _mem_cb_data {
    bool is64;
    // breakpointed ssdt context
    bp_syscall_t* bp_ssdt;
    // number of entries in ssdt
    unsigned int nb_services;
    // hash [gfn] -> [syscall list]
    GHashTable* hash_gfn_to_syscalls;
} mem_cb_data_t;

// Data struct to pass a context to the breakpoint callback
typedef struct _bp_cb_data {
    // hash [syscall address: addr_t] -> [breakpoint context: bp_syscall_t*]
    GHashTable* hash_syscall_to_ctxt;
} bp_cb_data_t;

// Data stuct to define a memory range or zone
typedef struct _range {
    addr_t start;
    addr_t end;
    size_t size;
} range_t;

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

bool is_zone_read(range_t *ref, range_t *target, range_t *overlap)
{
    // this function checks whether the target zone is contained in the ref zone
    // and fills an overlap range_t struct if necessary
    if (!ref || !target || !overlap)
        return false;

    if (ref->start < target->end && ref->end > target->start) {
        // overlap
        // find range
        // max(ref->start, target->start)
        // min(ref->end, target->end)
        overlap->start = (ref->start > target->start) ? ref->start : target->start;
        overlap->end = (ref->end < target->end) ? ref->end : target->end;
        overlap->size = overlap->end - overlap->start;
        return true;
    }
    return false;
}

bool mem_access_size_from_insn(INSTRUX *insn, size_t *size)
{
    // This function returns the memory access size of a given insn

    char insn_str[ND_MIN_BUF_SIZE];
    // checks that the insn is a memory access
    if (!(insn->MemoryAccess & ND_ACCESS_ANY_READ)) {
        NdToText(insn, 0, sizeof(insn_str), insn_str);
        fprintf(stderr, "bddisasm: Access is not read. Insn: %s\n", insn_str);
        return false;
    }

    switch (insn->Instruction) {
        case ND_INS_MOVZX:  // fall-through
        case ND_INS_MOVSXD: // fall-through
        case ND_INS_MOV: {
            *size = insn->Operands[0].Size;
            break;
        }
        case ND_INS_XOR: {
            *size = insn->Operands[0].Size;
            break;
        }
        case ND_INS_JMPE: {
            *size = insn->Operands[0].Size;
            break;
        }
        default:
            // display instruction
            NdToText(insn, 0, sizeof(insn_str), insn_str);
            fprintf(stderr, "Unimplemented insn: %s\n", insn_str);
            return false;
    }

    return true;
}

event_response_t breakpoint_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    (void)vmi;  // unused
    event_response_t rsp = VMI_EVENT_RESPONSE_NONE;
    interrupt_event_t* int_event = &event->interrupt_event;
    bp_cb_data_t* cb_data = event->data;
    if (!cb_data) {
        fprintf(stderr, "No callback data received in %s\n", __func__);
        return rsp;
    }
    // set default reinject behavior ("pass-through")
    int_event->reinject = 1;

    printf("[%d] Breakpoint hit at 0x%"PRIx64"\n", event->vcpu_id, int_event->gla);
    // get breakpoint ctxt
    bp_syscall_t* bp_syscall = (bp_syscall_t*)g_hash_table_lookup(cb_data->hash_syscall_to_ctxt, &int_event->gla);
    if (!bp_syscall) {
        // not our breakpoint
        // reinject interrupt
        printf("\tReinjecting breakpoint\n");
        // (or issue with GHashTable insertion)
        return rsp;
    }
    printf("\tSyscall %d:\n", bp_syscall->syscall_number);
    printf("\t\tEmulating insn: %s\n", bp_syscall->insn_str);

    // don't reinject
    event->interrupt_event.reinject = 0;
    // set previous opcode for emulation
    event->emul_insn = &bp_syscall->emul_insn;
    // set response to emulate instruction
    rsp |= VMI_EVENT_RESPONSE_SET_EMUL_INSN;

    return rsp;
}

event_response_t cb_on_rw_access(vmi_instance_t vmi, vmi_event_t *event)
{
    (void)vmi;
    mem_cb_data_t *cb_data = (mem_cb_data_t*)event->data;
    mem_access_event_t* mem_event = &event->mem_event;
    event_response_t rsp = VMI_EVENT_RESPONSE_NONE;

    char str_access[4] = {'_', '_', '_', '\0'};
    if (mem_event->out_access & VMI_MEMACCESS_R) str_access[0] = 'R';
    if (mem_event->out_access & VMI_MEMACCESS_W) str_access[1] = 'W';
    if (mem_event->out_access & VMI_MEMACCESS_X) str_access[2] = 'X';
    (void)str_access;

    // Debug
    // printf("%s: %s access at 0x%"PRIx64", on frame 0x%"PRIx64", at offset 0x%"PRIx64", generated by insn at 0x%"PRIx64"\n",
    //        __func__, str_access, event->mem_event.gla, event->mem_event.gfn, event->mem_event.offset, event->x86_regs->rip);

    // read ?
    if (!(mem_event->out_access & VMI_MEMACCESS_R)) {
        // not a read event. skip.
        return rsp;
    }

    // get [gfn] -> [syscall list]
    GSList* syscall_list = (GSList*)g_hash_table_lookup(cb_data->hash_gfn_to_syscalls, &mem_event->gfn);
    if (!syscall_list) {
        fprintf(stderr, "No syscalls associated with GFN 0x%"PRIx64"\n", mem_event->gfn);
        return rsp;
    }

    // read a buffer of an x86 insn max size at RIP (15 Bytes)
    uint8_t insn_buffer[MAX_SIZE_X86_INSN] = {0};
    size_t bytes_read = 0;
    if (VMI_FAILURE == vmi_read_va(vmi, event->x86_regs->rip, 0, MAX_SIZE_X86_INSN, insn_buffer, &bytes_read)) {
        fprintf(stderr, "Failed to read buffer at RIP\n");
        return rsp;
    }

    // check bytes_read
    if (bytes_read != MAX_SIZE_X86_INSN) {
        fprintf(stderr, "Failed to read enough bytes at RIP\n");
        return rsp;
    }

    // disassemble next instruction with libbdisasm
    uint8_t defcode = ND_CODE_32;
    uint8_t defdata = ND_DATA_32;
    if (cb_data->is64) {
        defcode = ND_CODE_64;
        defdata = ND_DATA_64;
    }

    INSTRUX rip_insn;
    NDSTATUS status = NdDecodeEx(&rip_insn, insn_buffer, sizeof(insn_buffer), defcode, defdata);
    if (!ND_SUCCESS(status)) {
        fprintf(stderr, "Failed to decode instruction with libbdisasm: %x\n", status);
        return rsp;
    }

    // determine memory access size
    size_t access_size = 0;
    if (!mem_access_size_from_insn(&rip_insn, &access_size)) {
        // emulate and return
        rsp |= VMI_EVENT_RESPONSE_EMULATE;
        return rsp;
    }
    // Debug
    // printf("Read access size: %ld\n", access_size);

    // find read guest physical addr
    addr_t read_paddr = 0;
    if (VMI_FAILURE == vmi_translate_kv2p(vmi, event->mem_event.gla, &read_paddr)) {
        fprintf(stderr, "Failed to translate read virtual address\n");
        return rsp;
    }

    range_t read_zone = {
        .start = read_paddr,
        .size = access_size,
        .end = read_paddr + access_size
    };

    // iterate over syscall list to find out if the read access could fetch the breakpoints we inserted
    for (GSList* cur_item = syscall_list; cur_item; cur_item = g_slist_next(cur_item)) {
        bp_syscall_t* bp_syscall = (bp_syscall_t*)cur_item->data;
        // check if zones are overlapping
        range_t syscall_bp_zone = {
            .start = bp_syscall->syscall_paddr,
            .size = sizeof(x86_bp),
            .end = bp_syscall->syscall_paddr + sizeof(x86_bp)
        };
        range_t overlap = {0};
        if (is_zone_read(&read_zone, &syscall_bp_zone, &overlap)) {
            // overlap !
            // get insn string
            char insn_str[ND_MIN_BUF_SIZE];
            NdToText(&rip_insn, 0, sizeof(insn_str), insn_str);
            printf("Read on syscall %d (size: %ld)\n", bp_syscall->syscall_number, overlap.size);
            printf("\t0x%"PRIx64": %s\n", event->x86_regs->rip, insn_str);

            // assume PatchGuard if read with a XOR
            if (rip_insn.Instruction == ND_INS_XOR) {
                printf("\tXOR read: Patchguard check !\n");
            }

            // read actual buffer at from physical memory
            bytes_read = 0;
            if (VMI_FAILURE == vmi_read_pa(vmi, read_zone.start, access_size, &bp_syscall->emul_read.data, &bytes_read)) {
                fprintf(stderr, "Failed to read buffer from read start paddr\n");
                return rsp;
            }

            if (bytes_read != access_size) {
                fprintf(stderr, "Failed to read enough bytes\n");
                return rsp;
            }
            // overwrite part of the read buffer to hide
            int overwrite_start = overlap.start - read_zone.start;
            memcpy(&bp_syscall->emul_read.data + overwrite_start, &bp_syscall->emul_insn.data, sizeof(x86_bp));
            // assign emul_read ptr
            event->emul_read = &bp_syscall->emul_read;
            printf("\tEmulated read content:\n");
            for (size_t i = 0; i < bp_syscall->emul_read.size; i++) {
                printf("\t\t0x%"PRIx64": %02X\n", read_zone.start + i, bp_syscall->emul_read.data[i]);
            }
            // set response to emulate read data
            rsp |= VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA;
        }
    }

    rsp |= VMI_EVENT_RESPONSE_EMULATE;
    return rsp;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    struct sigaction act = {0};
    vmi_init_data_t *init_data = NULL;
    int retcode = 1;
    // whether our Windows guest is 64 bits
    bool is64 = false;
    // our breakpointed ssdt
    bp_syscall_t* bp_ssdt = NULL;
    // hash [syscall addr: addr_t] -> [syscall breakpoint context: bp_syscall_t*]
    // used in breakpoint callback to find the syscall context
    GHashTable* hash_syscall_to_ctxt = g_hash_table_new_full(g_int64_hash, g_int64_equal, free_gint64, NULL);
    // hash [gfn: addr_t] -> [syscall_list: GSList*]
    // used in memory read/write callback to search if a syscall's modified code might have been read
    GHashTable* hash_gfn_to_syscalls = g_hash_table_new_full(g_int64_hash, g_int64_equal, free_gint64, NULL);
    addr_t nb_services = 0;

    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    char *name = NULL;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <name of VM> <32|64> [<socket>]\n", argv[0]);
        return retcode;
    }

    // Arg 1 is the VM name.
    name = argv[1];
    // Arg 2 is the guest architecture
    char* arch = argv[2];

    // whether guest is 64 bits
    if (!strncmp(arch, "64", 2)) {
        is64 = true;
    } else if (!strncmp(arch, "32", 2)) {
        is64 = false;
    } else {
        fprintf(stderr, "Usage: %s <name of VM> <32|64> [<socket>]\n", argv[0]);
        return retcode;
    }

    // bddisasm settings
    uint8_t defcode = ND_CODE_32;
    uint8_t defdata = ND_DATA_32;
    if (is64) {
        defcode = ND_CODE_64;
        defdata = ND_DATA_64;
    }

    if (argc == 4) {
        char *path = argv[3];

        // fill init_data
        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(path);
    }

    // Initialize the libvmi library.
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data,
                              VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        goto error_exit;
    }

    printf("LibVMI init succeeded!\n");
    uint8_t addr_width = vmi_get_address_width(vmi);
    if (addr_width == sizeof(uint64_t))
        is64 = true;

    // pause
    printf("Pausing VM\n");
    if (VMI_FAILURE == vmi_pause_vm(vmi)) {
        fprintf(stderr, "Failed to pause vm\n");
        goto error_exit;
    }

    // read nt!KeServiceDescriptorTable
    addr_t ke_sd_table_addr = 0;
    if (VMI_FAILURE == vmi_translate_ksym2v(vmi, "KeServiceDescriptorTable", &ke_sd_table_addr)) {
        fprintf(stderr, "Failed to translate KeServiceDescriptorTable symbol\n");
        goto error_exit;
    }
    printf("nt!KeServiceDescriptorTable: 0x%" PRIx64 "\n", ke_sd_table_addr);

    // read nt!KiServiceTable
    addr_t ki_sv_table_addr = 0;
    if (VMI_FAILURE == vmi_translate_ksym2v(vmi, "KiServiceTable", &ki_sv_table_addr)) {
        fprintf(stderr, "Failed to translate KiServiceTable symbol\n");
        goto error_exit;
    }
    printf("nt!KiServiceTable: 0x%" PRIx64 "\n", ki_sv_table_addr);

    /*
     * Table's structure looks like the following
     * (source: https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/ssdt-hook)

        struct SSDTStruct
        {
            LONG* pServiceTable;
            PVOID pCounterTable;
        #ifdef _WIN64
            ULONGLONG NumberOfServices;
        #else
            ULONG NumberOfServices;
        #endif
            PCHAR pArgumentTable;
        };
    */

    //  read NumberOfServices
    addr_t nb_services_addr = ke_sd_table_addr + (addr_width * 2);
    if (VMI_FAILURE == vmi_read_addr_va(vmi, nb_services_addr, 0, &nb_services)) {
        fprintf(stderr, "Failed to read SSDT.NumberOfServices field\n");
        goto error_exit;
    }
    printf("SSDT.NumberOfServices: %lu (0x%" PRIX64 ")\n", nb_services, nb_services);

    bp_ssdt = calloc(nb_services, sizeof(bp_syscall_t));
    if (!bp_ssdt) {
        fprintf(stderr, "calloc failed\n");
        goto error_exit;
    }

    // protect future breakpointed syscalls from Patchguard using generic mem event
    vmi_event_t read_event = {0};
    SETUP_MEM_EVENT(&read_event, 0, VMI_MEMACCESS_RW, cb_on_rw_access, 1);
    // add cb_data
    mem_cb_data_t cb_data = {0};
    cb_data.is64 = is64;
    cb_data.nb_services = nb_services;
    cb_data.hash_gfn_to_syscalls = hash_gfn_to_syscalls;
    cb_data.bp_ssdt = bp_ssdt;
    // set event callback data
    read_event.data = (void*)&cb_data;

    printf("Registering generic read event\n");
    if (VMI_FAILURE == vmi_register_event(vmi, &read_event)) {
        fprintf(stderr, "Failed to register event\n");
        goto error_exit;
    }

    for (unsigned int i = 0; i < nb_services; i++) {
        addr_t ki_service_entry_addr = ki_sv_table_addr + (KISERVICE_ENTRY_SIZE * i);
        uint32_t ki_service_entry_val = 0;
        if (VMI_FAILURE == vmi_read_32_va(vmi, ki_service_entry_addr, 0, &ki_service_entry_val)) {
            fprintf(stderr, "Failed to read syscall address\n");
            goto error_exit;
        }
        // 32 bits: KiServiceTable entries are absolute addresses to the syscall handlers
        addr_t syscall_addr = ki_service_entry_val;
        // 64 bits: KiServiceTable entries are offsets
        //      https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/glimpse-into-ssdt-in-windows-x64-kernel
        //      RoutineAbsoluteAddress = KiServiceTableAddress + ( routineOffset >>> 4 )
        if (is64) {
            syscall_addr = ki_sv_table_addr + (ki_service_entry_val >> 4);
        }

        // check if syscall is already in hashtable
        if (g_hash_table_lookup(hash_syscall_to_ctxt, &syscall_addr)) {
            printf("[%d] Already breakpointed (0x%"PRIx64")\n", i, syscall_addr);
            continue;
        }

        bp_syscall_t* bp_syscall = calloc(1, sizeof(bp_syscall_t));
        if (!bp_syscall) {
            fprintf(stderr,"Failed to allocate memory\n");
            goto error_exit;
        }
        bp_syscall->emul_insn.dont_free = 1;
        bp_syscall->syscall_number = i;
        bp_syscall->emul_read.dont_free = 1;

        // translate to physical address
        if (VMI_FAILURE == vmi_translate_kv2p(vmi, syscall_addr, &bp_syscall->syscall_paddr)) {
            fprintf(stderr, "Failed to translate syscall vaddr\n");
            free(bp_syscall);
            goto error_exit;
        }
        // set gfn
        bp_syscall->syscall_gfn = bp_syscall->syscall_paddr >> 12;

        // get syscall list for this GFN and add
        // [gfn] -> [syscall list]
        GSList* syscall_list = g_hash_table_lookup(hash_gfn_to_syscalls, &bp_syscall->syscall_gfn);
        // insert element in list
        syscall_list = g_slist_append(syscall_list, (gpointer)bp_syscall);
        // (re)insert in hashtable (list head may have changed)
        g_hash_table_insert(hash_gfn_to_syscalls, g_slice_dup(addr_t, &bp_syscall->syscall_gfn), syscall_list);

        // watch this gfn
        if (VMI_FAILURE == vmi_set_mem_event(vmi, bp_syscall->syscall_gfn, VMI_MEMACCESS_RW, 0)) {
            fprintf(stderr, "Failed to add GFN 0x%"PRIx64" to watch list\n", bp_syscall->syscall_gfn);
            free(bp_syscall);
            goto error_exit;
        }

        // read max size x86 insn
        uint8_t insn_buffer[15];
        if (VMI_FAILURE == vmi_read_va(vmi, syscall_addr, 0, sizeof(insn_buffer), insn_buffer, NULL)) {
            fprintf(stderr, "Failed to read at addr 0x%"PRIx64"\n", syscall_addr);
            continue;
        }

        // disassemble insn
        INSTRUX insn = {0};
        NDSTATUS status = NdDecodeEx(&insn, insn_buffer, sizeof(insn_buffer), defcode, defdata);
        if (!ND_SUCCESS(status)) {
            fprintf(stderr, "Failed to decode instruction with bddisasm: %x\n", status);
            free(bp_syscall);
            continue;
        }

        // convert insn to string
        NdToText(&insn, 0, sizeof(bp_syscall->insn_str), bp_syscall->insn_str);

        // copy first insn in emulation buffer
        memcpy(bp_syscall->emul_insn.data, insn_buffer, insn.Length);

        // insert breakpoint
        printf("[%d] Insert breakpoint at 0x%"PRIx64"\n", i, syscall_addr);
        if (VMI_FAILURE == vmi_write_va(vmi, syscall_addr, 0, sizeof(x86_bp), x86_bp, NULL)) {
            fprintf(stderr, "Failed to write breakpoint for syscall index %d\n", i);
            free(bp_syscall);
            continue;
        }
        bp_ssdt[i].present = true;
        bp_ssdt[i].syscall_addr = syscall_addr;

        // add to hash
        if (!g_hash_table_insert(hash_syscall_to_ctxt, g_slice_dup(addr_t, &syscall_addr), bp_syscall)) {
            fprintf(stderr, "Duplicated entry in GHashTable\n");
            goto error_exit;
        }
    }

    // flush LibVMI page cache after write
    vmi_pagecache_flush(vmi);

    // register int3 interrupt callback
    vmi_event_t bp_event = {0};
    SETUP_INTERRUPT_EVENT(&bp_event, breakpoint_cb);
    // pass cb data
    bp_cb_data_t bp_cb_data = { .hash_syscall_to_ctxt = hash_syscall_to_ctxt  };
    bp_event.data = &bp_cb_data;
    if (VMI_FAILURE == vmi_register_event(vmi, &bp_event)) {
        fprintf(stderr, "Failed to register breakpoint event\n");
        goto error_exit;
    }



    // resume
    printf("Resuming VM\n");
    if (VMI_FAILURE == vmi_resume_vm(vmi)) {
        fprintf(stderr, "Failed to continue VM\n");
        goto error_exit;
    }
    printf("Waiting for events...\n");
    while (!interrupted) {
        if (VMI_FAILURE == vmi_events_listen(vmi,500)) {
            fprintf(stderr, "Failed to listen on VMI events\n");
            goto error_exit;
        }
    }
    printf("Finished with test.\n");

    retcode = 0;
error_exit:
    // restore ssdt
    vmi_pause_vm(vmi);
    for (unsigned int i=0; i < nb_services; i++) {
        if (bp_ssdt && bp_ssdt[i].present) {
            if (VMI_FAILURE == vmi_write_va(vmi, bp_ssdt[i].syscall_addr, 0, sizeof(x86_bp), bp_ssdt[i].emul_insn.data, NULL)) {
                fprintf(stderr, "[%d] Failed to restore syscall opcode\n", i);
                continue;
            }
        }
    }

    vmi_clear_event(vmi, &bp_event, NULL);
    vmi_clear_event(vmi, &read_event, NULL);

    vmi_resume_vm(vmi);
    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    if (hash_syscall_to_ctxt) {
        g_hash_table_destroy(hash_syscall_to_ctxt);
    }

    if (hash_gfn_to_syscalls) {
        // free lists
        g_hash_table_destroy(hash_gfn_to_syscalls);
    }

    if (bp_ssdt) {
        free(bp_ssdt);
    }

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}
