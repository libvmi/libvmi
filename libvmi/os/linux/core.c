/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
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

#include "private.h"
#include "config/config_parser.h"
#include "driver/driver_wrapper.h"
#include "os/linux/linux.h"


void linux_read_config_ghashtable_entries(char* key, gpointer value,
        vmi_instance_t vmi);

static status_t init_task_kaslr_test(vmi_instance_t vmi, addr_t page_vaddr);

static status_t init_kaslr(vmi_instance_t vmi);

static status_t brute_force_find_kern_mem (vmi_instance_t vmi);

static status_t verify_linux_paging (vmi_instance_t vmi);

/*
 * Heuristic test to determine whether the memory at the given
 * physical address looks like an Intel x64 page directory structure.
 * Specifically we want PML4 directories.
*/
static bool is_x86_64_pd (vmi_instance_t vmi, addr_t pa)
{
    bool rc = false;
    status_t status = VMI_FAILURE;
    size_t i = 0;

#define PD_ENTRIES (VMI_PS_4KB / sizeof(uint64_t))
    uint64_t pdes[PD_ENTRIES];
    addr_t maxframe = vmi_get_max_physical_address (vmi) >> 12;

    status = vmi_read_pa (vmi, pa, sizeof(pdes), (void *)pdes, NULL);
    if (VMI_FAILURE == status)
        goto exit;

    for (i = 0; i < PD_ENTRIES; ++i) {
        uint64_t pde = pdes[i];

        if (VMI_GET_BIT (pde, 7) || VMI_GET_BIT (pde, 63) ) {
            /* ... reserved bit 7 or XD3 bit is asserted so reject entire page immediately */
            rc = false;
            goto exit;
        }

        /* Any test on the GFN requires that P=1 */
        if (!(VMI_GET_BIT (pde, 0)))
            continue;

        /* P = 1, and ... */

        addr_t gfn = pde >> 12;

        if (0 == gfn || gfn > maxframe) {
            /* ... this is not a valid GFN, so fail the whole page.  */
            rc = false;
            goto exit;
        }

        /* ... the page has a valid-looking PDE, so for now, it passes. */
        rc = true;
    }

exit:
    return rc;
}

/*
 * Identifies page directories in memory. This saves multiple minutes
 * off a brute force search for the KPDB and KASLR offset.
 */
static GSList * find_page_directories (vmi_instance_t vmi)
{
    GSList * list = NULL;
    addr_t candidate = 0;
    int count = 0;

    if (VMI_PM_IA32E != vmi_get_page_mode (vmi, 0))
        goto exit;

    for (candidate = 0x1000; candidate < vmi_get_max_physical_address (vmi); candidate += VMI_PS_4KB) {
        if (is_x86_64_pd (vmi, candidate)) {
            /* hold addr in dynamic storage: 32-bit libvmi could be analyzing 64 bit OS */
            addr_t * addr = g_malloc(sizeof(addr_t));
            *addr = candidate;
            list = g_slist_prepend (list, (gpointer) addr);
            ++count;
        }
    }

exit:
    dbprint(VMI_DEBUG_MISC, "**found %d potential page directories\n", count);
    return list;
}

static status_t linux_filemode_32bit_init(vmi_instance_t vmi,
        addr_t swapper_pg_dir,
        addr_t boundary,
        addr_t pa, addr_t va)
{
    addr_t test = 0;
    vmi->page_mode = VMI_PM_LEGACY;
    if (VMI_SUCCESS == arch_init(vmi)) {
        if ( VMI_SUCCESS == vmi_pagetable_lookup(vmi, swapper_pg_dir - boundary, va, &test) &&
                test == pa) {
            vmi->kpgd = swapper_pg_dir - boundary;
            return VMI_SUCCESS;
        }
    }

    vmi->page_mode = VMI_PM_PAE;
    if (VMI_SUCCESS == arch_init(vmi)) {
        if ( VMI_SUCCESS == vmi_pagetable_lookup(vmi, swapper_pg_dir - boundary, va, &test) &&
                test == pa) {
            vmi->kpgd = swapper_pg_dir - boundary;
            return VMI_SUCCESS;
        }
    }

    vmi->page_mode = VMI_PM_AARCH32;
    if (VMI_SUCCESS == arch_init(vmi)) {
        if ( VMI_SUCCESS == vmi_pagetable_lookup(vmi, swapper_pg_dir - boundary, va, &test) &&
                test == pa) {
            vmi->kpgd = swapper_pg_dir - boundary;
            return VMI_SUCCESS;
        }
    }

    return VMI_FAILURE;
}

static status_t linux_filemode_init(vmi_instance_t vmi)
{
    status_t rc;
    addr_t swapper_pg_dir = 0, kernel_pgt = 0;
    addr_t boundary = 0, phys_start = 0, virt_start = 0;

    switch (vmi->page_mode) {
        case VMI_PM_AARCH64:
        case VMI_PM_IA32E:
            linux_symbol_to_address(vmi, "phys_startup_64", NULL, &phys_start);
            linux_symbol_to_address(vmi, "startup_64", NULL, &virt_start);
            break;
        case VMI_PM_AARCH32:
        case VMI_PM_LEGACY:
        case VMI_PM_PAE:
            linux_symbol_to_address(vmi, "phys_startup_32", NULL, &phys_start);
            linux_symbol_to_address(vmi, "startup_32", NULL, &virt_start);
            break;
        case VMI_PM_UNKNOWN:
            linux_symbol_to_address(vmi, "phys_startup_64", NULL, &phys_start);
            linux_symbol_to_address(vmi, "startup_64", NULL, &virt_start);

            if (phys_start && virt_start) break;
            phys_start = virt_start = 0;

            linux_symbol_to_address(vmi, "phys_startup_32", NULL, &phys_start);
            linux_symbol_to_address(vmi, "startup_32", NULL, &virt_start);
            break;
    }

    virt_start = canonical_addr(virt_start);

    if (phys_start && virt_start && phys_start < virt_start) {
        boundary = virt_start - phys_start;
        dbprint(VMI_DEBUG_MISC, "--got kernel boundary (0x%.16"PRIx64").\n", boundary);
    }

    rc = linux_symbol_to_address(vmi, "swapper_pg_dir", NULL, &swapper_pg_dir);

    if (VMI_SUCCESS == rc) {

        dbprint(VMI_DEBUG_MISC, "--got vaddr for swapper_pg_dir (0x%.16"PRIx64").\n",
                swapper_pg_dir);

        swapper_pg_dir = canonical_addr(swapper_pg_dir);

        /* We don't know if VMI_PM_LEGACY, VMI_PM_PAE or VMI_PM_AARCH32 yet
         * so we do some heuristics below. */
        if (boundary) {
            rc = linux_filemode_32bit_init(vmi, swapper_pg_dir, boundary,
                                           phys_start, virt_start);
            if (VMI_SUCCESS == rc)
                goto done;
        }

        /*
         * So we have a swapper but don't know the physical page of it.
         * We will make some educated guesses now.
         */
        boundary = 0xC0000000;
        dbprint(VMI_DEBUG_MISC, "--trying boundary 0x%.16"PRIx64".\n",
                boundary);
        rc = linux_filemode_32bit_init(vmi, swapper_pg_dir, boundary,
                                       swapper_pg_dir-boundary, swapper_pg_dir);
        if (VMI_SUCCESS == rc) {
            goto done;
        }

        boundary = 0x80000000;
        dbprint(VMI_DEBUG_MISC, "--trying boundary 0x%.16"PRIx64".\n",
                boundary);
        rc = linux_filemode_32bit_init(vmi, swapper_pg_dir, boundary,
                                       swapper_pg_dir-boundary, swapper_pg_dir);
        if (VMI_SUCCESS == rc) {
            goto done;
        }

        boundary = 0x40000000;
        dbprint(VMI_DEBUG_MISC, "--trying boundary 0x%.16"PRIx64".\n",
                boundary);
        rc = linux_filemode_32bit_init(vmi, swapper_pg_dir, boundary,
                                       swapper_pg_dir-boundary, swapper_pg_dir);
        goto done;
    }

    /* Try 64-bit init */
    rc = linux_symbol_to_address(vmi, "init_level4_pgt", NULL, &kernel_pgt);
    if ( rc == VMI_FAILURE )
        rc = linux_symbol_to_address(vmi, "init_top_pgt", NULL, &kernel_pgt);

    if (rc == VMI_FAILURE)
        goto done;

    dbprint(VMI_DEBUG_MISC, "--got vaddr for kernel pagetable (0x%.16"PRIx64").\n", kernel_pgt);

    kernel_pgt = canonical_addr(kernel_pgt);

    if (!boundary)
        return VMI_FAILURE;

    vmi->page_mode = VMI_PM_IA32E;

    rc = arch_init(vmi);
    if (VMI_FAILURE == rc)
        return VMI_FAILURE;

    addr_t test = 0;

    /* First, look for kernel in likely place */
    rc = vmi_pagetable_lookup(vmi, kernel_pgt - boundary, virt_start, &test);
    if ( VMI_SUCCESS == rc &&
            test == phys_start) {
        vmi->kpgd = kernel_pgt - boundary;
        rc = verify_linux_paging (vmi);
    }

    /* If that didn't work, brute force across possible KPDB locations and virtual kernel bases */
    if (VMI_FAILURE == rc) {
        rc = brute_force_find_kern_mem (vmi);
    }

done:
    return rc;
}

static status_t init_from_json_profile(vmi_instance_t vmi)
{

    status_t ret = VMI_FAILURE;
    linux_instance_t linux_instance = vmi->os_data;

    if (!linux_instance->tasks_offset) {
        if (VMI_FAILURE == json_profile_lookup(vmi, "task_struct", "tasks", &linux_instance->tasks_offset)) {
            goto done;
        }
    }
    if (!linux_instance->mm_offset) {
        if (VMI_FAILURE == json_profile_lookup(vmi, "task_struct", "mm", &linux_instance->mm_offset)) {
            goto done;
        }
    }
    if (!linux_instance->pid_offset) {
        if (VMI_FAILURE == json_profile_lookup(vmi, "task_struct", "pid", &linux_instance->pid_offset)) {
            goto done;
        }
    }
    if (!linux_instance->name_offset) {
        if (VMI_FAILURE == json_profile_lookup(vmi, "task_struct", "comm", &linux_instance->name_offset)) {
            goto done;
        }
    }
    if (!linux_instance->pgd_offset) {
        if (VMI_FAILURE == json_profile_lookup(vmi, "mm_struct", "pgd", &linux_instance->pgd_offset)) {
            goto done;
        }
    }
    if (!vmi->init_task) {
        if (VMI_FAILURE == json_profile_lookup(vmi, "init_task", NULL, &vmi->init_task)) {
            goto done;
        }
    }

    ret = VMI_SUCCESS;

done:
    return ret;
}

/* Is this the page holding the init task? */
static status_t init_task_kaslr_test(vmi_instance_t vmi, addr_t page_vaddr)
{
    status_t ret = VMI_FAILURE;
    uint32_t pid = -1;
    addr_t addr = ~0;
    addr_t init_task = page_vaddr + (vmi->init_task & VMI_BIT_MASK(0,11));
    linux_instance_t linux_instance = vmi->os_data;
    ACCESS_CONTEXT(ctx,
                   .pm = vmi->page_mode,
                   .translate_mechanism = VMI_TM_PROCESS_PT,
                   .pt = vmi->kpgd);

    /* The pid should be 0 */
    ctx.addr = init_task + linux_instance->pid_offset;
    if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &pid) )
        return ret;

    if ( 0 != pid )
        return ret;

    /* Kernel tasks have no mm */
    ctx.addr = init_task + linux_instance->mm_offset;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &addr) )
        return ret;

    if ( 0 != addr )
        return ret;

    /* Verify that *(task->tasks) succeeds. */
    ctx.addr = init_task + linux_instance->tasks_offset;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &addr) )
        return ret;

    ctx.addr = addr;
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &addr) )
        return ret;

    /* Check the name */
    ctx.addr = init_task + linux_instance->name_offset;
    char* init_task_name = vmi_read_str(vmi, &ctx);

    if ( init_task_name && !strncmp("swapper", init_task_name, 7) )
        ret = VMI_SUCCESS;

    free(init_task_name);
    return ret;
}

static status_t get_kaslr_offset_ia32e(vmi_instance_t vmi)
{
    addr_t va, pa;
    addr_t kernel_text_start = 0xffffffff81000000;
    addr_t kernel_text_end = kernel_text_start + (1024*1024*1024);

    linux_instance_t linux_instance = vmi->os_data;

    vmi->init_task = linux_instance->init_task_fixed;

    for (va = kernel_text_start; va < kernel_text_end; va += 0x200000) {
        if ( vmi_translate_kv2p(vmi, va, &pa) == VMI_SUCCESS ) {
            linux_instance->kaslr_offset = va - kernel_text_start;
            vmi->init_task += linux_instance->kaslr_offset;
            dbprint(VMI_DEBUG_MISC, "**calculated KASLR offset in 64-bit mode: 0x%"PRIx64"\n", linux_instance->kaslr_offset);
            return VMI_SUCCESS;
        }
    }
    return VMI_FAILURE;
}

static status_t init_kaslr(vmi_instance_t vmi)
{
    /*
     * First check whether init_task can be translated as-is.
     */
    uint32_t test;
    linux_instance_t linux_instance = vmi->os_data;
    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_DTB,
                   .pt = vmi->kpgd,
                   .addr = vmi->init_task);

    if ( VMI_SUCCESS == vmi_read_32(vmi, &ctx, &test) ) {
        /* Provided init_task works fine, let's calculate kaslr from it if necessary */
        addr_t init_task_symbol_addr;
        if ( VMI_FAILURE == linux_symbol_to_address(vmi, "init_task", NULL, &init_task_symbol_addr) )
            return VMI_FAILURE;

        linux_instance->kaslr_offset = vmi->init_task - init_task_symbol_addr;
        dbprint(VMI_DEBUG_MISC, "**calculated KASLR offset from pre-defined init_task addr: 0x%"PRIx64"\n", linux_instance->kaslr_offset);
        return VMI_SUCCESS;
    }

    if ( vmi->page_mode == VMI_PM_IA32E ) {
        if ( VMI_SUCCESS == get_kaslr_offset_ia32e(vmi) )
            return VMI_SUCCESS;
    }

    status_t ret = VMI_FAILURE;
    GSList *loop, *pages = vmi_get_va_pages(vmi, vmi->kpgd);
    loop = pages;
    while (loop) {
        page_info_t *info = loop->data;

        if ( !linux_instance->kaslr_offset ) {
            switch (vmi->page_mode) {
                case VMI_PM_AARCH64:
                case VMI_PM_IA32E:
                    if ( VMI_GET_BIT(info->vaddr, 47) )
                        ret = init_task_kaslr_test(vmi, info->vaddr);
                    break;
                default:
                    ret = init_task_kaslr_test(vmi, info->vaddr);
                    break;
            }

            if ( VMI_SUCCESS == ret ) {
                linux_instance->kaslr_offset = info->vaddr - (vmi->init_task & ~VMI_BIT_MASK(0,11));
                vmi->init_task = linux_instance->init_task_fixed + linux_instance->kaslr_offset;
                dbprint(VMI_DEBUG_MISC, "**calculated KASLR offset: 0x%"PRIx64"\n", linux_instance->kaslr_offset);
                break;
            }
        }

        g_free(info);
        loop = loop->next;
    }

    g_slist_free(pages);
    return ret;
}

/*
 * Tests whether the init task is where it's expected, given the
 * current KPBD and kernel virtual base.
 */
static status_t verify_linux_paging (vmi_instance_t vmi)
{
    if (VMI_FAILURE == init_kaslr(vmi))
        return VMI_FAILURE;

    return init_task_kaslr_test (vmi, vmi->init_task & ~VMI_BIT_MASK(0,11));
}

/*
 * Try every possible physical address as the kernel page directory
 * base until the init task is located. Do this when we don't know the
 * location of the (physical) KPDB or the (virtual) kernel base. In
 * the case of x86_64, this is optimized so that page directories are
 * enumerated, and only they are examined.
 */
static status_t brute_force_find_kern_mem (vmi_instance_t vmi)
{
    status_t rc = VMI_FAILURE;
    /* Find pages that probably hold page directories. */
    GSList * pds = find_page_directories (vmi);

    if (pds) {
        /* Fast path for x64: only consider page directories for the KPGD. */
        GSList * loop = pds;
        while (loop) {
            vmi->kpgd = *(addr_t *) loop->data;

            if (VMI_SUCCESS == verify_linux_paging(vmi)) {
                rc = VMI_SUCCESS;
                break;
            }
            loop = loop->next;
        }
        g_slist_free_full (pds, g_free);

        if (VMI_SUCCESS == rc)
            goto exit;

        /* On failure, fall-through to slowest path */
    }

    /* Case for non-x64 systems. Expect poor performance. */
    warnprint("Looking for kernel PGD and KASLR with slowest available technique\n");

    for (vmi->kpgd = 0; vmi->kpgd < vmi_get_max_physical_address (vmi); vmi->kpgd += VMI_PS_4KB) {
        if (VMI_SUCCESS == verify_linux_paging(vmi)) {
            rc = VMI_SUCCESS;
            break;
        }
    }

exit:
    if (VMI_SUCCESS == rc) {
        dbprint(VMI_DEBUG_MISC, "**found kernel PGD: 0x%"PRIx64" and init task: 0x%"PRIx64"\n",
                vmi->kpgd, vmi->init_task);
    } else {
        errprint("Brute force search failed to find kernel PDB and KASLR offset\n");
    }
    return rc;
}

status_t linux_init(vmi_instance_t vmi, GHashTable *config)
{

    status_t rc;
    os_interface_t os_interface = NULL;

    if (!config) {
        errprint("No config table found\n");
        return VMI_FAILURE;
    }

    if (vmi->os_data != NULL) {
        errprint("os data already initialized, reinitializing\n");
        g_free(vmi->os_data);
    }

    vmi->os_data = g_try_malloc0(sizeof(struct linux_instance));
    if ( !vmi->os_data )
        return VMI_FAILURE;

    linux_instance_t linux_instance = vmi->os_data;

    g_hash_table_foreach(config, (GHFunc)linux_read_config_ghashtable_entries, vmi);

    rc = init_from_json_profile(vmi);

    if ( VMI_FAILURE == rc && !vmi->init_task )
        rc = linux_symbol_to_address(vmi, "init_task", NULL, &vmi->init_task);
    else
        rc = VMI_SUCCESS;

    if ( VMI_FAILURE == rc ) {
        errprint("Failed to determine init_task!\n");
        goto _exit;
    }

    /* Save away the claimed init_task addr. It may be needed again for KASLR computation. */
    vmi->init_task = canonical_addr(vmi->init_task);
    linux_instance->init_task_fixed = vmi->init_task;

    if ( !vmi->kpgd ) {
#if defined(ARM32) || defined(ARM64)
        rc = driver_get_vcpureg(vmi, &vmi->kpgd, TTBR1, 0);
#elif defined(I386) || defined(X86_64)
        rc = driver_get_vcpureg(vmi, &vmi->kpgd, CR3, 0);
        vmi->kpgd &= ~0x1fffull; // mask PCID and meltdown bits
#endif
    }

    /*
     * The driver failed to get us a pagetable.
     * As a fall-back, try to init using heuristics.
     * This path is taken in FILE mode as well.
     */
    if ( VMI_FAILURE == rc && VMI_FAILURE == linux_filemode_init(vmi) )
        goto _exit;

    if ( !linux_instance->kaslr_offset ) {
        if ( VMI_FAILURE == init_kaslr(vmi) ) {
            // try without masking Meltdown bit
            vmi->kpgd |= 0x1000ull;
            if ( VMI_FAILURE == init_kaslr(vmi) ) {
                dbprint(VMI_DEBUG_MISC, "**failed to determine KASLR offset\n");
                goto _exit;
            }
        }
    }

    dbprint(VMI_DEBUG_MISC, "**set vmi->kpgd (0x%.16"PRIx64").\n", vmi->kpgd);
    dbprint(VMI_DEBUG_MISC, "**set vmi->init_task (0x%.16"PRIx64").\n", vmi->init_task);

    os_interface = g_malloc(sizeof(struct os_interface));
    if ( !os_interface )
        goto _exit;

    bzero(os_interface, sizeof(struct os_interface));
    os_interface->os_get_offset = linux_get_offset;
    os_interface->os_get_kernel_struct_offset = linux_get_kernel_struct_offset;
    os_interface->os_pid_to_pgd = linux_pid_to_pgd;
    os_interface->os_pgd_to_pid = linux_pgd_to_pid;
    os_interface->os_ksym2v = linux_symbol_to_address;
    os_interface->os_usym2rva = NULL;
    os_interface->os_v2sym = NULL;
    os_interface->os_v2ksym = linux_system_map_address_to_symbol;
    os_interface->os_read_unicode_struct = NULL;
    os_interface->os_teardown = linux_teardown;

    vmi->os_interface = os_interface;

    return VMI_SUCCESS;

_exit:
    linux_teardown(vmi);
    return VMI_FAILURE;
}

void linux_read_config_ghashtable_entries(char* key, gpointer value,
        vmi_instance_t vmi)
{

    linux_instance_t linux_instance = vmi->os_data;

    if (strncmp(key, "sysmap", CONFIG_STR_LENGTH) == 0) {
        linux_instance->sysmap = strdup((char *)value);
        goto _done;
    }

    if (strncmp(key, "linux_tasks", CONFIG_STR_LENGTH) == 0) {
        linux_instance->tasks_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "linux_mm", CONFIG_STR_LENGTH) == 0) {
        linux_instance->mm_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "linux_pid", CONFIG_STR_LENGTH) == 0) {
        linux_instance->pid_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "linux_name", CONFIG_STR_LENGTH) == 0) {
        linux_instance->name_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "linux_pgd", CONFIG_STR_LENGTH) == 0) {
        linux_instance->pgd_offset = *(addr_t *)value;
        goto _done;
    }

    if (strncmp(key, "linux_init_task", CONFIG_STR_LENGTH) == 0) {
        vmi->init_task = *(addr_t*)value;
        goto _done;
    }

    if (strncmp(key, "linux_kaslr", CONFIG_STR_LENGTH) == 0) {
        linux_instance->kaslr_offset = *(addr_t*)value;
        goto _done;
    }

    if (strncmp(key, "kpgd", CONFIG_STR_LENGTH) == 0) {
        vmi->kpgd = *(addr_t*)value;
        goto _done;
    }

_done:
    return;
}

status_t linux_get_kernel_struct_offset(vmi_instance_t vmi, const char* symbol, const char* member, addr_t *addr)
{
    return json_profile_lookup(vmi, symbol, member, addr);
}

status_t linux_get_offset(vmi_instance_t vmi, const char* offset_name, addr_t *offset)
{
    const size_t max_length = 100;
    linux_instance_t linux_instance = vmi->os_data;

    if (linux_instance == NULL) {
        errprint("VMI_ERROR: OS instance not initialized\n");
        return 0;
    }

    if (strncmp(offset_name, "linux_tasks", max_length) == 0) {
        *offset = linux_instance->tasks_offset;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "linux_mm", max_length) == 0) {
        *offset = linux_instance->mm_offset;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "linux_pid", max_length) == 0) {
        *offset = linux_instance->pid_offset;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "linux_name", max_length) == 0) {
        *offset = linux_instance->name_offset;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "linux_pgd", max_length) == 0) {
        *offset = linux_instance->pgd_offset;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "linux_kaslr", max_length) == 0) {
        *offset = linux_instance->kaslr_offset;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "linux_init_task", max_length) == 0) {
        *offset = vmi->init_task;
        return VMI_SUCCESS;
    } else if (strncmp(offset_name, "kpgd", max_length) == 0) {
        *offset = vmi->kpgd;
        return VMI_SUCCESS;
    }

    warnprint("Invalid offset name in linux_get_offset (%s).\n", offset_name);
    return VMI_FAILURE;
}

status_t linux_teardown(vmi_instance_t vmi)
{
    linux_instance_t linux_instance = vmi->os_data;

    if (vmi->os_data == NULL) {
        return VMI_SUCCESS;
    }

    free(linux_instance->sysmap);
    g_free(linux_instance);

    vmi->os_data = NULL;
    vmi->kpgd = 0;

    return VMI_SUCCESS;
}

