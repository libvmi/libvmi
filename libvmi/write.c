/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include "libvmi.h"
#include "private.h"
#include "driver/interface.h"

///////////////////////////////////////////////////////////
// Classic write functions for access to memory
size_t vmi_write_pa (vmi_instance_t vmi, addr_t paddr, void *buf, size_t count)
{
    if (VMI_SUCCESS == driver_write(vmi, paddr, buf, count)){
        return count;
    }
    else{
        return 0;
    }
}

size_t vmi_write_va (vmi_instance_t vmi, addr_t vaddr, int pid, void *buf, size_t count)
{
    addr_t paddr = 0;
    if (pid){
        paddr = vmi_translate_uv2p(vmi, vaddr, pid);
    }
    else{
        paddr = vmi_translate_kv2p(vmi, vaddr);
    }
    return vmi_write_pa(vmi, paddr, buf, count);
}

size_t vmi_write_ksym (vmi_instance_t vmi, char *sym, void *buf, size_t count)
{
    addr_t vaddr = vmi_translate_ksym2v(vmi, sym);
    return vmi_write_va(vmi, vaddr, 0, buf, count);
}

///////////////////////////////////////////////////////////
// Easy write to physical memory
static status_t vmi_write_X_pa (vmi_instance_t vmi, addr_t paddr, void *value, int size)
{
    size_t len_write = vmi_write_pa(vmi, paddr, value, size);
    if (len_write == size){
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

status_t vmi_write_8_pa (vmi_instance_t vmi, addr_t paddr, uint8_t *value)
{
    return vmi_write_X_pa(vmi, paddr, value, 1);
}

status_t vmi_write_16_pa (vmi_instance_t vmi, addr_t paddr, uint16_t *value)
{
    return vmi_write_X_pa(vmi, paddr, value, 2);
}

status_t vmi_write_32_pa (vmi_instance_t vmi, addr_t paddr, uint32_t *value)
{
    return vmi_write_X_pa(vmi, paddr, value, 4);
}

status_t vmi_write_64_pa (vmi_instance_t vmi, addr_t paddr, uint64_t *value)
{
    return vmi_write_X_pa(vmi, paddr, value, 8);
}

///////////////////////////////////////////////////////////
// Easy write to virtual memory
static status_t vmi_write_X_va (vmi_instance_t vmi, addr_t vaddr, int pid, void *value, int size)
{
    size_t len_write = vmi_write_va(vmi, vaddr, pid, value, size);
    if (len_write == size){
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

status_t vmi_write_8_va (vmi_instance_t vmi, addr_t vaddr, int pid, uint8_t *value)
{
    return vmi_write_X_va(vmi, vaddr, pid, value, 1);
}

status_t vmi_write_16_va (vmi_instance_t vmi, addr_t vaddr, int pid, uint16_t *value)
{
    return vmi_write_X_va(vmi, vaddr, pid, value, 2);
}

status_t vmi_write_32_va (vmi_instance_t vmi, addr_t vaddr, int pid, uint32_t *value)
{
    return vmi_write_X_va(vmi, vaddr, pid, value, 4);
}

status_t vmi_write_64_va (vmi_instance_t vmi, addr_t vaddr, int pid, uint64_t *value)
{
    return vmi_write_X_va(vmi, vaddr, pid, value, 8);
}

///////////////////////////////////////////////////////////
// Easy write to memory using kernel symbols
static status_t vmi_write_X_ksym (vmi_instance_t vmi, char *sym, void *value, int size)
{
    size_t len_write = vmi_write_ksym(vmi, sym, value, size);
    if (len_write == size){
        return VMI_SUCCESS;
    }
    else{
        return VMI_FAILURE;
    }
}

status_t vmi_write_8_ksym (vmi_instance_t vmi, char *sym, uint8_t *value)
{
    return vmi_write_X_ksym(vmi, sym, value, 1);
}

status_t vmi_write_16_ksym (vmi_instance_t vmi, char *sym, uint16_t *value)
{
    return vmi_write_X_ksym(vmi, sym, value, 2);
}

status_t vmi_write_32_ksym (vmi_instance_t vmi, char *sym, uint32_t *value)
{
    return vmi_write_X_ksym(vmi, sym, value, 4);
}

status_t vmi_write_64_ksym (vmi_instance_t vmi, char *sym, uint64_t *value)
{
    return vmi_write_X_ksym(vmi, sym, value, 8);
}
