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

#include <Python.h>
#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <libvmi/libvmi.h>

#define vmi(v)  (((pyvmi_instance *)(v))->vmi)
#define mem(v)  (((pyvmi_instance *)(v))->memory)
#define desc(v)  (((pyvmi_instance *)(v))->desc)
#define conf(v)  (((pyvmi_instance *)(v))->config)

#define MAX_CONFIG_BUFFER 20

// PyVmi instance type fwdref
staticforward PyTypeObject pyvmi_instance_Type;

typedef struct {
    addr_t buffer[MAX_CONFIG_BUFFER];
    uint32_t num_entries;
    GHashTable *table;
} pyvmi_config;

typedef struct {
    PyObject_HEAD vmi_instance_t vmi;   // LibVMI instance
    void *memory;
    char *desc;
    pyvmi_config *config;
} pyvmi_instance;

status_t
pyvmi_add_to_config(
    pyvmi_config *config,
    PyObject * pykey,
    PyObject * pyvalue
    )
{
    status_t ret=VMI_FAILURE;

    if(PyString_Check(pykey)) {

        char *key = PyString_AS_STRING(pykey);

        if(PyString_Check(pyvalue)) {

            // We can insert the string pointers directly to the ghashtable
            // as Python gave us a pointer and it has the data (we don't need to dup the string here).
            char *svalue=PyString_AS_STRING(pyvalue);
            g_hash_table_insert(config->table, key, svalue);

            ret=VMI_SUCCESS;

        } else if(PyInt_Check(pyvalue)) {

            // Numeric values are given by value by Python, so these have to be buffered
            if(config->num_entries < MAX_CONFIG_BUFFER) {

                config->buffer[config->num_entries] = PyInt_AsUnsignedLongMask(pyvalue);
                g_hash_table_insert(config->table, key, &(config->buffer[config->num_entries]));
                config->num_entries++;
                ret=VMI_SUCCESS;

            } else {
                PyErr_SetString(PyExc_ValueError,
                        "Not enough space in config buffer.");
            }

        } else {
            PyErr_SetString(PyExc_ValueError,
                        "Value has to be either String or Int");
        }
    } else {
        PyErr_SetString(PyExc_ValueError,
                    "Key has to be a String");
    }

    return ret;
}

// Constructor & Destructor
static PyObject *
pyvmi_init(
    PyObject * self,
    PyObject * args)
{
    pyvmi_instance *object = NULL;
    object = PyObject_NEW(pyvmi_instance, &pyvmi_instance_Type);
    mem(object)  = NULL;
    desc(object) = NULL;
    conf(object) = NULL;

    char *vmname=NULL, *inittype=NULL;
    uint32_t flags = 0;
    PyObject *dict = NULL;
    vmi_config_t vmiconfig = NULL;

    if (PyArg_ParseTuple(args, "ss", &vmname, &inittype)) {
        flags |= VMI_CONFIG_GLOBAL_FILE_ENTRY;
        vmiconfig = (vmi_config_t)vmname;
    }
    else if(PyArg_ParseTuple(args, "O!", &PyDict_Type, &dict)) {
        flags |= VMI_CONFIG_GHASHTABLE;

        // convert dict to GHashTable
        conf(object) = malloc(sizeof(pyvmi_config));
        conf(object)->num_entries = 0;
        conf(object)->table = g_hash_table_new(g_str_hash, g_str_equal);
        vmiconfig = (vmi_config_t)(conf(object)->table);

        PyObject *pykey, *pyvalue;
        Py_ssize_t pos = 0;

        while (PyDict_Next(dict, &pos, &pykey, &pyvalue)) {
            if(VMI_FAILURE==pyvmi_add_to_config(conf(object), pykey, pyvalue)) {
                goto init_fail;
            }
        }

        inittype = g_hash_table_lookup(conf(object)->table, "inittype");
        if(inittype == NULL) {
            goto init_fail;
        }
    } else {
        PyErr_SetString(PyExc_ValueError, "Unknown input types received!");
        goto init_fail;
    }

    if (strcmp("complete", inittype) == 0) {
        flags |= VMI_AUTO | VMI_INIT_COMPLETE;
    }
    else if (strcmp("partial", inittype) == 0) {
        flags |= VMI_AUTO | VMI_INIT_PARTIAL;
    }
    else {
        PyErr_SetString(PyExc_ValueError,
                        "Inittype must be 'complete' or 'partial'");
        goto init_fail;
    }

    if (VMI_FAILURE == vmi_init_custom(&(vmi(object)), flags, vmiconfig)) {
        PyErr_SetString(PyExc_ValueError, "Init failed");
        goto init_fail;
    }

    // Once libvmi inits we don't need to keep the config anymore
    if(flags & VMI_CONFIG_GHASHTABLE) {
        g_hash_table_destroy(conf(object)->table);
        free(conf(object));
    }

    vmname = vmi_get_name(vmi(object));
    if(vmname) {
        desc(object)=vmname;
    } else {
        uint64_t domid = vmi_get_vmid(vmi(object));
        char *domidstring = malloc(snprintf(NULL, 0, "domid-%u", domid)+1);
        sprintf(domidstring, "domid-%u", domid);
        desc(object)=domidstring;
    }

    return (PyObject *)object;

init_fail:
    if(flags & VMI_CONFIG_GHASHTABLE) {
        g_hash_table_destroy(conf(object)->table);
        free(conf(object));
    }
    return NULL;
}

static PyObject *
pyvmi_init_complete(
    PyObject * self,
    PyObject * args)
{
    char *config = NULL;

    if (!PyArg_ParseTuple(args, "s", &config)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_init_complete(&(vmi(self)), config)) {
        PyErr_SetString(PyExc_ValueError, "Init complete failed");
        return NULL;
    }

    return Py_BuildValue("");   // return None
}

static void
pyvmi_instance_dealloc(
    PyObject * self)
{
    vmi_destroy(vmi(self));
    if (mem(self)) {
        free(mem(self));
    }
    if (desc(self)) {
        free(desc(self));
    }
    PyObject_DEL(self);
}

//-------------------------------------------------------------------
// Translate functions
static PyObject *
pyvmi_translate_kv2p(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;

    if (!PyArg_ParseTuple(args, "K", &vaddr)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    addr_t paddr = vmi_translate_kv2p(vmi(self), vaddr);

    if (!paddr) {
        PyErr_SetString(PyExc_ValueError, "Address translation failed");
        return NULL;
    }

    return Py_BuildValue("K", paddr);
}

static PyObject *
pyvmi_translate_uv2p(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;
    int pid;

    if (!PyArg_ParseTuple(args, "Ki", &vaddr, &pid)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    addr_t paddr = vmi_translate_uv2p(vmi(self), vaddr, pid);

    if (!paddr) {
        PyErr_SetString(PyExc_ValueError, "Address translation failed");
        return NULL;
    }

    return Py_BuildValue("K", paddr);
}

static PyObject *
pyvmi_translate_ksym2v(
    PyObject * self,
    PyObject * args)
{
    char *sym;

    if (!PyArg_ParseTuple(args, "s", &sym)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    addr_t vaddr = vmi_translate_ksym2v(vmi(self), sym);

    if (!vaddr) {
        PyErr_SetString(PyExc_ValueError, "Symbol lookup failed");
        return NULL;
    }

    return Py_BuildValue("K", vaddr);
}

static PyObject *
pyvmi_pid_to_dtb(
    PyObject * self,
    PyObject * args)
{
    int pid;

    if (!PyArg_ParseTuple(args, "i", &pid)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    addr_t dtb = vmi_pid_to_dtb(vmi(self), pid);

    if (!dtb) {
        PyErr_SetString(PyExc_ValueError, "DTB lookup failed");
        return NULL;
    }

    return Py_BuildValue("K", dtb);
}

//-------------------------------------------------------------------
// Primary read functions
static PyObject *
pyvmi_read_pa(
    PyObject * self,
    PyObject * args)
{
    addr_t paddr;
    uint32_t length;
    char msg[1024];

#define ll_t unsigned long long

    if (!PyArg_ParseTuple(args, "KI", &paddr, &length)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (mem(self)) {
        free(mem(self));
    }

    mem(self) = malloc(length);
    if (!mem(self)) {
        PyErr_SetString(PyExc_MemoryError, "malloc failed");
        return NULL;
    }   // if

    size_t nbytes = vmi_read_pa(vmi(self), paddr, mem(self), length);

    if (nbytes != length) {
        snprintf(msg, sizeof(msg),
                 "%s was asked to read PA [0x%.16llx-0x%.16llx] (%d bytes), but only read %lld bytes)",
                 __FUNCTION__, (ll_t) paddr, (ll_t) (paddr + length),
                 length, (ll_t) nbytes);
        PyErr_SetString(PyExc_ValueError, msg);
        return NULL;
    }

    return Py_BuildValue("s#", mem(self), length);
}

// Similar to pyvmi_read_pa, but puts zeros in memory holes instead of failing
static PyObject *
pyvmi_zread_pa(
    PyObject * self,
    PyObject * args)
{
    addr_t paddr;
    uint32_t length;

#define ll_t unsigned long long

#define PAGE_SIZE 0x1000    // minimal PAGE_SIZE
#define PAGE_MASK 0xfff
#define PAGE_SHIFT 12

    if (!PyArg_ParseTuple(args, "KI", &paddr, &length)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (mem(self)) {
        free(mem(self));
        mem(self) = 0;
    }

    if (0 == length) {
        return Py_BuildValue("s#", NULL, 0);
    }

    mem(self) = malloc(length);
    if (!mem(self)) {
        PyErr_SetString(PyExc_MemoryError, "malloc failed");
        return NULL;
    }   // if
    memset(mem(self), 0, length);

    size_t remaining = (size_t) length;
    uint8_t *target = (uint8_t *) (mem(self));

    while (remaining > 0) {
        // calculate how many bytes to read
        size_t count = PAGE_SIZE;

        if (paddr & PAGE_MASK) {    // an offset was given
            count = PAGE_SIZE - (paddr & PAGE_MASK);    // read to end of PAGE
        }
        if (remaining < count) {    // don't read more than requested
            count = remaining;
        }

        // ignore return value here
        (void) vmi_read_pa(vmi(self), paddr, target, count);

        remaining -= count;
        paddr += count;
        target += count;
    }   // while

    return Py_BuildValue("s#", mem(self), length);
}

static PyObject *
pyvmi_read_va(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;
    int pid;
    uint32_t length;

    if (!PyArg_ParseTuple(args, "KiI", &vaddr, &pid, &length)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (mem(self)) {
        free(mem(self));
    }

    mem(self) = malloc(length);
    if (!mem(self)) {
        PyErr_SetString(PyExc_MemoryError, "malloc failed");
        return NULL;
    }   // if

    size_t nbytes =
        vmi_read_va(vmi(self), vaddr, pid, mem(self), length);
    if (nbytes != length) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("s#", mem(self), length);
}

static PyObject *
pyvmi_read_ksym(
    PyObject * self,
    PyObject * args)
{
    char *sym;
    uint32_t length;

    if (!PyArg_ParseTuple(args, "sI", &sym, &length)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (mem(self)) {
        free(mem(self));
    }

    mem(self) = malloc(length);
    if (!mem(self)) {
        PyErr_SetString(PyExc_MemoryError, "malloc failed");
        return NULL;
    }   // if

    size_t nbytes = vmi_read_ksym(vmi(self), sym, mem(self), length);

    if (nbytes != length) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("s#", mem(self), length);
}

//-------------------------------------------------------------------
// Primary write functions
static PyObject *
pyvmi_write_pa(
    PyObject * self,
    PyObject * args)
{
    addr_t paddr;
    void *buf;
    int count;

    if (!PyArg_ParseTuple(args, "Ks#", &paddr, &buf, &count)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    size_t nbytes = vmi_write_pa(vmi(self), paddr, buf, (size_t) count);

    if (nbytes != count) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("I", nbytes);
}

static PyObject *
pyvmi_write_va(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;
    int pid;
    void *buf;
    int count;

    if (!PyArg_ParseTuple(args, "Kis#", &vaddr, &pid, &buf, &count)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    size_t nbytes =
        vmi_write_va(vmi(self), vaddr, pid, buf, (size_t) count);
    if (nbytes != count) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("I", nbytes);
}

static PyObject *
pyvmi_write_ksym(
    PyObject * self,
    PyObject * args)
{
    char *sym;
    void *buf;
    int count;

    if (!PyArg_ParseTuple(args, "ss#", &sym, &buf, &count)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    size_t nbytes = vmi_write_ksym(vmi(self), sym, buf, (size_t) count);

    if (nbytes != count) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("I", nbytes);
}

//-------------------------------------------------------------------
// Utility read functions
static PyObject *
pyvmi_read_8_pa(
    PyObject * self,
    PyObject * args)
{
    addr_t paddr;
    uint8_t value;

    if (!PyArg_ParseTuple(args, "K", &paddr)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_8_pa(vmi(self), paddr, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("B", value);
}

static PyObject *
pyvmi_read_16_pa(
    PyObject * self,
    PyObject * args)
{
    addr_t paddr;
    uint16_t value;

    if (!PyArg_ParseTuple(args, "K", &paddr)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_16_pa(vmi(self), paddr, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("H", value);
}

static PyObject *
pyvmi_read_32_pa(
    PyObject * self,
    PyObject * args)
{
    addr_t paddr;
    uint32_t value;

    if (!PyArg_ParseTuple(args, "K", &paddr)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_32_pa(vmi(self), paddr, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("I", value);
}

static PyObject *
pyvmi_read_64_pa(
    PyObject * self,
    PyObject * args)
{
    addr_t paddr;
    uint64_t value;

    if (!PyArg_ParseTuple(args, "K", &paddr)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_64_pa(vmi(self), paddr, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("K", value);
}

static PyObject *
pyvmi_read_addr_pa(
    PyObject * self,
    PyObject * args)
{
    addr_t paddr;
    addr_t value;

    if (!PyArg_ParseTuple(args, "K", &paddr)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_addr_pa(vmi(self), paddr, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("B", value);
}

static PyObject *
pyvmi_read_str_pa(
    PyObject * self,
    PyObject * args)
{
    addr_t paddr;
    char *str = NULL;

    if (!PyArg_ParseTuple(args, "K", &paddr)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if ((str = vmi_read_str_pa(vmi(self), paddr)) == NULL) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("s", str);
}

static PyObject *
pyvmi_read_8_va(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;
    int pid;
    uint8_t value;

    if (!PyArg_ParseTuple(args, "Ki", &vaddr, &pid)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_8_va(vmi(self), vaddr, pid, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("B", value);
}

static PyObject *
pyvmi_read_16_va(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;
    int pid;
    uint16_t value;

    if (!PyArg_ParseTuple(args, "Ki", &vaddr, &pid)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_16_va(vmi(self), vaddr, pid, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("H", value);
}

static PyObject *
pyvmi_read_32_va(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;
    int pid;
    uint32_t value;

    if (!PyArg_ParseTuple(args, "Ki", &vaddr, &pid)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_32_va(vmi(self), vaddr, pid, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("I", value);
}

static PyObject *
pyvmi_read_64_va(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;
    int pid;
    uint64_t value;

    if (!PyArg_ParseTuple(args, "Ki", &vaddr, &pid)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_64_va(vmi(self), vaddr, pid, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("K", value);
}

static PyObject *
pyvmi_read_addr_va(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;
    int pid;
    addr_t value;

    if (!PyArg_ParseTuple(args, "Ki", &vaddr, &pid)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_addr_va(vmi(self), vaddr, pid, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("K", value);
}

static PyObject *
pyvmi_read_str_va(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;
    int pid;
    char *str = NULL;

    if (!PyArg_ParseTuple(args, "Ki", &vaddr, &pid)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if ((str = vmi_read_str_va(vmi(self), vaddr, pid)) == NULL) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("s", str);
}

static PyObject *
pyvmi_read_8_ksym(
    PyObject * self,
    PyObject * args)
{
    char *sym;
    uint8_t value;

    if (!PyArg_ParseTuple(args, "s", &sym)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_8_ksym(vmi(self), sym, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("B", value);
}

static PyObject *
pyvmi_read_16_ksym(
    PyObject * self,
    PyObject * args)
{
    char *sym;
    uint16_t value;

    if (!PyArg_ParseTuple(args, "s", &sym)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_16_ksym(vmi(self), sym, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("H", value);
}

static PyObject *
pyvmi_read_32_ksym(
    PyObject * self,
    PyObject * args)
{
    char *sym;
    uint32_t value;

    if (!PyArg_ParseTuple(args, "s", &sym)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_32_ksym(vmi(self), sym, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("I", value);
}

static PyObject *
pyvmi_read_64_ksym(
    PyObject * self,
    PyObject * args)
{
    char *sym;
    uint64_t value;

    if (!PyArg_ParseTuple(args, "s", &sym)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_64_ksym(vmi(self), sym, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("K", value);
}

static PyObject *
pyvmi_read_addr_ksym(
    PyObject * self,
    PyObject * args)
{
    char *sym;
    addr_t value;

    if (!PyArg_ParseTuple(args, "s", &sym)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_addr_ksym(vmi(self), sym, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("K", value);
}

static PyObject *
pyvmi_read_str_ksym(
    PyObject * self,
    PyObject * args)
{
    char *sym;
    char *str = NULL;

    if (!PyArg_ParseTuple(args, "s", &sym)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if ((str = vmi_read_str_ksym(vmi(self), sym)) == NULL) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("s", str);
}

//-------------------------------------------------------------------
// Utility write functions
static PyObject *
pyvmi_write_8_pa(
    PyObject * self,
    PyObject * args)
{
    addr_t paddr;
    uint8_t value;

    if (!PyArg_ParseTuple(args, "Kc", &paddr, &value) &&
        !PyArg_ParseTuple(args, "KB", &paddr, &value)
    ) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_write_8_pa(vmi(self), paddr, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject *
pyvmi_write_16_pa(
    PyObject * self,
    PyObject * args)
{
    addr_t paddr;
    uint16_t value;

    if (!PyArg_ParseTuple(args, "KH", &paddr, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_write_16_pa(vmi(self), paddr, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject *
pyvmi_write_32_pa(
    PyObject * self,
    PyObject * args)
{
    addr_t paddr;
    uint32_t value;

    if (!PyArg_ParseTuple(args, "KI", &paddr, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_write_32_pa(vmi(self), paddr, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject *
pyvmi_write_64_pa(
    PyObject * self,
    PyObject * args)
{
    addr_t paddr;
    uint64_t value;

    if (!PyArg_ParseTuple(args, "KK", &paddr, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_write_64_pa(vmi(self), paddr, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject *
pyvmi_write_8_va(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;
    int pid;
    uint8_t value;

    if (!PyArg_ParseTuple(args, "Kic", &vaddr, &pid, &value) &&
        !PyArg_ParseTuple(args, "KiB", &vaddr, &pid, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_write_8_va(vmi(self), vaddr, pid, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject *
pyvmi_write_16_va(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;
    int pid;
    uint16_t value;

    if (!PyArg_ParseTuple(args, "KiH", &vaddr, &pid, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_write_16_va(vmi(self), vaddr, pid, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject *
pyvmi_write_32_va(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;
    int pid;
    uint32_t value;

    if (!PyArg_ParseTuple(args, "KiI", &vaddr, &pid, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_write_32_va(vmi(self), vaddr, pid, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject *
pyvmi_write_64_va(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;
    int pid;
    uint64_t value;

    if (!PyArg_ParseTuple(args, "KiK", &vaddr, &pid, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_write_64_va(vmi(self), vaddr, pid, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject *
pyvmi_write_8_ksym(
    PyObject * self,
    PyObject * args)
{
    char *sym;
    uint8_t value;

    if (!PyArg_ParseTuple(args, "sc", &sym, &value) &&
        !PyArg_ParseTuple(args, "sB", &sym, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_write_8_ksym(vmi(self), sym, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject *
pyvmi_write_16_ksym(
    PyObject * self,
    PyObject * args)
{
    char *sym;
    uint16_t value;

    if (!PyArg_ParseTuple(args, "sH", &sym, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_write_16_ksym(vmi(self), sym, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject *
pyvmi_write_32_ksym(
    PyObject * self,
    PyObject * args)
{
    char *sym;
    uint32_t value;

    if (!PyArg_ParseTuple(args, "sI", &sym, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_write_32_ksym(vmi(self), sym, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("");
}

static PyObject *
pyvmi_write_64_ksym(
    PyObject * self,
    PyObject * args)
{
    char *sym;
    uint64_t value;

    if (!PyArg_ParseTuple(args, "sK", &sym, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    if (VMI_FAILURE == vmi_write_64_ksym(vmi(self), sym, &value)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to write memory at specified address");
        return NULL;
    }

    return Py_BuildValue("");
}

//-------------------------------------------------------------------
// Accessor and other utility functions
static PyObject *
pyvmi_get_vcpureg(
    PyObject * self,
    PyObject * args)
{
    char *reg_name = NULL;
    unsigned long vcpu = 0;

    if (!PyArg_ParseTuple(args, "sI", &reg_name, &vcpu)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    reg_t reg = 0, value = 0;

    if (strcmp(reg_name, "RAX") == 0 || strcmp(reg_name, "rax") == 0) {
        reg = RAX;
    }
    else if (strcmp(reg_name, "RBX") == 0 ||
             strcmp(reg_name, "rbx") == 0) {
        reg = RBX;
    }
    else if (strcmp(reg_name, "RCX") == 0 ||
             strcmp(reg_name, "rcx") == 0) {
        reg = RCX;
    }
    else if (strcmp(reg_name, "RDX") == 0 ||
             strcmp(reg_name, "rdx") == 0) {
        reg = RDX;
    }
    else if (strcmp(reg_name, "RBP") == 0 ||
             strcmp(reg_name, "rbp") == 0) {
        reg = RBP;
    }
    else if (strcmp(reg_name, "RSI") == 0 ||
             strcmp(reg_name, "rsi") == 0) {
        reg = RSI;
    }
    else if (strcmp(reg_name, "RDI") == 0 ||
             strcmp(reg_name, "rdi") == 0) {
        reg = RDI;
    }
    else if (strcmp(reg_name, "RSP") == 0 ||
             strcmp(reg_name, "rsp") == 0) {
        reg = RSP;
    }
    else if (strcmp(reg_name, "R8") == 0 || strcmp(reg_name, "r8") == 0) {
        reg = R8;
    }
    else if (strcmp(reg_name, "R9") == 0 || strcmp(reg_name, "r9") == 0) {
        reg = R9;
    }
    else if (strcmp(reg_name, "R10") == 0 ||
             strcmp(reg_name, "r10") == 0) {
        reg = R10;
    }
    else if (strcmp(reg_name, "R11") == 0 ||
             strcmp(reg_name, "r11") == 0) {
        reg = R11;
    }
    else if (strcmp(reg_name, "R12") == 0 ||
             strcmp(reg_name, "r12") == 0) {
        reg = R12;
    }
    else if (strcmp(reg_name, "R13") == 0 ||
             strcmp(reg_name, "r13") == 0) {
        reg = R13;
    }
    else if (strcmp(reg_name, "R14") == 0 ||
             strcmp(reg_name, "r14") == 0) {
        reg = R14;
    }
    else if (strcmp(reg_name, "R15") == 0 ||
             strcmp(reg_name, "r15") == 0) {
        reg = R15;
    }
    else if (strcmp(reg_name, "RIP") == 0 ||
             strcmp(reg_name, "rip") == 0) {
        reg = RIP;
    }
    else if (strcmp(reg_name, "RFLAGS") == 0 ||
             strcmp(reg_name, "rflags") == 0) {
        reg = RFLAGS;
    }
    else if (strcmp(reg_name, "CR0") == 0 ||
             strcmp(reg_name, "cr0") == 0) {
        reg = CR0;
    }
    else if (strcmp(reg_name, "CR2") == 0 ||
             strcmp(reg_name, "cr2") == 0) {
        reg = CR2;
    }
    else if (strcmp(reg_name, "CR3") == 0 ||
             strcmp(reg_name, "cr3") == 0) {
        reg = CR3;
    }
    else if (strcmp(reg_name, "CR4") == 0 ||
             strcmp(reg_name, "cr4") == 0) {
        reg = CR4;
    }
    else if (strcmp(reg_name, "DR0") == 0 ||
             strcmp(reg_name, "dr0") == 0) {
        reg = DR0;
    }
    else if (strcmp(reg_name, "DR1") == 0 ||
             strcmp(reg_name, "dr1") == 0) {
        reg = DR1;
    }
    else if (strcmp(reg_name, "DR2") == 0 ||
             strcmp(reg_name, "dr2") == 0) {
        reg = DR2;
    }
    else if (strcmp(reg_name, "DR3") == 0 ||
             strcmp(reg_name, "dr3") == 0) {
        reg = DR3;
    }
    else if (strcmp(reg_name, "DR6") == 0 ||
             strcmp(reg_name, "dr6") == 0) {
        reg = DR6;
    }
    else if (strcmp(reg_name, "DR7") == 0 ||
             strcmp(reg_name, "dr7") == 0) {
        reg = DR7;
    }
    else if (strcmp(reg_name, "CS_SEL") == 0 ||
             strcmp(reg_name, "cs_sel") == 0) {
        reg = CS_SEL;
    }
    else if (strcmp(reg_name, "DS_SEL") == 0 ||
             strcmp(reg_name, "ds_sel") == 0) {
        reg = DS_SEL;
    }
    else if (strcmp(reg_name, "ES_SEL") == 0 ||
             strcmp(reg_name, "es_sel") == 0) {
        reg = ES_SEL;
    }
    else if (strcmp(reg_name, "FS_SEL") == 0 ||
             strcmp(reg_name, "fs_sel") == 0) {
        reg = FS_SEL;
    }
    else if (strcmp(reg_name, "GS_SEL") == 0 ||
             strcmp(reg_name, "gs_sel") == 0) {
        reg = GS_SEL;
    }
    else if (strcmp(reg_name, "SS_SEL") == 0 ||
             strcmp(reg_name, "ss_sel") == 0) {
        reg = SS_SEL;
    }
    else if (strcmp(reg_name, "TR_SEL") == 0 ||
             strcmp(reg_name, "tr_sel") == 0) {
        reg = TR_SEL;
    }
    else if (strcmp(reg_name, "LDTR_SEL") == 0 ||
             strcmp(reg_name, "ldtr_sel") == 0) {
        reg = LDTR_SEL;
    }
    else if (strcmp(reg_name, "CS_LIMIT") == 0 ||
             strcmp(reg_name, "cs_limit") == 0) {
        reg = CS_LIMIT;
    }
    else if (strcmp(reg_name, "DS_LIMIT") == 0 ||
             strcmp(reg_name, "ds_limit") == 0) {
        reg = DS_LIMIT;
    }
    else if (strcmp(reg_name, "ES_LIMIT") == 0 ||
             strcmp(reg_name, "es_limit") == 0) {
        reg = ES_LIMIT;
    }
    else if (strcmp(reg_name, "FS_LIMIT") == 0 ||
             strcmp(reg_name, "fs_limit") == 0) {
        reg = FS_LIMIT;
    }
    else if (strcmp(reg_name, "GS_LIMIT") == 0 ||
             strcmp(reg_name, "gs_limit") == 0) {
        reg = GS_LIMIT;
    }
    else if (strcmp(reg_name, "SS_LIMIT") == 0 ||
             strcmp(reg_name, "ss_limit") == 0) {
        reg = SS_LIMIT;
    }
    else if (strcmp(reg_name, "TR_LIMIT") == 0 ||
             strcmp(reg_name, "tr_limit") == 0) {
        reg = TR_LIMIT;
    }
    else if (strcmp(reg_name, "LDTR_LIMIT") == 0 ||
             strcmp(reg_name, "ldtr_limit") == 0) {
        reg = LDTR_LIMIT;
    }
    else if (strcmp(reg_name, "IDTR_LIMIT") == 0 ||
             strcmp(reg_name, "idtr_limit") == 0) {
        reg = IDTR_LIMIT;
    }
    else if (strcmp(reg_name, "GDTR_LIMIT") == 0 ||
             strcmp(reg_name, "gdtr_limit") == 0) {
        reg = GDTR_LIMIT;
    }
    else if (strcmp(reg_name, "CS_BASE") == 0 ||
             strcmp(reg_name, "cs_base") == 0) {
        reg = CS_BASE;
    }
    else if (strcmp(reg_name, "DS_BASE") == 0 ||
             strcmp(reg_name, "ds_base") == 0) {
        reg = DS_BASE;
    }
    else if (strcmp(reg_name, "ES_BASE") == 0 ||
             strcmp(reg_name, "es_base") == 0) {
        reg = ES_BASE;
    }
    else if (strcmp(reg_name, "FS_BASE") == 0 ||
             strcmp(reg_name, "fs_base") == 0) {
        reg = FS_BASE;
    }
    else if (strcmp(reg_name, "GS_BASE") == 0 ||
             strcmp(reg_name, "gs_base") == 0) {
        reg = GS_BASE;
    }
    else if (strcmp(reg_name, "SS_BASE") == 0 ||
             strcmp(reg_name, "ss_base") == 0) {
        reg = SS_BASE;
    }
    else if (strcmp(reg_name, "TR_BASE") == 0 ||
             strcmp(reg_name, "tr_base") == 0) {
        reg = TR_BASE;
    }
    else if (strcmp(reg_name, "LDTR_BASE") == 0 ||
             strcmp(reg_name, "ldtr_base") == 0) {
        reg = LDTR_BASE;
    }
    else if (strcmp(reg_name, "IDTR_BASE") == 0 ||
             strcmp(reg_name, "idtr_base") == 0) {
        reg = IDTR_BASE;
    }
    else if (strcmp(reg_name, "GDTR_BASE") == 0 ||
             strcmp(reg_name, "gdtr_base") == 0) {
        reg = GDTR_BASE;
    }
    else if (strcmp(reg_name, "CS_ARBYTES") == 0 ||
             strcmp(reg_name, "cs_arbytes") == 0) {
        reg = CS_ARBYTES;
    }
    else if (strcmp(reg_name, "DS_ARBYTES") == 0 ||
             strcmp(reg_name, "ds_arbytes") == 0) {
        reg = DS_ARBYTES;
    }
    else if (strcmp(reg_name, "ES_ARBYTES") == 0 ||
             strcmp(reg_name, "es_arbytes") == 0) {
        reg = ES_ARBYTES;
    }
    else if (strcmp(reg_name, "FS_ARBYTES") == 0 ||
             strcmp(reg_name, "fs_arbytes") == 0) {
        reg = FS_ARBYTES;
    }
    else if (strcmp(reg_name, "GS_ARBYTES") == 0 ||
             strcmp(reg_name, "gs_arbytes") == 0) {
        reg = GS_ARBYTES;
    }
    else if (strcmp(reg_name, "SS_ARBYTES") == 0 ||
             strcmp(reg_name, "ss_arbytes") == 0) {
        reg = SS_ARBYTES;
    }
    else if (strcmp(reg_name, "TR_ARBYTES") == 0 ||
             strcmp(reg_name, "tr_arbytes") == 0) {
        reg = TR_ARBYTES;
    }
    else if (strcmp(reg_name, "LDTR_ARBYTES") == 0 ||
             strcmp(reg_name, "ldtr_arbytes") == 0) {
        reg = LDTR_ARBYTES;
    }
    else if (strcmp(reg_name, "SYSENTER_CS") == 0 ||
             strcmp(reg_name, "sysenter_cs") == 0) {
        reg = SYSENTER_CS;
    }
    else if (strcmp(reg_name, "SYSENTER_ESP") == 0 ||
             strcmp(reg_name, "sysenter_esp") == 0) {
        reg = SYSENTER_ESP;
    }
    else if (strcmp(reg_name, "SYSENTER_EIP") == 0 ||
             strcmp(reg_name, "sysenter_eip") == 0) {
        reg = SYSENTER_EIP;
    }
    else if (strcmp(reg_name, "SHADOW_GS") == 0 ||
             strcmp(reg_name, "shadow_gs") == 0) {
        reg = SHADOW_GS;
    }
    else if (strcmp(reg_name, "MSR_FLAGS") == 0 ||
             strcmp(reg_name, "msr_flags") == 0) {
        reg = MSR_FLAGS;
    }
    else if (strcmp(reg_name, "MSR_LSTAR") == 0 ||
             strcmp(reg_name, "msr_lstar") == 0) {
        reg = MSR_LSTAR;
    }
    else if (strcmp(reg_name, "MSR_CSTAR") == 0 ||
             strcmp(reg_name, "msr_cstar") == 0) {
        reg = MSR_CSTAR;
    }
    else if (strcmp(reg_name, "MSR_SYSCALL_MASK") == 0 ||
             strcmp(reg_name, "msr_syscall_mask") == 0) {
        reg = MSR_SYSCALL_MASK;
    }
    else if (strcmp(reg_name, "MSR_EFER") == 0 ||
             strcmp(reg_name, "msr_efer") == 0) {
        reg = MSR_EFER;
    }
    else if (strcmp(reg_name, "MSR_TSC_AUX") == 0 ||
             strcmp(reg_name, "msr_tsc_aux") == 0) {
        reg = MSR_TSC_AUX;
    }
    else if (strcmp(reg_name, "TSC") == 0 ||
             strcmp(reg_name, "tsc") == 0) {
        reg = TSC;
    }
    else {
        PyErr_SetString(PyExc_ValueError, "Bad register name");
        return NULL;
    }

    if (VMI_FAILURE == vmi_get_vcpureg(vmi(self), &value, reg, vcpu)) {
        PyErr_SetString(PyExc_ValueError,
                        "Unable to get register value");
        return NULL;
    }

    return Py_BuildValue("K", value);
}

static PyObject *
pyvmi_get_name(
    PyObject * self,
    PyObject * args)
{
    char *name = NULL;

    if (!PyArg_ParseTuple(args, "")) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    name = vmi_get_name(vmi(self)); //TODO how do we free the memory for name ???
    return Py_BuildValue("s", name);
}

static PyObject *
pyvmi_get_vmid(
    PyObject * self,
    PyObject * args)
{
    unsigned long vmid = 0;

    if (!PyArg_ParseTuple(args, "")) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    vmid = vmi_get_vmid(vmi(self));
    return Py_BuildValue("I", vmid);
}

static PyObject *
pyvmi_get_access_mode(
    PyObject * self,
    PyObject * args)
{
    uint32_t mode = 0;

    if (!PyArg_ParseTuple(args, "")) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    mode = vmi_get_access_mode(vmi(self));

    PyObject *rtnval = NULL;

    if (VMI_AUTO == mode) {
        rtnval = Py_BuildValue("s", "auto");
    }
    else if (VMI_XEN == mode) {
        rtnval = Py_BuildValue("s", "xen");
    }
    else if (VMI_KVM == mode) {
        rtnval = Py_BuildValue("s", "kvm");
    }
    else if (VMI_FILE == mode) {
        rtnval = Py_BuildValue("s", "file");
    }
    else {
        rtnval = Py_BuildValue("s", "unknown");
    }
    return rtnval;
}

// Just implementing get_winver_str and not get_winver as I think this
// makes the most sense for python
static PyObject *
pyvmi_get_winver_str(
    PyObject * self,
    PyObject * args)
{
    const char *version = NULL;

    if (!PyArg_ParseTuple(args, "")) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    version = vmi_get_winver_str(vmi(self));
    PyObject *rtnval = Py_BuildValue("s", version);

    return rtnval;
}

static PyObject *
pyvmi_get_memsize(
    PyObject * self,
    PyObject * args)
{
    unsigned long size = 0;

    if (!PyArg_ParseTuple(args, "")) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    size = vmi_get_memsize(vmi(self));
    return Py_BuildValue("I", size);
}

static PyObject *
pyvmi_get_offset(
    PyObject * self,
    PyObject * args)
{
    char *name;

    if (!PyArg_ParseTuple(args, "s", &name)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    unsigned long offset = vmi_get_offset(vmi(self), name);

    return Py_BuildValue("I", offset);
}

static PyObject *
pyvmi_get_page_mode(
    PyObject * self,
    PyObject * args)
{
    if (!PyArg_ParseTuple(args, "")) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    page_mode_t mode = vmi_get_page_mode(vmi(self));

    PyObject *rtnval = NULL;

    if (VMI_PM_LEGACY == mode) {
        rtnval = Py_BuildValue("s", "legacy");
    }
    else if (VMI_PM_PAE == mode) {
        rtnval = Py_BuildValue("s", "pae");
    }
    else if (VMI_PM_IA32E == mode) {
        rtnval = Py_BuildValue("s", "ia32e");
    }
    else {
        rtnval = Py_BuildValue("s", "unknown");
    }
    return rtnval;
}

static PyObject *
pyvmi_get_ostype(
    PyObject * self,
    PyObject * args)
{
    if (!PyArg_ParseTuple(args, "")) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    os_t type = vmi_get_ostype(vmi(self));

    PyObject *rtnval = NULL;

    if (VMI_OS_WINDOWS == type) {
        rtnval = Py_BuildValue("s", "windows");
    }
    else if (VMI_OS_LINUX == type) {
        rtnval = Py_BuildValue("s", "linux");
    }
    else {
        rtnval = Py_BuildValue("s", "unknown");
    }
    return rtnval;
}

static PyObject *
pyvmi_print_hex(
    PyObject * self,
    PyObject * args)
{
    unsigned char *data;
    int length;

    if (!PyArg_ParseTuple(args, "s#", &data, &length)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    vmi_print_hex(data, (uint32_t) length);
    return Py_BuildValue("");   // return None
}

static PyObject *
pyvmi_print_hex_pa(
    PyObject * self,
    PyObject * args)
{
    addr_t paddr;
    uint32_t length;

    if (!PyArg_ParseTuple(args, "KI", &paddr, &length)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    vmi_print_hex_pa(vmi(self), paddr, length);
    return Py_BuildValue("");   // return None
}

static PyObject *
pyvmi_print_hex_va(
    PyObject * self,
    PyObject * args)
{
    addr_t vaddr;
    int pid;
    uint32_t length;

    if (!PyArg_ParseTuple(args, "KiI", &vaddr, &pid, &length)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    vmi_print_hex_va(vmi(self), vaddr, pid, length);
    return Py_BuildValue("");   // return None
}

static PyObject *
pyvmi_print_hex_ksym(
    PyObject * self,
    PyObject * args)
{
    char *sym;
    uint32_t length;

    if (!PyArg_ParseTuple(args, "sI", &sym, &length)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    vmi_print_hex_ksym(vmi(self), sym, length);
    return Py_BuildValue("");   // return None
}

static PyObject *
pyvmi_pause_vm(
    PyObject * self,
    PyObject * args)
{
    if (VMI_FAILURE == vmi_pause_vm(vmi(self))) {
        PyErr_SetString(PyExc_OSError, "Failed to pause VM");
        return NULL;
    }
    return Py_BuildValue("");   // return None
}

static PyObject *
pyvmi_resume_vm(
    PyObject * self,
    PyObject * args)
{
    if (VMI_FAILURE == vmi_resume_vm(vmi(self))) {
        PyErr_SetString(PyExc_OSError, "Failed to resume VM");
        return NULL;
    }
    return Py_BuildValue("");   // return None
}

static PyObject *
pyvmi_v2pcache_flush(
    PyObject * self,
    PyObject * args)
{
    addr_t dtb;
    if (!PyArg_ParseTuple(args, "K", &dtb)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    vmi_v2pcache_flush(vmi(self), dtb);
    return Py_BuildValue("");   // return None
}

static PyObject *
pyvmi_v2pcache_add(
    PyObject * self,
    PyObject * args)
{
    addr_t va;
    addr_t dtb;
    addr_t pa;

    if (!PyArg_ParseTuple(args, "KKK", &va, &dtb, &pa)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    vmi_v2pcache_add(vmi(self), va, dtb, pa);
    return Py_BuildValue("");   // return None
}

static PyObject *
pyvmi_symcache_flush(
    PyObject * self,
    PyObject * args)
{
    vmi_symcache_flush(vmi(self));
    return Py_BuildValue("");   // return None
}

static PyObject *
pyvmi_symcache_add(
    PyObject * self,
    PyObject * args)
{
    char *sym;
    addr_t va;
    addr_t base_addr;
    int pid;

    if (!PyArg_ParseTuple(args, "KisK", &base_addr, &pid, &sym, &va)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    vmi_symcache_add(vmi(self), base_addr, pid, sym, va);
    return Py_BuildValue("");   // return None
}

static PyObject *
pyvmi_pidcache_flush(
    PyObject * self,
    PyObject * args)
{
    vmi_pidcache_flush(vmi(self));
    return Py_BuildValue("");   // return None
}

static PyObject *
pyvmi_pidcache_add(
    PyObject * self,
    PyObject * args)
{
    int pid;
    addr_t dtb;

    if (!PyArg_ParseTuple(args, "iK", &pid, &dtb)) {
        PyErr_SetString(PyExc_ValueError,
                        "Invalid argument(s) to function");
        return NULL;
    }

    vmi_pidcache_add(vmi(self), pid, dtb);
    return Py_BuildValue("");   // return None
}

//-------------------------------------------------------------------
// Python interface

// pyvmi_instance method table
static PyMethodDef pyvmi_instance_methods[] = {
    {"init_complete", pyvmi_init_complete, METH_VARARGS,
     "Complete initialization when init was only partial"},
    {"translate_kv2p", pyvmi_translate_kv2p, METH_VARARGS,
     "Translate kernel virtual address to physical address"},
    {"translate_uv2p", pyvmi_translate_uv2p, METH_VARARGS,
     "Translate user virtual address to physical address"},
    {"translate_ksym2v", pyvmi_translate_ksym2v, METH_VARARGS,
     "Translate kernel symbol to virtual address"},
    {"pid_to_dtb", pyvmi_pid_to_dtb, METH_VARARGS,
     "Get directory table base value from process id"},
    {"read_pa", pyvmi_read_pa, METH_VARARGS,
     "Read physical memory"},
    {"zread_pa", pyvmi_zread_pa, METH_VARARGS,
     "Read physical memory, fill memory holes with zeroes"},
    {"read_va", pyvmi_read_va, METH_VARARGS,
     "Read virtual memory"},
    {"read_ksym", pyvmi_read_ksym, METH_VARARGS,
     "Read memory using kernel symbol"},
    {"read_8_pa", pyvmi_read_8_pa, METH_VARARGS,
     "Read 1 byte using a physical address"},
    {"read_16_pa", pyvmi_read_16_pa, METH_VARARGS,
     "Read 2 bytes using a physical address"},
    {"read_32_pa", pyvmi_read_32_pa, METH_VARARGS,
     "Read 4 bytes using a physical address"},
    {"read_64_pa", pyvmi_read_64_pa, METH_VARARGS,
     "Read 8 bytes using a physical address"},
    {"read_addr_pa", pyvmi_read_addr_pa, METH_VARARGS,
     "Read address using a physical address"},
    {"read_str_pa", pyvmi_read_str_pa, METH_VARARGS,
     "Read string using a physical address"},
    {"read_8_va", pyvmi_read_8_va, METH_VARARGS,
     "Read 1 byte using a virtual address"},
    {"read_16_va", pyvmi_read_16_va, METH_VARARGS,
     "Read 2 bytes using a virtual address"},
    {"read_32_va", pyvmi_read_32_va, METH_VARARGS,
     "Read 4 bytes using a virtual address"},
    {"read_64_va", pyvmi_read_64_va, METH_VARARGS,
     "Read 8 bytes using a virtual address"},
    {"read_addr_va", pyvmi_read_addr_va, METH_VARARGS,
     "Read address using a virtual address"},
    {"read_str_va", pyvmi_read_str_va, METH_VARARGS,
     "Read string using a virtual address"},
    {"read_8_ksym", pyvmi_read_8_ksym, METH_VARARGS,
     "Read 1 byte using a kernel symbol"},
    {"read_16_ksym", pyvmi_read_16_ksym, METH_VARARGS,
     "Read 2 bytes using a kernel symbol"},
    {"read_32_ksym", pyvmi_read_32_ksym, METH_VARARGS,
     "Read 4 bytes using a kernel symbol"},
    {"read_64_ksym", pyvmi_read_64_ksym, METH_VARARGS,
     "Read 8 bytes using a kernel symbol"},
    {"read_addr_ksym", pyvmi_read_addr_ksym, METH_VARARGS,
     "Read address using a kernel symbol"},
    {"read_str_ksym", pyvmi_read_str_ksym, METH_VARARGS,
     "Read string using a kernel symbol"},
    {"write_pa", pyvmi_write_pa, METH_VARARGS,
     "Write physical memory"},
    {"write_va", pyvmi_write_va, METH_VARARGS,
     "Write virtual memory"},
    {"write_ksym", pyvmi_write_ksym, METH_VARARGS,
     "Write memory using kernel symbol"},
    {"write_8_pa", pyvmi_write_8_pa, METH_VARARGS,
     "Write 1 byte using a physical address"},
    {"write_16_pa", pyvmi_write_16_pa, METH_VARARGS,
     "Write 2 bytes using a physical address"},
    {"write_32_pa", pyvmi_write_32_pa, METH_VARARGS,
     "Write 4 bytes using a physical address"},
    {"write_64_pa", pyvmi_write_64_pa, METH_VARARGS,
     "Write 8 bytes using a physical address"},
    {"write_8_va", pyvmi_write_8_va, METH_VARARGS,
     "Write 1 byte using a virtual address"},
    {"write_16_va", pyvmi_write_16_va, METH_VARARGS,
     "Write 2 bytes using a virtual address"},
    {"write_32_va", pyvmi_write_32_va, METH_VARARGS,
     "Write 4 bytes using a virtual address"},
    {"write_64_va", pyvmi_write_64_va, METH_VARARGS,
     "Write 8 bytes using a virtual address"},
    {"write_8_ksym", pyvmi_write_8_ksym, METH_VARARGS,
     "Write 1 byte using a kernel symbol"},
    {"write_16_ksym", pyvmi_write_16_ksym, METH_VARARGS,
     "Write 2 bytes using a kernel symbol"},
    {"write_32_ksym", pyvmi_write_32_ksym, METH_VARARGS,
     "Write 4 bytes using a kernel symbol"},
    {"write_64_ksym", pyvmi_write_64_ksym, METH_VARARGS,
     "Write 8 bytes using a kernel symbol"},
    {"get_vcpureg", pyvmi_get_vcpureg, METH_VARARGS,
     "Get the current value of a vcpu register"},
    {"get_name", pyvmi_get_name, METH_VARARGS,
     "Get the name of the VM, or the filename"},
    {"get_vmid", pyvmi_get_vmid, METH_VARARGS,
     "Get the VM identifier"},
    {"get_access_mode", pyvmi_get_access_mode, METH_VARARGS,
     "Get the resource being used to access memory (e.g., xen, kvm, or file)"},
    {"get_winver_str", pyvmi_get_winver_str, METH_VARARGS,
     "Get a string representation of the windows version running in the VM"},
    {"get_memsize", pyvmi_get_memsize, METH_VARARGS,
     "Get the memory size (in bytes) of this memory"},
    {"get_offset", pyvmi_get_offset, METH_VARARGS,
     "Get an offset value by name from the config file"},
    {"get_page_mode", pyvmi_get_page_mode, METH_VARARGS,
     "Get the page mode used in the target system"},
    {"get_ostype", pyvmi_get_ostype, METH_VARARGS,
     "Get the OS type of the target system"},
    {"print_hex", pyvmi_print_hex, METH_VARARGS,
     "Prints raw binary data to the screen in a useful format"},
    {"print_hex_pa", pyvmi_print_hex_pa, METH_VARARGS,
     "Prints raw binary data to the screen in a useful format"},
    {"print_hex_pa", pyvmi_print_hex_va, METH_VARARGS,
     "Prints raw binary data to the screen in a useful format"},
    {"print_hex_pa", pyvmi_print_hex_ksym, METH_VARARGS,
     "Prints raw binary data to the screen in a useful format"},
    {"pause_vm", pyvmi_pause_vm, METH_VARARGS,
     "Pauses the VM to allow for consistent analysis"},
    {"resume_vm", pyvmi_resume_vm, METH_VARARGS,
     "Resumes the VM, called after pause_vm"},

    {"v2pcache_flush", pyvmi_v2pcache_flush, METH_VARARGS,
     "Remove all entries from the virtual to physical cache"},
    {"v2pcache_add", pyvmi_v2pcache_add, METH_VARARGS,
     "Add an entry to the virtual to physical cache"},
    {"symcache_flush", pyvmi_symcache_flush, METH_VARARGS,
     "Remove all entries from the symbol to virtual cache"},
    {"symcache_add", pyvmi_symcache_add, METH_VARARGS,
     "Add an entry to the symbol to virtual cache"},
    {"pidcache_flush", pyvmi_pidcache_flush, METH_VARARGS,
     "Remove all entries from the pid to dtb cache"},
    {"pidcache_add", pyvmi_pidcache_add, METH_VARARGS,
     "Add an entry to the pid to dtb cache"},

    {NULL, NULL, 0, NULL}   /* Sentinel */
};

// python callbacks
static PyObject *
pyvmi_instance_getattr(
    PyObject * self,
    char *attrname)
{
    return Py_FindMethod(pyvmi_instance_methods, self, attrname);
}

static PyObject *
pyvmi_instance_repr(
    PyObject * self)
{
    char buf[100];

    snprintf(buf, 100, "<pyvmi_instance for %s>", desc(self));
    return PyString_FromString(buf);
}

// Type object itself
static PyTypeObject pyvmi_instance_Type = {
    PyObject_HEAD_INIT(&PyType_Type)
        0,
    "pyvmi_instance",   /* char *tp_name; */
    sizeof(pyvmi_instance), /* int tp_basicsize; */
    0,  /* int tp_itemsize;        not used much */
    (destructor) pyvmi_instance_dealloc,    /* destructor tp_dealloc; */
    0,  /* printfunc  tp_print;   */
    (getattrfunc) pyvmi_instance_getattr,   /* getattrfunc  tp_getattr;  __getattr__ */
    0,  /* setattrfunc  tp_setattr;  __setattr__ */
    0,  /* cmpfunc  tp_compare;  __cmp__ */
    (reprfunc) pyvmi_instance_repr, /* reprfunc  tp_repr;    __repr__ */
    0,  /* PyNumberMethods *tp_as_number; */
    0,  /* PySequenceMethods *tp_as_sequence; */
    0,  /* PyMappingMethods *tp_as_mapping; */
    0,  /* hashfunc tp_hash;     __hash__ */
    0,  /* ternaryfunc tp_call;  __call__ */
    0,  /* reprfunc tp_str;      __str__ */
};

// module method table
static PyMethodDef PyVmiMethods[] = {
    {"init", pyvmi_init, METH_VARARGS,
     "Create a new PyVmi instance using the name"},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initpyvmi(
    void)
{
    (void) Py_InitModule("pyvmi", PyVmiMethods);
}

int
main(
    int argc,
    char *argv[])
{
    /* Pass argv[0] to the Python interpreter */
    Py_SetProgramName(argv[0]);

    /* Initialize the Python interpreter.  Required. */
    Py_Initialize();

    /* Add a static module */
    initpyvmi();

    return 0;
}
