/*
 * The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * This code is based on the original PyXa module by Brendan Dolan-Gavitt.
 *
 * Copyright (C) 2010 Sandia National Laboratories
 * Author: Bryan D. Payne (bpayne@sandia.gov)
 */

#include <Python.h>
#include <string.h>
#include <stdio.h>
#include <libvmi/libvmi.h>

#define vmi(v)  (((pyvmi_instance *)(v))->vmi)
#define mem(v)  (((pyvmi_instance *)(v))->memory)
#define name(v)  (((pyvmi_instance *)(v))->name)

// PyVmi instance type fwdref
staticforward PyTypeObject pyvmi_instance_Type;

typedef struct {
    PyObject_HEAD
    vmi_instance_t vmi;    // LibVMI instance
    void *memory;
    char *name;
} pyvmi_instance;

// Constructor & Destructor
static PyObject *
pyvmi_init(PyObject *self, PyObject *args) {
    char *vmname;
    pyvmi_instance *object = NULL;
    
    object = PyObject_NEW(pyvmi_instance, &pyvmi_instance_Type);    

    if (!PyArg_ParseTuple(args, "s", &vmname)){
        return NULL;
    }
    
    if (VMI_FAILURE == vmi_init(&(vmi(object)), VMI_MODE_AUTO, vmname)){
        PyErr_SetString(PyExc_ValueError, "Init failed");
        return NULL;
    }

    mem(object) = NULL;
    name(object) = strdup(vmname);

    return (PyObject *) object;
}

static void
pyvmi_instance_dealloc(PyObject *self) {
    vmi_destroy(vmi(self));
    if (mem(self)){
        free(mem(self));
    }
    if (name(self)){
        free(name(self));
    }
    PyObject_DEL(self);
}

//-------------------------------------------------------------------
// Translate functions
static PyObject *
pyvmi_translate_kv2p(PyObject *self, PyObject *args) {
    uint32_t vaddr;

    if (!PyArg_ParseTuple(args, "I", &vaddr)){
        return NULL;
    }

    uint32_t paddr = vmi_translate_kv2p(vmi(self), vaddr);
    if(!paddr){
        PyErr_SetString(PyExc_ValueError, "Address translation failed");
        return NULL;
    }

    return Py_BuildValue("I", paddr);
}

static PyObject *
pyvmi_translate_uv2p(PyObject *self, PyObject *args) {
    uint32_t vaddr;
    int pid;

    if (!PyArg_ParseTuple(args, "Ii", &vaddr, &pid)){
        return NULL;
    }

    uint32_t paddr = vmi_translate_uv2p(vmi(self), vaddr, pid);
    if(!paddr){
        PyErr_SetString(PyExc_ValueError, "Address translation failed");
        return NULL;
    }

    return Py_BuildValue("I", paddr);
}

static PyObject *
pyvmi_translate_ksym2v(PyObject *self, PyObject *args) {
    char *sym;

    if (!PyArg_ParseTuple(args, "s", &sym)){
        return NULL;
    }

    uint32_t vaddr = vmi_translate_ksym2v(vmi(self), sym);
    if(!vaddr){
        PyErr_SetString(PyExc_ValueError, "Symbol lookup failed");
        return NULL;
    }

    return Py_BuildValue("I", vaddr);
}

//-------------------------------------------------------------------
// Primary read functions
static PyObject *
pyvmi_read_pa(PyObject *self, PyObject *args) {
    uint32_t paddr;
    uint32_t length;

    if (!PyArg_ParseTuple(args, "II", &paddr, &length)){
        return NULL;
    }

    if (mem(self)){
        free(mem(self));
    }
    mem(self) = malloc(length);

    size_t nbytes = vmi_read_pa(vmi(self), paddr, mem(self), length);
    if(nbytes != length){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("s#", mem(self), length);
}

static PyObject *
pyvmi_read_va(PyObject *self, PyObject *args) {
    uint32_t vaddr;
    int pid;
    uint32_t length;

    if (!PyArg_ParseTuple(args, "IiI", &vaddr, &pid, &length)){
        return NULL;
    }

    if (mem(self)){
        free(mem(self));
    }
    mem(self) = malloc(length);

    size_t nbytes = vmi_read_va(vmi(self), vaddr, pid, mem(self), length);
    if(nbytes != length){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("s#", mem(self), length);
}

static PyObject *
pyvmi_read_ksym(PyObject *self, PyObject *args) {
    char *sym;
    uint32_t length;

    if (!PyArg_ParseTuple(args, "sI", &sym, &length)){
        return NULL;
    }

    if (mem(self)){
        free(mem(self));
    }
    mem(self) = malloc(length);

    size_t nbytes = vmi_read_ksym(vmi(self), sym, mem(self), length);
    if(nbytes != length){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("s#", mem(self), length);
}

//-------------------------------------------------------------------
// Utility read functions

static PyObject *
pyvmi_read_8_pa (PyObject *self, PyObject *args)
{
    uint32_t paddr;
    uint8_t value;

    if (!PyArg_ParseTuple(args, "I", &paddr)){
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_8_pa(vmi(self), paddr, &value)){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("c", &value);
}

static PyObject *
pyvmi_read_16_pa (PyObject *self, PyObject *args)
{
    uint32_t paddr;
    uint16_t value;

    if (!PyArg_ParseTuple(args, "I", &paddr)){
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_16_pa(vmi(self), paddr, &value)){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("H", &value);
}

static PyObject *
pyvmi_read_32_pa (PyObject *self, PyObject *args)
{
    uint32_t paddr;
    uint32_t value;

    if (!PyArg_ParseTuple(args, "I", &paddr)){
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_32_pa(vmi(self), paddr, &value)){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("I", &value);
}

static PyObject *
pyvmi_read_64_pa (PyObject *self, PyObject *args)
{
    uint32_t paddr;
    uint64_t value;

    if (!PyArg_ParseTuple(args, "I", &paddr)){
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_64_pa(vmi(self), paddr, &value)){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("K", &value);
}

static PyObject *
pyvmi_read_8_va (PyObject *self, PyObject *args)
{
    uint32_t vaddr;
    int pid;
    uint8_t value;

    if (!PyArg_ParseTuple(args, "Ii", &vaddr, &pid)){
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_8_va(vmi(self), vaddr, pid, &value)){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("c", &value);
}

static PyObject *
pyvmi_read_16_va (PyObject *self, PyObject *args)
{
    uint32_t vaddr;
    int pid;
    uint16_t value;

    if (!PyArg_ParseTuple(args, "Ii", &vaddr, &pid)){
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_16_va(vmi(self), vaddr, pid, &value)){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("H", &value);
}

static PyObject *
pyvmi_read_32_va (PyObject *self, PyObject *args)
{
    uint32_t vaddr;
    int pid;
    uint32_t value;

    if (!PyArg_ParseTuple(args, "Ii", &vaddr, &pid)){
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_32_va(vmi(self), vaddr, pid, &value)){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("I", &value);
}

static PyObject *
pyvmi_read_64_va (PyObject *self, PyObject *args)
{
    uint32_t vaddr;
    int pid;
    uint64_t value;

    if (!PyArg_ParseTuple(args, "Ii", &vaddr, &pid)){
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_64_va(vmi(self), vaddr, pid, &value)){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("K", &value);
}

static PyObject *
pyvmi_read_8_ksym (PyObject *self, PyObject *args)
{
    char *sym;
    uint8_t value;

    if (!PyArg_ParseTuple(args, "s", &sym)){
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_8_ksym(vmi(self), sym, &value)){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("c", &value);
}

static PyObject *
pyvmi_read_16_ksym (PyObject *self, PyObject *args)
{
    char *sym;
    uint16_t value;

    if (!PyArg_ParseTuple(args, "s", &sym)){
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_16_ksym(vmi(self), sym, &value)){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("H", &value);
}

static PyObject *
pyvmi_read_32_ksym (PyObject *self, PyObject *args)
{
    char *sym;
    uint32_t value;

    if (!PyArg_ParseTuple(args, "s", &sym)){
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_32_ksym(vmi(self), sym, &value)){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("I", &value);
}

static PyObject *
pyvmi_read_64_ksym (PyObject *self, PyObject *args)
{
    char *sym;
    uint64_t value;

    if (!PyArg_ParseTuple(args, "s", &sym)){
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_64_ksym(vmi(self), sym, &value)){
        PyErr_SetString(PyExc_ValueError, "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("K", &value);
}

//-------------------------------------------------------------------
// Accessor and other utility functions
static PyObject *
pyvmi_get_cr3(PyObject *self, PyObject *args) {
    reg_t cr3 = 0;
    
    if (!PyArg_ParseTuple(args, "")){
        return NULL;
    }

    if (VMI_FAILURE == vmi_get_vcpureg(vmi(self), &cr3, CR3, 0)){
        PyErr_SetString(PyExc_ValueError, "Unable to get CR3 value");
        return NULL;
    }
    
    return Py_BuildValue("I", cr3);
}

static PyObject *
pyvmi_get_memsize(PyObject *self, PyObject *args) {
    unsigned long size = 0;

    if (!PyArg_ParseTuple(args, "")){
        return NULL;
    }

    size = vmi_get_memsize(vmi(self));
    return Py_BuildValue("I", size);
}

static PyObject *
pyvmi_get_offset(PyObject *self, PyObject *args) {
    char *name;

    if (!PyArg_ParseTuple(args, "s", &name)){
        return NULL;
    }

    unsigned long offset = vmi_get_offset(vmi(self), name);
    return Py_BuildValue("I", offset);
}

static PyObject *
pyvmi_get_ostype(PyObject *self, PyObject *args) {
    if (!PyArg_ParseTuple(args, "")){
        return NULL;
    }

    os_t type = vmi_get_ostype(vmi(self));

    PyObject *rtnval = NULL;
    if (VMI_OS_WINDOWS == type){
        rtnval = Py_BuildValue("s", "Windows");
    }
    else if (VMI_OS_LINUX == type){
        rtnval = Py_BuildValue("s", "Linux");
    }
    else{
        rtnval = Py_BuildValue("s", "Unknown");
    }
    return rtnval;
}

static PyObject *
pyvmi_print_hex(PyObject *self, PyObject *args) {
    unsigned char *data;
    int length;

    if (!PyArg_ParseTuple(args, "s#", &data, &length)){
        return NULL;
    }

    vmi_print_hex(data, (unsigned long) length);
    return Py_BuildValue(""); // return None
}

//-------------------------------------------------------------------
// Python interface

// pyvmi_instance method table
static PyMethodDef pyvmi_instance_methods[] = {
    {"translate_kv2p", pyvmi_translate_kv2p, METH_VARARGS,
     "Translate kernel virtual address to physical address"},
    {"translate_uv2p", pyvmi_translate_uv2p, METH_VARARGS,
     "Translate user virtual address to physical address"},
    {"translate_ksym2v", pyvmi_translate_ksym2v, METH_VARARGS,
     "Translate kernel symbol to virtual address"},
    {"read_pa", pyvmi_read_pa, METH_VARARGS,
     "Read physical memory"},
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
    {"read_8_va", pyvmi_read_8_va, METH_VARARGS,
     "Read 1 byte using a virtual address"},
    {"read_16_va", pyvmi_read_16_va, METH_VARARGS,
     "Read 2 bytes using a virtual address"},
    {"read_32_va", pyvmi_read_32_va, METH_VARARGS,
     "Read 4 bytes using a virtual address"},
    {"read_64_va", pyvmi_read_64_va, METH_VARARGS,
     "Read 8 bytes using a virtual address"},
    {"read_8_ksym", pyvmi_read_8_ksym, METH_VARARGS,
     "Read 1 byte using a kernel symbol"},
    {"read_16_ksym", pyvmi_read_16_ksym, METH_VARARGS,
     "Read 2 bytes using a kernel symbol"},
    {"read_32_ksym", pyvmi_read_32_ksym, METH_VARARGS,
     "Read 4 bytes using a kernel symbol"},
    {"read_64_ksym", pyvmi_read_64_ksym, METH_VARARGS,
     "Read 8 bytes using a kernel symbol"},
    {"get_cr3", pyvmi_get_cr3, METH_VARARGS,
     "Get the current value of the CR3 register"},
    {"get_memsize", pyvmi_get_memsize, METH_VARARGS,
     "Get the memory size (in bytes) of this memory"},
    {"get_offset", pyvmi_get_offset, METH_VARARGS,
     "Get an offset value by name from the config file"},
    {"get_ostype", pyvmi_get_ostype, METH_VARARGS,
     "Get the OS type of the target system"},
    {"print_hex", pyvmi_print_hex, METH_VARARGS,
     "Prints raw binary data to the screen in a useful format"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

// python callbacks
static PyObject *
pyvmi_instance_getattr(PyObject *self, char *attrname) {
    return Py_FindMethod(pyvmi_instance_methods, self, attrname);
}

static PyObject *
pyvmi_instance_repr(PyObject *self) {
    char buf[100];
    snprintf(buf, 100, "<pyvmi_instance for %s>", name(self));
    return PyString_FromString(buf);
}

// Type object itself
static PyTypeObject pyvmi_instance_Type = {
    PyObject_HEAD_INIT(&PyType_Type)
    0,
    "pyvmi_instance",          /* char *tp_name; */
    sizeof(pyvmi_instance),    /* int tp_basicsize; */
    0,                        /* int tp_itemsize;        not used much */
    (destructor) pyvmi_instance_dealloc,    /* destructor tp_dealloc; */
    0,                        /* printfunc  tp_print;   */
    (getattrfunc) pyvmi_instance_getattr,    /* getattrfunc  tp_getattr;  __getattr__ */
    0,    /* setattrfunc  tp_setattr;  __setattr__ */
    0,                        /* cmpfunc  tp_compare;  __cmp__ */
    (reprfunc) pyvmi_instance_repr,       /* reprfunc  tp_repr;    __repr__ */
    0,                        /* PyNumberMethods *tp_as_number; */
    0,                        /* PySequenceMethods *tp_as_sequence; */
    0,                        /* PyMappingMethods *tp_as_mapping; */
    0,                        /* hashfunc tp_hash;     __hash__ */
    0,                        /* ternaryfunc tp_call;  __call__ */
    0,                        /* reprfunc tp_str;      __str__ */
};

// module method table
static PyMethodDef PyVmiMethods[] = {
    {"init", pyvmi_init, METH_VARARGS,
     "Create a new PyVmi instance using the name"},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initpyvmi(void) {
    (void) Py_InitModule("pyvmi", PyVmiMethods);
}

int main(int argc, char *argv[]) {
    /* Pass argv[0] to the Python interpreter */
    Py_SetProgramName(argv[0]);

    /* Initialize the Python interpreter.  Required. */
    Py_Initialize();

    /* Add a static module */
    initpyvmi();

    return 0;
}
