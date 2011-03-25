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

//void print_debug(xa_instance_t xai) {
//    printf("DEBUG: KPGD [%#x] CR3: [%#x] DomId: [%d] Version: [%d]\n"
//           "       Memory size: [%d] OS Type: [%s]\n",
//
//           xai.kpgd, xai.cr3, xai.m.xen.domain_id,
//           xai.m.xen.xen_version, xai.m.xen.size,
//           xai.os_type == XA_OS_LINUX ? "Linux" : "Windows");
//}

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
pyvmi_init_name(PyObject *self, PyObject *args) {
    char *vmname;
    pyvmi_instance *object = NULL;
    
    object = PyObject_NEW(pyvmi_instance, &pyvmi_instance_Type);    

    if (!PyArg_ParseTuple(args, "s", &vmname)){
        return NULL;
    }
    
    if (VMI_FAILURE == vmi_init_name(&(vmi(object)), VMI_MODE_AUTO, vmname)){
        PyErr_SetString(PyExc_ValueError, "Init failed");
        return NULL;
    }

    mem(object) = NULL;
    name(object) = strdup(vmname);

    //print_debug(vmi(object));
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

// Methods
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

// pyvmi_instance method table
static PyMethodDef pyvmi_instance_methods[] = {
    {"read_pa", pyvmi_read_pa, METH_VARARGS,
     "Read physical memory"},
    {"read_va", pyvmi_read_va, METH_VARARGS,
     "Read virtual memory"},
    {"read_ksym", pyvmi_read_ksym, METH_VARARGS,
     "Read memory using kernel symbol"},
    {"get_cr3", pyvmi_get_cr3, METH_VARARGS,
     "Get the current value of the CR3 register"},
    {"get_memsize", pyvmi_get_memsize, METH_VARARGS,
     "Get the memory size (in bytes) of this memory"},
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
    {"pyvmi_init", pyvmi_init_name, METH_VARARGS,
     "Create a new PyVmi instance"},
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
